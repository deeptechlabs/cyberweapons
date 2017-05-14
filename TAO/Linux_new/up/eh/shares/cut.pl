#
# cut.pl - routines to cut size of webmail or webdisk fpr quota
#
use strict;
use Fcntl qw(:DEFAULT :flock);

use vars qw($_OFFSET $_FROM $_TO $_DATE $_SUBJECT $_CONTENT_TYPE $_STATUS $_SIZE $_REFERENCES $_CHARSET);	# defined in maildb.pl
use vars qw(%is_defaultfolder);
use vars qw(%config);

########## CUTFOLDERMAILS/CUTDIRFILES ############################
sub cutfoldermails {
   my ($sizetocut, $user, @folders)=@_;
   my ($total_foldersize, $user_foldersize)=(0,0);
   my (@userfolders, %folderfile, %folderdb);
   my $inbox_foldersize=0;

   foreach my $f (@folders) {
      ($folderfile{$f},$folderdb{$f})=get_folderpath_folderdb($user, $f);
      my $foldersize=(-s "$folderfile{$f}");
      if (!$is_defaultfolder{$f}) {
         push (@userfolders, $f);
         $user_foldersize+=$foldersize;
      }
      if ($f eq 'INBOX') {
         if ($config{'use_homedirspools'}) {
            $total_foldersize+=$foldersize;
            $inbox_foldersize=$foldersize;
         }
      } else {
         $total_foldersize+=$foldersize;
      }
   }

   # empty folders
   foreach my $f ('mail-trash', 'saved-drafts') {
      next if ( (-s "$folderfile{$f}")==0 );

      my $sizereduced = (-s "$folderfile{$f}");

      if (!ow::filelock::lock($folderfile{$f}, LOCK_EX|LOCK_NB)) {
         writelog("emptyfolder error - Couldn't get write lock on $folderfile{$f}");
         writehistory("emptyfolder error - Couldn't get write lock on $folderfile{$f}");
         next;
      }
      my $ret=emptyfolder($folderfile{$f}, $folderdb{$f});
      ow::filelock::lock($folderfile{$f}, LOCK_UN);
      if ($ret<0) {
         writelog("emptyfolder error - folder $f ret=$ret");
         writehistory("emptyfolder error - folder $f ret=$ret");
         next;
      }

      $sizereduced -= (-s "$folderfile{$f}");

      $total_foldersize-=$sizereduced;
      $sizetocut-=$sizereduced;
      return ($_[0]-$sizetocut) if ($sizetocut<=0);	# return cutsize
   }

   # cut folders
   my @folders_tocut=('sent-mail', 'saved-messages');
   # put @userfolders to cutlist if it occupies more than 33%
   if ($user_foldersize > $total_foldersize*0.33) {
      push (@folders_tocut, sort(@userfolders));
   } else {
      $total_foldersize -= $user_foldersize;
   }
   # put INBOX to cutlist if it occupies more than 33%
   if ($config{'use_homedirspools'}) {
      if ($inbox_foldersize > $total_foldersize*0.33) {
         push (@folders_tocut, 'INBOX');
      } else {
         $total_foldersize -= $inbox_foldersize;
      }
   }

   for (my $i=0; $i<3; $i++) {
      return ($_[0]-$sizetocut) if ($total_foldersize==0);	# return cutsize

      my $cutpercent=$sizetocut/$total_foldersize;
      $cutpercent=0.1 if ($cutpercent<0.1);

      foreach my $f (@folders_tocut) {
         next if ( (-s "$folderfile{$f}")==0 );

         my $sizereduced = (-s "$folderfile{$f}");
         my $ret;
         if ($f eq 'sent-mail') {
            $ret=cutfolder($folderfile{$f}, $folderdb{$f}, $cutpercent+0.1);
         } else {
            $ret=cutfolder($folderfile{$f}, $folderdb{$f}, $cutpercent);
         }
         if ($ret<0) {
            writelog("cutfoldermails error - folder $f ret=$ret");
            writehistory("cutfoldermails error - folder $f ret=$ret");
            next;
         }
         $sizereduced -= (-s "$folderfile{$f}");
         writelog("cutfoldermails - $f, $ret msg removed, reduced size $sizereduced");
         writehistory("cutfoldermails - $f, $ret msg removed, reduced size $sizereduced");

         $total_foldersize-=$sizereduced;
         $sizetocut-=$sizereduced;
         return ($_[0]-$sizetocut) if ($sizetocut<=0);	# return cutsize
      }
   }

   writelog("cutfoldermails error - still $sizetocut bytes to cut");
   writehistory("cutfoldermails error - still $sizetocut bytes to cut");
   return ($_[0]-$sizetocut);	# return cutsize
}

sub cutfolder {				# reduce folder size by $cutpercent
   my ($folderfile, $folderdb, $cutpercent) = @_;
   my (@delids, $cutsize, %FDB);

   ow::filelock::lock($folderfile, LOCK_SH|LOCK_NB) or return -1;

   return -2 if (update_folderindex($folderfile, $folderdb)<0);

   my ($totalsize, $new, $r_messageids)=get_info_messageids_sorted_by_date($folderdb, 0);

   ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or return -3;
   foreach my $id  (reverse @{$r_messageids}) {
      push(@delids, $id);
      $cutsize += (string2msgattr($FDB{$id}))[$_SIZE];
      last if ($cutsize > $totalsize*$cutpercent);
   }
   ow::dbm::close(\%FDB, $folderdb);
   my $counted=operate_message_with_ids("delete", \@delids, $folderfile, $folderdb);
   $counted=folder_zapmessages($folderfile, $folderdb);

   ow::filelock::lock($folderfile, LOCK_UN);

   return($counted);
}

sub cutdirfiles {
   my ($sizetocut, $dir)=@_;
   return 0 if (is_under_dotdir_or_folderdir($dir));
   return -1 if (!opendir(D, $dir));
   my @files=readdir(D);
   closedir(D);
   
   my (%ftype, %fdate, %fsize);

   foreach my $fname (@files) {
      next if ($fname eq "."|| $fname eq "..");

      my ($st_mode, $st_mtime, $st_blocks)= (lstat("$dir/$fname"))[2,9,12];
      if ( ($st_mode&0170000)==0040000 ) {	# directory
         $ftype{$fname}='d';
         $fdate{$fname}=$st_mtime;
         $fsize{$fname}=$st_blocks*512;
      } elsif ( ($st_mode&0170000)==0100000 ||	# regular file
                ($st_mode&0170000)==0120000 ) {	# symlink
         $ftype{$fname}='f';
         $fdate{$fname}=$st_mtime;
         $fsize{$fname}=$st_blocks*512;
      } else {	# unix specific filetype: fifo, socket, block dev, char dev..
         next;
      }
   }

   my $now=time();
   my @sortedlist= sort { $fdate{$a}<=>$fdate{$b} } keys(%ftype);
   foreach my $fname (@sortedlist) {
      if ($ftype{$fname} eq 'f') {
         if (unlink("$dir/$fname")) {
            $sizetocut-=$fsize{$fname};
            writelog("cutdirfiles - file $dir/$fname has been removed");
            writehistory("cutdirfiles - file $dir/$fname has been removed");
            return ($_[0]-$sizetocut) if ($sizetocut<=0);	# return cutsize
         }
      } else {	# dir
         my $sizecut=cutdirfiles($sizetocut, "$dir/$fname");
         if ($sizecut>0) {
            $sizetocut-=$sizecut;
            if (rmdir("$dir/$fname")) {
               writelog("cutdir - dir $dir/$fname has been removed");
               writehistory("cutdir - dir $dir/$fname has been removed");
            } else {
               utime($now, $fdate{$fname}, "$dir/$fname");	# set modify time back
            }
            return ($_[0]-$sizetocut) if ($sizetocut<=0);	# return cutsize
         }
      }
   }
   return ($_[0]-$sizetocut);
}
########## END CUTFOLDERMAILS/CUTDIRFILES ########################

1;
