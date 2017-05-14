#
# maildb.pl - mail indexing routines
#
# 2001/12/21 tung.AT.turtle.ee.ncku.edu.tw
#
# it speeds up the message access on folder file by caching important
# information with perl dbm.
#

#
# IMPORTANT!!!
#
# Functions in this file don't do locks for folderfile/folderhandle.
# They rely the caller to do that lock
#
# Functions with folderfile/folderhandle in argument must be inside
# a folderfile lock session
#
# Functions may change the current folderfile read position!!

# 2004/03/22 scott.AT.littlefish.ca
# - optimized delete old message replacing 'foreach' with 'each' index scan.
# - rewrote update_folderindex.  fixed indexing bug.
# - Added md5 checksums to the index to positively validate message headers.
# - minor tweaks here and there :)

use strict;
use Fcntl qw(:DEFAULT :flock);
use FileHandle;

# extern vars, defined in caller openwebmail-xxx.pl
use vars qw(%config %prefs);

# define the version of the mail index database
use vars qw($DBVERSION);
$DBVERSION=20040425;

# globals, message attribute number constant
use vars qw($_OFFSET $_FROM $_TO $_DATE $_SUBJECT $_CONTENT_TYPE $_STATUS $_SIZE $_REFERENCES $_CHARSET $_HEADERSIZE $_HEADERCHKSUM);
($_OFFSET, $_FROM, $_TO, $_DATE, $_SUBJECT, $_CONTENT_TYPE, $_STATUS, $_SIZE, $_REFERENCES, $_CHARSET, $_HEADERSIZE, $_HEADERCHKSUM)
=(0,1,2,3,4,5,6,7,8,9,10,11);

use vars qw(%is_internal_dbkey);
%is_internal_dbkey= (
   DBVERSION => 1,
   METAINFO => 1,
   NEWMESSAGES => 1,
   INTERNALMESSAGES => 1,
   ALLMESSAGES => 1,
   ZAPSIZE => 1,
   "" => 1
);

use vars qw($BUFF_blocksize);
$BUFF_blocksize=32768;

########## UPDATE_FOLDERDB #######################################
# this routine indexes the mesgs in folder and mark duplicated msgs with Z (to be zapped)
sub update_folderindex {
   my ($folderfile, $folderdb) = @_;
   my (%FDB, %OLDFDB);
   my @oldmessageids=();
   my $dberr=0;
   my $folderhandle=FileHandle->new();
   my $foldermeta=ow::tool::metainfo($folderfile);

   $folderdb=ow::tool::untaint($folderdb);
   if (ow::dbm::exist($folderdb)) {
      ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or return -1;
      my ($dbversion, $metainfo, $allmessages, $internalmessages, $newmessages, $zapsize)=
         @FDB{'DBVERSION', 'METAINFO', 'ALLMESSAGES', 'INTERNALMESSAGES', 'NEWMESSAGES', 'ZAPSIZE'};
      ow::dbm::close(\%FDB, $folderdb);

      if ( $dbversion eq $DBVERSION && 
           $metainfo eq $foldermeta && 
           $zapsize>=0 && 
           $allmessages>=0 && $internalmessages>=0 && $newmessages>=0 ) {
         return 0;
      }

      if ($dbversion eq $DBVERSION) {
         # we will try to reference records in old folderdb if possible
         ow::dbm::rename($folderdb, "$folderdb.old");
      } else {
         ow::dbm::unlink($folderdb);
      }
   }

   my ($messagenumber, $zapsize, $newmessages, $internalmessages, $totalsize) = (-1, 0, 0, 0, 0);

   ow::dbm::open(\%FDB, $folderdb, LOCK_EX) or return -1;

   %FDB=();	# ensure the folderdb is empty
   open ($folderhandle, $folderfile);
   my $foldersize=(stat($folderhandle))[7];

   # copy records from oldhdb as many as possible
   if ( ow::dbm::exist("$folderdb.old") ) {
      ow::dbm::open(\%OLDFDB, "$folderdb.old", LOCK_SH) or return -1;
      @oldmessageids=get_messageids_sorted_by_offset_db(\%OLDFDB);

      my $lastzapsize=0;
      my $lastinternal=0;
      my $lastnewmsg=0;
      my $lastsize=0;
      my $lastid='';

      foreach my $id (@oldmessageids) {
         my ($size, $offset, $status, $subject) = (_get_validated_msgattr($folderhandle, \%OLDFDB, $id))[$_SIZE, $_OFFSET, $_STATUS, $_SUBJECT];

         last if ( !$size or $offset<0 or $offset != $totalsize+$lastsize);

         if ($messagenumber>=0) {
            $FDB{$lastid}=$OLDFDB{$lastid};
            $zapsize+=$lastzapsize;
            $internalmessages++ if ($lastinternal);
            $newmessages++ if ($lastnewmsg);
            $totalsize += $lastsize;
         }
         $messagenumber++;
         $lastzapsize =($status =~ m/Z/i)? $size:0;
         $lastinternal=(is_internal_subject($subject))? 1:0;
         $lastnewmsg  =($status !~ m/R/i)? 1:0;
         $lastsize = $size;
         $lastid = $id;
      } # end scanning old index

      if ($messagenumber>=0) { #at least one message header matched?
          # did the last successful match make it exactly to the end of the folder?
         if ($totalsize+$lastsize == $foldersize) {
            # yes? then the last message is OK
            $FDB{$lastid}=$OLDFDB{$lastid};
            $zapsize+=$lastzapsize;
            $internalmessages+=$lastinternal;
            $newmessages+=$lastnewmsg;
           $totalsize+=$lastsize;
         } else {
            # did the last valid header match end at the start at a new message?
            seek( $folderhandle, $totalsize+$lastsize-2, 0 );
            my $buff; read($folderhandle, $buff, 7);
            if ( $buff eq "\n\nFrom " ) {
               # yes? then the last matching message is OK
               $FDB{$lastid}=$OLDFDB{$lastid};
               $zapsize+=$lastzapsize;
               $internalmessages+=$lastinternal;
               $newmessages+=$lastnewmsg;
               $totalsize+=$lastsize;
            } else { # the last valid message header was not trusted
               $messagenumber--;
            }
         }
      }
   }
   buffer_reset($folderhandle, $totalsize);

   my ($header_offset, $r_content) = _get_next_msgheader_buffered(0);
   $totalsize=$header_offset;

   my $r_message;
   my %flag=();		# internal flag, member: T(has att), V(verified), Z(to be zapped);

   while ($header_offset >=0 and !$dberr) {

      foreach (qw(T V Z)) { $flag{$_}=0 }
      $r_message=_get_msghash_from_header($header_offset, $r_content);
      $messagenumber++;
      $internalmessages++ if ($$r_message{msg_internal});
      $newmessages++ if($$r_message{msg_new});

      # check if msg info recorded in old folderdb, we can seek to msg end quickly
      # and skip scanning the content types
      my ($skip, $oldstatus, $oldcharset, $oldchksum ) = (string2msgattr( $OLDFDB{$$r_message{'message-id'}} ))[$_SIZE, $_STATUS, $_CHARSET, $_HEADERCHKSUM];
      $skip = 0 if ($oldchksum ne $$r_message{headerchksum});

      if ( $skip ) {  #old message match
         foreach (qw(T V Z)) {
            $flag{$_}=1 if ($oldstatus =~ m/$_/i);
         } # copy internal flags
         $$r_message{charset}=$oldcharset;
         $zapsize += $skip if ($oldstatus =~ m/Z/i);
         # skip past this message, we're already positioned at the end of the header
         $skip -= $$r_message{headersize};
      } else {	# new msg
         if ($$r_message{msg_type} eq 'm') {
            # multipart message
            my $block=_skip_to_next_text_block();
            while ( $block ne '') {
               if ($$r_message{charset} eq '' and
                   $block =~ m/^--/ and
                   # note the match 'm' option to check multiple lines
                   $block =~ m/^content-type:.*;\s*charset="?([^\s"';]*)"?/ims ) {	# att header
                  $$r_message{charset}=$1;
               }
               if ( !$flag{T} and
                    ($block =~ m/^content-type:.*;\s*name\s*\*?=/ims or
                     $block =~ m/^content-disposition:.*;\s*filename\s*\*?=/ims) ) {
                  $flag{T}=1;
               }
               if (!$flag{T} or $$r_message{charset} eq '') { 
                  $block=_skip_to_next_text_block();
               } else {
                  $block='';
               }
            }

         } elsif ( $$r_message{msg_type} eq 'p') {
            # plain text message
            my $block=_skip_to_next_text_block();
            while ( $block ne '') {
               if ( $block =~ m/^begin [0-7][0-7][0-7][0-7]? [^\n\r]+/mi) {
                  $flag{T}=1;
                  $block='';
               } else { 
                  $block=_skip_to_next_text_block();
               }
            }

         }
      }
      ($header_offset, $r_content) = _get_next_msgheader_buffered($skip);
      if ( $header_offset>=0 ) {	# next msg start found
         $$r_message{size}=$header_offset-$totalsize;
         $totalsize=$header_offset;
      } else {				# folder end
         # reget folder size in case it isn't larger than current msg start
         # this happens only if other process writes to folder without checking filelock
         if ($foldersize<=$totalsize) {
            $foldersize=(stat($folderhandle))[7];
         }
         $$r_message{size}=$foldersize-$totalsize;
      }
      $dberr=_update_message_index(\%FDB, $r_message, \%flag, \$zapsize);
   }

   close ($folderhandle);

   if ( !$dberr ) {
      $FDB{'ALLMESSAGES'}=$messagenumber+1;
      $FDB{'INTERNALMESSAGES'}=$internalmessages;
      $FDB{'NEWMESSAGES'}=$newmessages;
      $FDB{'ZAPSIZE'}=$zapsize;
      $FDB{'DBVERSION'}=$DBVERSION;
      $FDB{'METAINFO'}=$foldermeta;
   }

   ow::dbm::close(\%FDB, $folderdb);

   # remove old folderdb
   if ( ow::dbm::exist("$folderdb.old") ) {
      ow::dbm::close(\%OLDFDB, "$folderdb.old");
      ow::dbm::unlink("$folderdb.old");
   }

   return -1 if ($dberr);
   return 1;
}

# verify an index entry against the folder file contents
# We're only checking the message header contents here
# Making an assumption that as long as the header matches, the body will too.
# Note we're modifiying the folder current position pointer (and not putting it back!)
# size attribute will be zero if the index can't be validated
sub _get_validated_msgattr {
   my ($folderhandle, $r_FDB, $msgid) =@_;

   if ( defined $$r_FDB{$msgid} ) {
      my @attr = string2msgattr( $$r_FDB{$msgid} );
      # now validate the index attributes;
      if ( $attr[$_OFFSET] >=0 and
           $attr[$_HEADERSIZE] >0 and
           $attr[$_SIZE] > $attr[$_HEADERSIZE] ) {
         my $buff='';
         seek( $folderhandle, $attr[$_OFFSET], 0 );
         my $readlen=read($folderhandle, $buff, $attr[$_HEADERSIZE]);
         if ( $readlen == $attr[$_HEADERSIZE] and
              $buff =~ m/^From / and
              $attr[$_HEADERCHKSUM] eq ow::tool::calc_checksum(\$buff) ) {
            return @attr;
         }
      }
   }
   return ();
}

sub _get_msghash_from_header {
   my ($header_offset, $r_header_content)=@_;

   my %message=();

   foreach (qw(from to date subject content-type)) { $message{$_}='N/A' }
   foreach (qw(message-id status references charset in-reply-to)) { $message{$_}='' }

   ow::mailparse::parse_header($r_header_content, \%message);
   $message{status}.=$message{'x-status'} if (defined($message{'x-status'}));
   $message{status}.='I' if ($message{priority} =~ m/urgent/i);

   # Convert to readable text from MIME-encoded
   foreach (qw(from to subject)) {
      $message{$_} = ow::mime::decode_mimewords($message{$_});
   }

   my $dateserial=ow::datetime::datefield2dateserial($message{date});
   my $deliserial=ow::datetime::delimiter2dateserial($message{delimiter}, $config{'deliver_use_GMT'}, $prefs{'daylightsaving'}) ||
                  ow::datetime::gmtime2dateserial();
   if ($dateserial eq "") {
      $dateserial=$deliserial;
   } elsif ($deliserial ne "") {
      my $t=ow::datetime::dateserial2gmtime($deliserial) - ow::datetime::dateserial2gmtime($dateserial);
      $dateserial=$deliserial if ($t>86400*7 || $t<-86400); # msg transmission time use deliverytime in case sender host may have wrong time configuration
   }
   $message{date}=$dateserial;

   $message{msg_internal}=1 if ( is_internal_subject($message{subject}) );
   $message{msg_new}=1 if ( $message{status} !~ m/r/i );

   if ($message{'content-type'} =~ m/^multipart/i) {
      $message{msg_type}='m';
   } elsif ($message{'content-type'} eq 'N/A' or $message{'content-type'} =~ m/^text\/plain/i ) {
      $message{msg_type}='p';
   }

   $message{offset} = $header_offset;
   $message{headersize}=length($$r_header_content);
   $message{headerchksum}=ow::tool::calc_checksum($r_header_content);

   return \%message;
}

# returns: $offset, $r_content
sub _get_next_msgheader_buffered {
   my ($skip)=@_;

   my $pos=0;
   my $offset=-1;
   my $content='';

   buffer_skipchars($skip) if ($skip);

   # locate the start of the message
   while ($offset < 0 and $pos >= 0) {
      $pos=buffer_index("From ");
      $offset = buffer_startmsgchk($pos) if ($pos>=0);
   }

   # get msgheader until to the first nlnl (pos>0) or end of file(pos=-1)
   # note: the 1st nl is counted as part of the msgheader
   if ($offset >=0) {
      $pos=buffer_index("\n\n",1); 
      $pos++ if ($pos>=0);		# count 1st nl into msgheader
      $content=buffer_getchars($pos);
   }

   return ($offset, \$content);
}

# search the buffered file for a block of text (delimited by \n\n)
# we're only interested in returning the first 500 or less bytes of the block
sub _skip_to_next_text_block {
   my $block_content='';

   # skip past any leading new line characters
   buffer_skipleading("\n");

   # we're done if this is the next message block
   if ( buffer_startmsgchk(0)<0 ) {
      # get max 500 chars or to the end of the block
      $block_content=buffer_getchars(500,"\n\n");
      # skip to the next block end
      my $pos=buffer_index("\n\n");
      buffer_skipchars($pos);
   }

   return ($block_content);
}

sub _update_message_index {
   my ($r_FDB, $r_message, $r_flag, $r_zapsize)=@_;

   # try to get charset from contenttype header
   if ($$r_message{charset} eq "" && 
       $$r_message{'content-type'} =~ m/charset\s*=\s*"?([^\s"';]*)"?\s?/i) {
      $$r_message{charset}=$1;
   }

   # in most case, a msg references field should already contain
   # ids in in-reply-to: field, but do check it again here
   if ($$r_message{'in-reply-to'} =~ m/^\s*(\<\S+\>)\s*$/) {
      $$r_message{references} .= " " . $1 if ($$r_message{references} !~ m/\Q$1\E/);
   }
   $$r_message{references} =~ s/\s{2,}/ /g;

   if ($$r_message{'message-id'} eq '') {	# fake messageid with date and from
      $$r_message{'message-id'}="$$r_message{date}.".(ow::tool::email2nameaddr($$r_message{from}))[1];
      $$r_message{'message-id'} =~s![\<\>\(\)\s\/"':]!!g;
      $$r_message{'message-id'}="<$$r_message{'message-id'}>";
   } elsif (length($$r_message{'message-id'})>=128) {
      $$r_message{'message-id'}='<'.substr($$r_message{'message-id'}, 1, 125).'>';
   }

   # flags used by openwebmail internally
   foreach (qw(T V Z)) { $$r_message{status} .= $_ if ($$r_flag{$_}) }
   $$r_message{status} =~ s/\s//g;	# remove blanks

   my $id=$$r_message{'message-id'};
   if (defined($$r_FDB{$id})) {	# duplicated msg found?
      if ( $$r_message{status}!~m/Z/ ) {
         #  mark previous one as zap
         my @attr0=string2msgattr( $$r_FDB{$id} );
         $attr0[$_STATUS].='Z' if ($attr0[$_STATUS] !~ m/Z/i);
         $$r_FDB{"DUP$attr0[$_OFFSET]-$id"}=msgattr2string(@attr0);
         ${$r_zapsize}+=$attr0[$_SIZE];
      } else {
         # mark this msg as zap
         $$r_message{status}.='Z';
         $$r_zapsize+=$$r_message{size};
         $id="DUP$$r_message{offset}-$id";
      }
   }
   return -1 if (!_update_index_with_msghash($r_FDB,$id,$r_message));
   return 0;
}

sub _update_index_with_msghash {
   my ($r_FDB, $id, $r_message)=@_;
   $$r_FDB{$id}=msgattr2string(${$r_message}{offset}, ${$r_message}{from}, ${$r_message}{to},
      ${$r_message}{date}, ${$r_message}{subject}, ${$r_message}{'content-type'}, ${$r_message}{status}, 
      ${$r_message}{size}, ${$r_message}{references}, ${$r_message}{charset}, 
      ${$r_message}{headersize}, ${$r_message}{headerchksum});
   return 1;
}

########## END UPDATE_FOLDERDB ####################################

########## GET_MESSAGEIDS_SORTED_BY_OFFSET #######################
sub get_messageids_sorted_by_offset {
   my $folderdb=$_[0];
   my %FDB;

   ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or return ();

   my @keys = get_messageids_sorted_by_offset_db( \%FDB );

   ow::dbm::close(\%FDB, $folderdb);

   return @keys;
}
########## END GET_MESSAGEIDS_OSRTED_BY_OFFSET ###################

########## GET_MESSAGEIDS_SORTED_BY_OFFSET #######################
# same as above, only no DBM open close
sub get_messageids_sorted_by_offset_db {
   my ($r_FDB)=@_;
   my (%offset, $key, $data);
   while ( ($key,$data)=each(%$r_FDB) ) {
      $offset{$key}=(string2msgattr($data))[$_OFFSET] if (!$is_internal_dbkey{$key});
   }
   return( sort { $offset{$a}<=>$offset{$b} } keys(%offset) );
}
########## END GET_MESSAGEIDS_OSRTED_BY_OFFSET ###################

########## GET_INFO_MSGID2ATTRS ##################################
sub get_info_msgid2attrs {
   my ($folderdb, $ignore_internal, @attrnum)=@_;

   my %msgid2attr=();
   my ($total, $new, $totalsize)=(0,0,0);;
   my (%FDB, $key, $data, @attr);

   ow::dbm::open(\%FDB, $folderdb, LOCK_SH)
      or return ($totalsize, $total, $new, \%msgid2attr);
   while ( ($key, $data)=each(%FDB) ) {
      if ($is_internal_dbkey{$key}) {
         $new=$data if ($key eq 'NEWMESSAGES');
         next;
      } else {
         @attr=string2msgattr( $data );
         next if ($attr[$_STATUS] =~ m/Z/i);
         next if ($ignore_internal && is_internal_subject($attr[$_SUBJECT]));
         $total++;
         $totalsize+=$attr[$_SIZE];
         my @attr2=@attr[@attrnum];
         $msgid2attr{$key}=\@attr2;
      }
   }
   ow::dbm::close(\%FDB, $folderdb);

   return($totalsize, $total, $new, \%msgid2attr);
}
########## END GET_INFO_MSGID2ATTRS ##############################

########## GET_MESSAGE_.... ######################################
sub get_message_attributes {
   my ($messageid, $folderdb)=@_;
   my (%FDB, @attr);

   ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or return @attr;

   @attr=string2msgattr( $FDB{$messageid} );
   ow::dbm::close(\%FDB, $folderdb);
   return(@attr);
}

sub get_message_block {
   my ($messageid, $folderdb, $folderhandle)=@_;
   my $buff;

   my @attr=get_message_attributes($messageid, $folderdb);
   if ($attr[$_SIZE]>0) {
      seek($folderhandle, $attr[$_OFFSET], 0);
      my $bytes=read($folderhandle, $buff, $attr[$_SIZE]);
      # what we read should match what we asked for!
      if ($bytes !=  $attr[$_SIZE]) {	# trying to read past end of file foldersize?
         $buff="";
         writelog("db error - msg $messageid in $folderdb readsize mismatched, msgsize=$attr[$_SIZE], read=$bytes");
      }
   } else {
      $buff="";
      writelog("db error - msg $messageid has invalid size $attr[$_SIZE] in $folderdb");
   }
   return(\$buff);
}

########## END GET_MESSAGE_.... ##################################

########## UPDATE_MESSAGE_STATUS #################################
sub update_message_status {
   my ($messageid, $status, $folderdb, $folderfile) = @_;
   my $folderhandle=FileHandle->new();
   my %FDB;
   my $ioerr=0;

   if (update_folderindex($folderfile, $folderdb)<0) {
      writelog("db error - Couldn't update index db $folderdb");
      writehistory("db error - Couldn't update index db $folderdb");
      return -1;
   }

   ow::dbm::open(\%FDB, $folderdb, LOCK_EX) or return -1;

   my @messageids=get_messageids_sorted_by_offset_db(\%FDB);
   my $movement=0;
   my @attr;
   my $i;

   if (!open ($folderhandle, "+<$folderfile")) {
      ow::dbm::close(\%FDB, $folderdb);
      return -3;
   }
   # since setvbuf is only available before perl 5.8.0, we put this inside eval
   eval { my $_vbuf; $folderhandle->setvbuf($_vbuf, _IOFBF,  $BUFF_blocksize) };

   for ($i=0; $i<=$#messageids; $i++) {
      if ($messageids[$i] eq $messageid) {

         @attr = string2msgattr( $FDB{$messageid} ) if ( defined $FDB{$messageid} );

         my $messagestart=$attr[$_OFFSET];
         my $headerlen=$attr[$_HEADERSIZE];
         my $headerend=$messagestart+$headerlen;

         my $header;
         seek ($folderhandle, $messagestart, 0);
         read ($folderhandle, $header, $headerlen);	# header ends with one \n

         if ($header!~/^From /) { # index not consistent with folder content
            close ($folderhandle);

            writelog("db warning - msg $messageid in $folderfile index inconsistence - ".__FILE__.':'.__LINE__);
            writehistory("db warning - msg $messageid in $folderfile index inconsistence - ".__FILE__.':'.__LINE__);

            close ($folderhandle);
            $FDB{'METAINFO'}="ERR";
            ow::dbm::close(\%FDB, $folderdb);

            # forced reindex since metainfo = ERR
            update_folderindex($folderfile, $folderdb);
            return -3;
         }
         last if ($attr[$_STATUS] eq $status);

         # update status, flags from rfc2076
         my $status_update = "";
         if ($status =~ m/[ro]/i) {
            $status_update .= "R" if ($status =~ m/r/i); # Read
            $status_update .= "O" if ($status =~ m/o/i); # Old
         } else {
            $status_update .= "N" if ($status =~ m/n/i); # New
            $status_update .= "U" if ($status =~ m/u/i); # still Undownloaded & Undeleted
         }
         $status_update .= "D" if ($status =~ m/d/i); # to be Deleted
         if ($status_update ne "") {
            if (!($header =~ s/^status:.*\n/Status: $status_update\n/im)) {
               $header .= "Status: $status_update\n";
            }
         } else {
            $header =~ s/^status:.*\n//im;
         }

	 # update x-status
         $status_update = "";
         $status_update .= "A" if ($status =~ m/a/i); # Answered
         $status_update .= "I" if ($status =~ m/i/i); # Important
         $status_update .= "D" if ($status =~ m/d/i); # to be Deleted
         if ($status_update ne "") {
            if (!($header =~ s/^x-status:.*\n/X-Status: $status_update\n/im)) {
               $header .= "X-Status: $status_update\n";
            }
         } else {
            $header =~ s/^x-status:.*\n//im;
         }

         my $newheaderlen=length($header);
         $movement=ow::tool::untaint($newheaderlen-$headerlen);

         my $foldersize=(stat($folderhandle))[7];
         if (shiftblock($folderhandle, $headerend, $foldersize-$headerend, $movement)<0) {
            writelog("data error - msg $messageids[$i] in $folderfile shiftblock failed");
            writehistory("data error - msg $messageids[$i] in $folderfile shiftblock failed");
            $ioerr++;
         }

         if (!$ioerr) {
            seek($folderhandle, $messagestart, 0);
            print $folderhandle $header or $ioerr++;
         }

         if (!$ioerr) {
            truncate($folderhandle, $foldersize+$movement) or writelog("truncate failed??");
            # set attributes in folderdb for this status changed message
            if ($attr[$_STATUS] !~ m/r/i && $status =~ m/r/i) {
               $FDB{'NEWMESSAGES'}--;
               $FDB{'NEWMESSAGES'}=0 if ($FDB{'NEWMESSAGES'}<0); # should not happen
            } elsif ($attr[$_STATUS] =~ m/r/i && $status !~ m/r/i) {
               $FDB{'NEWMESSAGES'}++;
            }
            $FDB{'ZAPSIZE'}+=$movement if ($status =~ m/Z/i);

            $attr[$_SIZE] += $movement;
            $attr[$_STATUS]=$status;
            $attr[$_HEADERCHKSUM]=ow::tool::calc_checksum(\$header);
            $attr[$_HEADERSIZE]=$newheaderlen;
            $FDB{$messageid}=msgattr2string(@attr);
         }

         last;
      }
   }
   close ($folderhandle);

   writelog("db warning - msg $messageid in $folderfile index missing") if ($i>$#messageids);

   $i++;

   # if size of this message is changed
   if ($movement!=0 && !$ioerr) {
      #  change offset attr for messages after the above one
      for (;$i<=$#messageids; $i++) {
         @attr=string2msgattr( $FDB{$messageids[$i]} );
         $attr[$_OFFSET]+=$movement;
         $FDB{$messageids[$i]}=msgattr2string(@attr);
      }
   }

   # update folder metainfo
   $FDB{'METAINFO'}=ow::tool::metainfo($folderfile) if (!$ioerr);

   ow::dbm::close(\%FDB, $folderdb);

   if (!$ioerr) {
      return 0;
   } else {
      return -3;
   }
}
########## END UPDATE_MESSAGE_STATUS #############################

########## OP_MESSAGE_WITH_IDS ###################################
# operate messages with @messageids from src folderfile to dst folderfile
# available $op: "move", "copy", "delete"
sub operate_message_with_ids {
   my ($op, $r_messageids, $srcfile, $srcdb, $dstfile, $dstdb)=@_;
   my (%FDB, %FDB2);
   my $opendst=0;

   # $lang_err{'inv_msg_op'}
   return -1 if ($op ne "move" && $op ne "copy" && $op ne "delete");
   return 0 if ($srcfile eq $dstfile || $#{$r_messageids} < 0);

   if (update_folderindex($srcfile, $srcdb)<0) {
      writelog("db error - Couldn't update index db $srcdb");
      writehistory("db error - Couldn't update index db $srcdb");
      return -1;
   }

   my $srchandle=FileHandle->new();
   return -3 if (!open($srchandle, $srcfile));
   return -1 if (!ow::dbm::open(\%FDB, $srcdb, LOCK_EX));

   my $dsthandle=FileHandle->new();
   my $dstlength=0;
   my $readlen=0;
   if ($op eq "move" || $op eq "copy") {
      if (update_folderindex($dstfile, $dstdb)<0) {
         ow::dbm::close(\%FDB, $srcdb);
         close ($srchandle);
         writelog("db error - Couldn't update index db $dstdb");
         writehistory("db error - Couldn't update index db $dstdb");
         return -1;
      }

      if (!open ($dsthandle, ">>$dstfile")) {
         ow::dbm::close(\%FDB, $srcdb);
         close ($srchandle);
         return -5;
      }
      $dstlength=(stat($dsthandle))[7];
      # since setvbuf is only available before perl 5.8.0, we put this inside eval
      eval { my $_dstvbuf; $dsthandle->setvbuf($_dstvbuf, _IOFBF,  $BUFF_blocksize) };

      if (!ow::dbm::open(\%FDB2,$dstdb, LOCK_EX)) {
         close ($dsthandle);
         ow::dbm::close(\%FDB, $srcdb);
         close ($srchandle);
         writelog("db error - Couldn't open index db $dstdb");
         writehistory("db error - Couldn't open index db $dstdb");
         return -1;
      }
      $opendst=1;
   }

   my $counted=0;
   foreach my $messageid (@{$r_messageids}) {
      next if (!defined($FDB{$messageid}));

      my @attr = string2msgattr( $FDB{$messageid} );

      if (!is_msgattr_consistent_with_folder(\@attr, $srchandle)) {	# index not consistent with folder content
         writelog("db warning - msg $messageid in $srcfile index inconsistence - ".__FILE__.':'.__LINE__);
         writehistory("db warning - msg $messageid in $srcfile index inconsistence - ".__FILE__.':'.__LINE__);

         close ($srchandle);
         $FDB{'METAINFO'}="ERR";
         ow::dbm::close(\%FDB, $srcdb);         

         # forced reindex since metainfo = ERR
         update_folderindex($srcfile, $srcdb);

         if ($opendst) {
            close ($dsthandle);
            $FDB2{'METAINFO'}="ERR";
            ow::dbm::close(\%FDB2,$dstdb);
            update_folderindex($dsthandle, $dstdb);	# ensure msg cp/mv to dst are correctly indexed
         }
         return -8;
      } 

      $counted++;
      # append msg to dst folder only if op=move/copy and msg doesn't exist in dstfile
      if ($opendst) {
         if (defined($FDB2{$messageid})) {
            my @attr0=string2msgattr( $FDB2{$messageid} );
            if ($attr0[$_SIZE] eq $attr[$_SIZE]) {	# skip the cp because same size
               if ($attr0[$_STATUS] =~ s/Z//ig) {
                  $FDB2{$messageid}=msgattr2string(@attr0);
                  $FDB2{'ZAPSIZE'}-=$attr0[$_SIZE];
               }
            } else {
               if ($attr0[$_STATUS] !~ m/Z/i) {		# mark old duplicated one as zap
                  $attr0[$_STATUS].='Z';
                  $FDB2{'ZAPSIZE'}+=$attr0[$_SIZE];
               }
               $FDB2{"DUP$attr0[$_OFFSET]-$messageid"}=msgattr2string(@attr0);
               delete $FDB2{$messageid};
            }
         }

         if (!defined($FDB2{$messageid})) {	# cp message from $srchandle to $dsthandle
            # since @attr will be used for FDB2 temporarily and $attr[$_OFFSET] will be modified
            # we save it in $srcoffset and copy it back after write of dst folder
            my $srcoffset=$attr[$_OFFSET];
            seek($srchandle, $srcoffset, 0);

            my $left=$attr[$_SIZE];
            my $buff='';
            while ($left>0) {
               my $dstioerr=0;
               if ($left>$BUFF_blocksize) {
                  read($srchandle, $buff,  $BUFF_blocksize);
               } else {
                  read($srchandle, $buff, $left);
               }
               print $dsthandle $buff or $dstioerr=1;

               if ($dstioerr) {
                  writelog("data error - Couldn't write $dstfile, $!");
                  close ($srchandle);
                  ow::dbm::close(\%FDB, $srcdb);
                  truncate($dsthandle, $dstlength);	# cut at last successful write
                  close ($dsthandle);
                  $FDB2{'METAINFO'}='ERR';
                  ow::dbm::close(\%FDB2, $dstdb);
                  return -8;
               }

               $left-=$BUFF_blocksize;
            }

            $FDB2{'NEWMESSAGES'}++ if ($attr[$_STATUS] !~ m/r/i);
            $FDB2{'INTERNALMESSAGES'}++ if (is_internal_subject($attr[$_SUBJECT]));
            $FDB2{'ALLMESSAGES'}++;
            $attr[$_OFFSET]=$dstlength;
            $dstlength+=$attr[$_SIZE];
            $FDB2{$messageid}=msgattr2string(@attr);
            $attr[$_OFFSET]=$srcoffset;
         }
      }

      if (($op eq 'move' || $op eq 'delete') && $attr[$_STATUS] !~ m/Z/i) {
         $attr[$_STATUS].='Z';	# to be zapped in the future
         $FDB{'ZAPSIZE'}+=$attr[$_SIZE];
         $FDB{$messageid}=msgattr2string(@attr);	# $attr[$_OFFSET] is used here
      }
   }

   if ($opendst) {
      close ($dsthandle);
      $FDB2{'METAINFO'}=ow::tool::metainfo($dstfile);
      ow::dbm::close(\%FDB2, $dstdb);
   }
   close ($srchandle);
   ow::dbm::close(\%FDB, $srcdb);

   return($counted);
}

sub folder_zapmessages {
   my ($srcfile, $srcdb)=@_;
   my %FDB;
   my $ioerr=0;

   if (update_folderindex($srcfile, $srcdb)<0) {
      writelog("db error - Couldn't update index db $srcdb");
      writehistory("db error - Couldn't update index db $srcdb");
      return -2;
   }

   return -1 if ( !ow::dbm::open(\%FDB, $srcdb, LOCK_SH) );
   my $zapsize=$FDB{'ZAPSIZE'};
   ow::dbm::close(\%FDB, $srcdb);
   return 0 if ($zapsize==0);	# no zap messages in folder

   my $folderhandle=FileHandle->new();
   return -3 if (!open ($folderhandle, "+<$srcfile"));
   # since setvbuf is only available before perl 5.8.0, we put this inside eval
   eval { my $_vbuf; $folderhandle->setvbuf($_vbuf, _IOFBF, $BUFF_blocksize) };

   if ( !ow::dbm::open(\%FDB, $srcdb, LOCK_EX) ) {
      close ($folderhandle);
      return -1;
   }

   my @allmessageids=get_messageids_sorted_by_offset_db(\%FDB);

   my ($blockstart, $blockend, $writepointer);
   my $counted=0;

   $blockstart=$blockend=$writepointer=0;

   for (my $i=0; $i<=$#allmessageids; $i++) {
      my $messageid=$allmessageids[$i];
      my @attr=string2msgattr( $FDB{$messageid} );

      if (!is_msgattr_consistent_with_folder(\@attr, $folderhandle)) {	# index not consistent with folder content
         writelog("db warning - msg $messageid in $srcfile index inconsistence - ".__FILE__.':'.__LINE__);
         writehistory("db warning - msg $messageid in $srcfile index inconsistence - ".__FILE__.':'.__LINE__);

         $FDB{'METAINFO'}="ERR";
         ow::dbm::close(\%FDB, $srcdb);
         close ($folderhandle);

         return -10;
      } 

      my $nextstart=ow::tool::untaint($attr[$_OFFSET]+$attr[$_SIZE]);
      if ( $attr[$_STATUS] =~ m/Z/ ) {
         $counted++;
         if ( shiftblock($folderhandle, $blockstart, $blockend-$blockstart, $writepointer-$blockstart)<0 ) {
            writelog("data error - msg $messageid in $srcfile shiftblock failed, $!");
            writehistory("data error - msg $messageid in $srcfile shiftblock failed, $!");
            $ioerr++;
         } else {
            $writepointer=$writepointer+($blockend-$blockstart);
            $blockstart=$blockend=$nextstart;
         }
         if (!$ioerr) {
            $FDB{'NEWMESSAGES'}-- if ($attr[$_STATUS] !~ m/r/i);
            $FDB{'INTERNALMESSAGES'}-- if (is_internal_subject($attr[$_SUBJECT]));
            $FDB{'ALLMESSAGES'}--;
            $FDB{'ZAPSIZE'}-=$attr[$_SIZE];
            delete $FDB{$messageid};
         }

      } else {						# msg to be kept in same folder
         $blockend=$nextstart;
         my $movement=$writepointer-$blockstart;
         if ($movement<0) {
            $attr[$_OFFSET]+=$movement;
            $FDB{$messageid}=msgattr2string(@attr);
         }
      }

      last if ($ioerr);
   }

   if ($counted>0 && !$ioerr) {
      if (shiftblock($folderhandle, $blockstart, $blockend-$blockstart, $writepointer-$blockstart)<0) {
         writelog("data error - msgs in $srcfile shiftblock failed, $!");
         writehistory("data error - msgs in $srcfile shiftblock failed, $!");
         $ioerr++;
      } else {
         truncate($folderhandle, $writepointer+$blockend-$blockstart);
      }
   }

   close ($folderhandle);

   if (!$ioerr) {
      foreach (qw(NEWMESSAGES INTERNALMESSAGES ALLMESSAGES ZAPSIZE)) {
         $FDB{$_}=0 if $FDB{$_}<0;	# should not happen
      }
      $FDB{'METAINFO'}=ow::tool::metainfo($srcfile);
   } else {
      $FDB{'METAINFO'}='ERR';
   }
   ow::dbm::close(\%FDB, $srcdb);

   return -9 if ($ioerr);

   return($counted);
}
########## END OP_MESSAGE_WITH_IDS ###############################

########## DELETE_MESSAGE_BY_AGE #################################
sub delete_message_by_age {
   my ($dayage, $folderdb, $folderfile)=@_;
   return 0 if ( ! -f $folderfile );

   my $folderhandle=do { local *FH };
   my (%FDB, $key, $data, @allmessageids, @agedids);

   if (update_folderindex($folderfile, $folderdb)<0) {
      ow::filelock::lock($folderfile, LOCK_UN);
      writelog("db error - Couldn't update index db $folderdb");
      writehistory("db error - Couldn't update index db $folderdb");
      return 0;
   }
    my $agestarttime=time()-$dayage*86400;

   ow::dbm::open(\%FDB, $folderdb, LOCK_EX) or return -1;

   while ( ($key, $data)=each(%FDB) ) {
      my @attr = string2msgattr( $data );
      push(@agedids, $key) if (ow::datetime::dateserial2gmtime($attr[$_DATE])<=$agestarttime); # too old
   }
   ow::dbm::close(\%FDB, $folderdb);

   return 0 if ($#agedids==-1);

   my $deleted=operate_message_with_ids('delete', \@agedids, $folderfile, $folderdb);
   my $zapped=folder_zapmessages($folderfile, $folderdb);

   return($zapped) if ($deleted<0);
   return($deleted);
}
########## END DELETE_MESSAGE_BY_AGE #############################

########## MOVE_OLDMSG_FROM_FOLDER ###############################
sub move_oldmsg_from_folder {
   my ($srcfile, $srcdb, $dstfile, $dstdb)=@_;

   my (%FDB, $key, $data, @attr);
   my @messageids=();

   ow::dbm::open(\%FDB, $srcdb, LOCK_SH) or return -1;

   # if oldmsg == internal msg or 0, then do not read ids
   if ( $FDB{'ALLMESSAGES'}-$FDB{'NEWMESSAGES'} > $FDB{'INTERNALMESSAGES'} ) {
      while ( ($key, $data)=each(%FDB) ) {
         next if ($is_internal_dbkey{$key});
         @attr=string2msgattr( $data );
         if ( $attr[$_STATUS] =~ m/r/i &&
              !is_internal_subject($attr[$_SUBJECT]) ) {
            push(@messageids, $key);
         }
      }
   }

   ow::dbm::close(\%FDB, $srcdb);

   # no old msg found
   return 0 if ($#messageids==-1);

   my $moved=operate_message_with_ids('move', \@messageids, $srcfile, $srcdb, $dstfile, $dstdb);
   my $zapped=folder_zapmessages($srcfile, $srcdb);

   return($zapped) if ($moved<0);
   return($moved);
}
########## END MOVE_OLDMSG_FROM_FOLDER ###########################

########## REBUILD_MESSAGE_WITH_PARTIALID ########################
# rebuild orig msg with partial msgs in the same folder
sub rebuild_message_with_partialid {
   my ($folderfile, $folderdb, $partialid)=@_;

   my (%FDB, $id, $data);
   my ($partialtotal, @partialmsgids, @offset, @size);

   if (update_folderindex($folderfile, $folderdb)<0) {
      ow::filelock::lock($folderfile, LOCK_UN);
      writelog("db error - Couldn't update index db $folderdb");
      writehistory("db error - Couldn't update index db $folderdb");
      return -1;
   }

   # find all partial msgids
   ow::dbm::open(\%FDB, $folderdb, LOCK_SH) or return -2;

   while ( ($id,$data)=each(%FDB) ) {
      next if ($is_internal_dbkey{$id});
      my @attr=string2msgattr($data);
      next if ($attr[$_CONTENT_TYPE] !~ m/^message\/partial/i );

      $attr[$_CONTENT_TYPE] =~ m/;\s*id="(.+?)";?/i;
      next if ($partialid ne $1);

      if ($attr[$_CONTENT_TYPE] =~ m/;\s*number="?(.+?)"?;?/i) {
         my $n=$1;
         $partialmsgids[$n]=$id;
         $offset[$n]=$attr[$_OFFSET];
         $size[$n]=$attr[$_SIZE];
         $partialtotal=$1 if ($attr[$_CONTENT_TYPE] =~ m/;\s*total="?(.+?)"?;?/i);
      }
   }
   ow::dbm::close(\%FDB, $folderdb);

   # check completeness
   if ($partialtotal<1) {	# last part not found
      return -3;
   }
   for (my $i=1; $i<=$partialtotal; $i++) {
      if ($partialmsgids[$i] eq "") {	# some part missing
         return -4;
      }
   }

   my $tmpfile=ow::tool::untaint("/tmp/rebuild_tmp_$$");
   my $tmpdb=ow::tool::untaint("/tmp/.rebuild_tmp_$$");

   ow::filelock::lock($tmpfile, LOCK_EX) or return -5;
   open (TMP,  ">$tmpfile");
   open (FOLDER, "$folderfile");

   seek(FOLDER, $offset[1], 0);
   my $line = <FOLDER>;
   my $writtensize = length($line);
   print TMP $line;	# copy delimiter line from 1st partial message

   for (my $i=1; $i<=$partialtotal; $i++) {
      my $currsize=0;
      seek(FOLDER, $offset[$i], 0);

      # skip header of the partial message
      while (defined($line = <FOLDER>)) {
         $currsize += length($line);
         last if ( $line =~ m/^\r*$/ );
      }

      # read body of the partial message and copy to tmpfile
      while (defined($line = <FOLDER>)) {
         $currsize += length($line);
         $writtensize += length($line);
         print TMP $line;
         last if ( $currsize>=$size[$i] );
      }
   }

   close(TMP);
   close(FOLDER);
   ow::filelock::lock($tmpfile, LOCK_EX) or return -6;

   # index tmpfile, get the msgid
   if (update_folderindex($tmpfile, $tmpdb)<0) {
      ow::filelock::lock($tmpfile, LOCK_UN);
      writelog("db error - Couldn't update index db $tmpdb");
      writehistory("db error - Couldn't update index db $tmpdb");
      return -7;
   }

   # check the rebuild integrity
   my @rebuildmsgids=get_messageids_sorted_by_offset($tmpdb);
   if ($#rebuildmsgids!=0) {
      unlink($tmpfile);
      ow::dbm::unlink($tmpdb);
      return -8;
   }
   my $rebuildsize=(get_message_attributes($rebuildmsgids[0], $tmpdb))[$_SIZE];
   if ($writtensize!=$rebuildsize) {
      unlink($tmpfile);
      ow::dbm::unlink($tmpdb);
      return -9;
   }

   operate_message_with_ids("move", \@rebuildmsgids, $tmpfile, $tmpdb, $folderfile, $folderdb);

   unlink($tmpfile);
   ow::dbm::unlink($tmpdb);

   return(0, $rebuildmsgids[0], @partialmsgids);
}
########## END REBUILD_MESSAGE_WITH_PARTIALID ####################

########## SHIFTBLOCK ############################################
sub shiftblock {
   my ($fh, $start, $size, $movement)=@_;
   return 0 if ($movement == 0 );

   my ($movestart, $buff);
   my $ioerr=0;
   my $left=$size;

   if ( $movement >0 ) {
      while ($left>$BUFF_blocksize && !$ioerr) {
          $movestart=$start+$left-$BUFF_blocksize;
          seek($fh, $movestart, 0);
          read($fh, $buff, $BUFF_blocksize);
          seek($fh, $movestart+$movement, 0);
          print $fh $buff or $ioerr++;
          $left=$left-$BUFF_blocksize;
      }
      if (!$ioerr) {
         seek($fh, $start, 0);
         read($fh, $buff, $left);
         seek($fh, $start+$movement, 0);
         print $fh $buff or $ioerr++;
      }

   } elsif ( $movement <0 ) {
      while ($left>$BUFF_blocksize && !$ioerr) {
         $movestart=$start+$size-$left;
         seek($fh, $movestart, 0);
         read($fh, $buff, $BUFF_blocksize);
         seek($fh, $movestart+$movement, 0);
         print $fh $buff or $ioerr++;
         $left=$left-$BUFF_blocksize;
      }
      if (!$ioerr) {
         $movestart=$start+$size-$left;
         seek($fh, $movestart, 0);
         read($fh, $buff, $left);
         seek($fh, $movestart+$movement, 0);
         print $fh $buff or $ioerr++;
      }
   }

   return -1 if ($ioerr);
   return 1;
}
########## END SHIFTBLOCK ########################################

########## EMPTYFOLDER ###########################################
sub emptyfolder {
   my ($folderfile, $folderdb) = @_;

   open (F, ">$folderfile") or return -1;
   close (F);
   return -2 if (update_folderindex($folderfile, $folderdb) <0);

   return 0;
}
########## END EMPTYFOLDER #######################################

########## STRING <-> MSGATTR ####################################
# we use \n as delimiter for attributes
# since we assume max record len is 1024, 
# len(msgid) < 128, len(other fields)<60, len(delimiter)=10,
# so len( from + to + subject + contenttype + references ) must < 826
sub msgattr2string {
   my (@attr)=@_;

   if ( $attr[$_OFFSET] <0 or
        $attr[$_HEADERSIZE]<=0 or
        $attr[$_SIZE] <= $attr[$_HEADERSIZE] ) {
        writelog(ow::tool::stacktrace("msgattr error"));
   }

   # remove delimiter \r,\n from string attributes
   for my $i ($_FROM, $_TO, $_SUBJECT, $_CONTENT_TYPE, $_REFERENCES, $_CHARSET) {
      $attr[$i]=~s/[\r\n]/ /sg;
   }	

   my $value=join("\n", @attr);
   if (length($value)>800) {
      foreach my $i ($_TO, $_SUBJECT, $_REFERENCES) {
         $attr[$i]=substr($attr[$i],0,253).'...' if (length($attr[$i])>256);
      }
      $value=join("\n", @attr);
      if (length($value)>800) {
         foreach my $i ($_FROM, $_TO, $_SUBJECT, $_CONTENT_TYPE, $_REFERENCES) {
            $attr[$i]=substr($attr[$i],0,157).'...' if (length($attr[$i])>160);
         }
         $value=join("\n", @attr);
      }
   }
   return $value;
}

sub string2msgattr {
   return (split(/\n/, $_[0]));
}
########## END STRING <-> MSGATTR ################################

########## SIMPLEHEADER ##########################################
sub simpleheader {
   my $simpleheader="";
   my $lastline = 'NONE';
   my $regex_simpleheaders=qr/^(?:from|reply-to|to|cc|date|subject):\s?/i;

   foreach (split(/\n/, $_[0])) {	# $_[0] is header
      if (/^\s+/) {
         $simpleheader.="$_\n" if ($lastline eq 'HEADER');
      } elsif (/$regex_simpleheaders/) {
         $simpleheader .= "$_\n"; $lastline = 'HEADER';
      } else {
         $lastline = 'NONE';
      }
   }
   return($simpleheader);
}
########## END SIMPLEHEADER ######################################

########## IS_INTERNAL_SUBJECT ###################################
sub is_internal_subject {
   return 1 if ($_[0] =~ m/(?:DON'T DELETE THIS MESSAGE|Message from mail server)/);
   return 0;
}
########## END IS_INTERNAL_SUBJECT ###############################

########## IS_MSGATTR_CONSISTENT_WITH_FOLDER #####################
# check if a message is valid based on its attr
sub is_msgattr_consistent_with_folder {
   my ($r_attr, $folderhandle)=@_;
   my $buff;

   return 0 if (${$r_attr}[$_OFFSET]<0 || 
                ${$r_attr}[$_HEADERSIZE]<=0 || 
                ${$r_attr}[$_SIZE]<=${$r_attr}[$_HEADERSIZE]);

   seek($folderhandle, ${$r_attr}[$_OFFSET], 0);
   read($folderhandle, $buff, 5);
   return 0 if ($buff!~/^From /);

   seek($folderhandle, ${$r_attr}[$_OFFSET]+${$r_attr}[$_SIZE], 0);
   read($folderhandle, $buff, 5);
   return 0 if ($buff!~/^From / && $buff ne "");

   return 1;
}
########## END IS_MESSAGE_VALID ##################################

########## BUFFERED FILE PROCESSING ##############################
# use buffered file reads to quickly scan through a mail file for the next message header

use vars qw($BUFF_filehandle $BUFF_filestart $BUFF_fileoffset $BUFF_start $BUFF_size $BUFF_buff $BUFF_EOF);
use vars qw($BUFF_blocksizemax $BUFF_regex);
$BUFF_blocksizemax=$BUFF_blocksize+512;
$BUFF_regex=qr/^From .*(\w\w\w)\s+(\w\w\w)\s+(\d+)\s+(\d+):(\d+):?(\d*)\s+([A-Z]{3,4}\d?\s+)?(\d\d+)/;

sub buffer_reset {
   ($BUFF_filehandle, $BUFF_filestart)=@_;
   $BUFF_fileoffset=$BUFF_filestart;
   $BUFF_start=$BUFF_filestart;
   $BUFF_size=0;
   $BUFF_buff='';
   $BUFF_EOF=0;
   buffer_readblock();
}

# read a new block from the file to the buffer
sub buffer_readblock {
   if (!$BUFF_EOF) {
      # make sure we're still in the file where we think we should be
      seek($BUFF_filehandle, $BUFF_fileoffset, 0);

      my $readlen=read($BUFF_filehandle, $BUFF_buff, $BUFF_blocksize, $BUFF_size);
      $BUFF_EOF=1 if ($readlen < $BUFF_blocksize);
      $BUFF_start=$BUFF_fileoffset-$BUFF_size;
      $BUFF_size+=$readlen;
      $BUFF_fileoffset+=$readlen;
      return $readlen;
   }
   return 0;
}

# check for the start of a new message
sub buffer_startmsgchk {
   my ($pos)=@_;

   # verify preceding new line characters
   # if this fails, bump the position to invalidate it
   if ( $pos>1 ) {
      $pos++ if (substr($BUFF_buff, $pos-2, 2) ne "\n\n");
   } elsif ( $pos==1 ) {
      $pos++ if (substr($BUFF_buff, $pos-1, 1) ne "\n");
   }

   # clear out the old buffer contents so we don't scan through them again
   buffer_skipchars($pos) if ($pos);

   # just in case we got too close to the end of the buffer, better top it up
   # or we might not match the regex
   buffer_readblock() if ($BUFF_size < 200);

   # check this message start more closely (this will fail if the preceding newline characters check above failed)
   if ( $BUFF_buff =~ m/$BUFF_regex/ ) {
      return $BUFF_start;
   } else {
      # if a 'From' is not a msgstart, skip it so we won't meet it again
      buffer_skipchars(4) if (substr($BUFF_buff, 0, 4) eq 'From');
      return -1;
   }
}
#
# Note: buffer_startmsgchk() uses too many string copy (the substr())
#       it should be further optimized with pos()
#
# example of pos()
# ----------------------------------------------
# $_ = 'this is a string of text';
# $pos = m/(\bs\w+)/g ? pos() - length($1)  : -1;
# print "$pos\n";
#

# get chars from the buffer
# up to the size, or to the delim chars (which ever comes first)
# the entire buffer/file if size = -1
# chars are removed from the buffer
sub buffer_getchars {
   my ($size, $delim)=@_;

   my $pos=-1;
   my $offset=0;
   my $len=length($delim);
   $pos=index($BUFF_buff,$delim,$offset) if ($len);

   # make sure the buffer contains enough bytes to meet the request
   while ( ( $size < 0 or $size > $BUFF_size) and $pos < 0 and ! $BUFF_EOF) {
      $offset+=($BUFF_size-$len) if ($BUFF_size>$len);
      buffer_readblock();
      $pos=index($BUFF_buff,$delim,$offset) if ($len);
   }

   $size=$pos if ($pos>=0);
   $size=$BUFF_size if ($size<0);

   my $content=substr($BUFF_buff, 0, $size);

   buffer_skipchars($size);
   return $content;
}

# skip past chars in the buffer
# the entire buffer/file if size = -1
# chars are removed from the buffer
sub buffer_skipchars {
   my ($skip)=@_;

   if ($skip < 0) {
      $BUFF_EOF = 1;
      $BUFF_size = 0;
      $BUFF_buff='';
   } elsif ($skip >= $BUFF_size) {
      # skipping passed the end of the buffer
      $BUFF_size = 0;
      $BUFF_buff='';
      $BUFF_fileoffset = $BUFF_start + $skip;
      buffer_readblock();
   } else {
      $BUFF_start += $skip;
      $BUFF_size -= $skip;
      $BUFF_buff = substr($BUFF_buff, $skip);
   }
}

# skip past chars in the buffer
# while $delim string is found
# chars are removed from the buffer
sub buffer_skipleading {
   my ($delim)=@_;
   my $len=length($delim);
   return if (!$len);

   my $skip=0;

   buffer_readblock() if ($BUFF_size<$len);
   while ( $BUFF_size>=$len and substr($BUFF_buff,$skip,$len) eq $delim ) {
      $skip+=$len;
      $BUFF_size-=$len;
      if ($BUFF_size < $len) {
         $BUFF_start += $skip;
         $BUFF_buff = substr($BUFF_buff, $skip);
         buffer_readblock();
         $skip=0;
      }
   }
   $BUFF_start += $skip;
   $BUFF_buff = substr($BUFF_buff, $skip);
}

# search the buffered file for a string
# if $keep = 1 then buffer contents will grow until $str is found
#  otherwise, previous contents of buffer are tossed.
sub buffer_index {
   my ($str, $keep)=@_;
   my $pos=-1;
   my $eof=0;
   my $offset=0;
   my $len=length($str);

   while ($pos<0 and !$eof) {

      # search the buffer for the next message start
      $pos=index($BUFF_buff, $str, $offset);

      next if ($pos >= 0);

      if ($keep) {
         $offset = $BUFF_size-$len;
      } else {
         # keep the buffer size reasonable
         buffer_skipchars($BUFF_blocksize) if ($BUFF_size > $BUFF_blocksizemax);
      }

      $eof=1 if ( !buffer_readblock() ); # nothing left to read?
   }
   return $pos;
}

1;
