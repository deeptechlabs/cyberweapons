#
# mailfilter.pl - mail filter routines
#
# 2001/11/13 Ebola.AT.turtle.ee.ncku.edu.tw
#            tung.AT.turtle.ee.ncku.edu.tw
#

use strict;
use Fcntl qw(:DEFAULT :flock);
use MIME::Base64;
use MIME::QuotedPrint;

# extern vars
use vars qw($_OFFSET $_FROM $_TO $_DATE $_SUBJECT $_CONTENT_TYPE $_STATUS $_SIZE $_REFERENCES $_CHARSET $_HEADERSIZE $_HEADERCHKSUM);
use vars qw(%config %lang_err);

# local global
use vars qw ($_PRIORITY $_RULETYPE $_INCLUDE $_TEXT $_OP $_DESTINATION $_ENABLE $_REGEX_TEXT);
($_PRIORITY, $_RULETYPE, $_INCLUDE, $_TEXT, $_OP, $_DESTINATION, $_ENABLE, $_REGEX_TEXT)=(0,1,2,3,4,5,6,7);

use vars qw(%op_order %ruletype_order);	# ruletype prefered order if same priority
%op_order=(
   copy   => 0, 
   move   => 1,
   delete => 2,
);
%ruletype_order=(
   from        => 0, 
   to          => 1,
   subject     => 2,
   header      => 3,
   smtprelay   => 4,
   attfilename => 5,
   textcontent => 6
);

########## FILTERMESSAGE #########################################
# return: 0=nothing, <0=error, n=filted count
# there are 4 op for a msg: 'copy', 'move', 'delete' and 'keep'
sub filtermessage {
   my ($user, $folder, $r_prefs)=@_;
   my ($folderfile, $folderdb)=get_folderpath_folderdb($user, $folder);
   return 0 if ( ! -f $folderfile );	# check existence of folderfile

   my $filtercheckfile=dotpath('filter.check');
   my $filterbookfile=dotpath('filter.book');

   my (@filterfiles, @filterrules, @allmessageids);
   my %filtered_to_folder=();
   my %repeatlists=();
   my $folderhandle=do { local *FH };
   my (%FDB, %FILTERDB);

   my $forced_recheck=0;
   my $ioerr=0;

   ## check .filter_check ##
   if ( -f $filtercheckfile ) {
      my $checkinfo;
      open (FILTERCHECK, $filtercheckfile ) or return -1;
      $checkinfo=<FILTERCHECK>;
      close (FILTERCHECK);
      if ($checkinfo eq ow::tool::metainfo($folderfile)) {
         return 0;
      }
   } else {
      $forced_recheck=1;	# new filterrule, so do filtering on all msg
   }

   ## get @filterrules ##
   push(@filterfiles, $filterbookfile)              if ($config{'enable_userfilter'} && -f $filterbookfile);
   push(@filterfiles, $config{'global_filterbook'}) if ($config{'global_filterbook'} ne "" && -f $config{'global_filterbook'});
   foreach my $filterfile (@filterfiles) {
      open (FILTER, $filterfile) or next;
      while (<FILTER>) {
         chomp($_);
         if (/^\d+\@\@\@/) { # add valid rule only
            my @rule=split(/\@\@\@/);
            next if (!$rule[$_ENABLE]||
                     $rule[$_OP] ne 'copy' && $rule[$_OP] ne 'move' && $rule[$_OP] ne 'delete');

            $rule[$_DESTINATION]=safefoldername($rule[$_DESTINATION]);
            if ($rule[$_DESTINATION] eq 'DELETE') {
               next if ($rule[$_OP] eq 'copy');			# copy to DELETE is meaningless
               $rule[$_OP]='delete' if ($rule[$_OP] eq 'move');	# move to DELETE is 'delete'
            }

            # precompile text into regex for speed
            if ( (${$r_prefs}{'regexmatch'} || $filterfile eq $config{'global_filterbook'}) &&
                 ow::tool::is_regex($rule[$_TEXT]) ) {	# do regex compare?
               $rule[$_REGEX_TEXT]=qr/$rule[$_TEXT]/im;
            } else {
               $rule[$_REGEX_TEXT]=qr/\Q$rule[$_TEXT]\E/im;
            }
            push(@filterrules, \@rule);
         }
      }
      close (FILTER);
   }
   return 0 if ($#filterrules<0);	# empty filterfiles?
   # sort rules by priority, the smaller the top
   @filterrules=sort { 
                     ${$a}[$_PRIORITY] <=> ${$b}[$_PRIORITY] or
                     $op_order{${$a}[$_OP]} <=>  $op_order{${$b}[$_OP]} or
                     (${$a}[$_DESTINATION] ne 'INBOX') <=> (${$b}[$_DESTINATION] ne 'INBOX') or
                     (${$a}[$_DESTINATION] eq 'DELETE') <=> (${$b}[$_DESTINATION] eq 'DELETE') or
                     (${$a}[$_DESTINATION] eq 'mail-trash') <=> (${$b}[$_DESTINATION] eq 'mail-trash') or
                     $ruletype_order{${$a}[$_RULETYPE]} <=>  $ruletype_order{${$b}[$_RULETYPE]}
                     } @filterrules;
   ow::dbm::open(\%FILTERDB, $filterbookfile, LOCK_EX) or return -3;

   if (! ow::filelock::lock($folderfile, LOCK_EX|LOCK_NB)) {
      ow::dbm::close(\%FILTERDB, $filterbookfile);
      return -4;
   }
   if (update_folderindex($folderfile, $folderdb)<0) {
      ow::dbm::close(\%FILTERDB, $filterbookfile);
      ow::filelock::lock($folderfile, LOCK_UN);
      writelog("db error - Couldn't update index db $folderdb");
      writehistory("db error - Couldn't update index db $folderdb");
      return -4;
   }

   open ($folderhandle, "+<$folderfile") or return -5;
   if (!ow::dbm::open(\%FDB, $folderdb, LOCK_EX)) {
      ow::dbm::close(\%FILTERDB, $filterbookfile);
      close($folderhandle);
      ow::filelock::lock($folderfile, LOCK_UN);
      return -6;
   }

   @allmessageids=get_messageids_sorted_by_offset_db(\%FDB);
   foreach my $messageid (@allmessageids) {
      next if ($messageid=~/^DUP\d+\-/);        # skip duplicated msg in src folder
      my @attr = string2msgattr($FDB{$messageid});
      my ($header, $decoded_header, $currmessage, $body)=("", "", "", "");
      my (%msg, $r_attachments, $r_smtprelays, $r_connectfrom, $r_byas);
      my ($is_body_decoded, $is_attachments_decoded)=(0, 0);
      my ($reserved_in_folder, $to_be_moved)=(0, 0);

      # if flag V not found, this msg has not been filtered before (Verify)
      if ($attr[$_STATUS] !~ /V/i || $forced_recheck) {

         # 0. read && check msg header
         if ($attr[$_OFFSET]>=0 && $attr[$_HEADERSIZE]>0 && 
             $attr[$_SIZE]>$attr[$_HEADERSIZE]) {
            seek($folderhandle, $attr[$_OFFSET], 0);
            read($folderhandle, $header, $attr[$_HEADERSIZE]);
         }
         if ($header!~/^From /) {
            ow::dbm::close(\%FILTERDB, $filterbookfile);

            close($folderhandle);
            $FDB{'METAINFO'}='ERR';
            ow::dbm::close(\%FDB, $folderdb);

            # forced reindex since metainfo = ERR
            update_folderindex($folderfile, $folderdb);

            ow::filelock::lock($folderfile, LOCK_UN);
            writelog("db warning - msg $messageid in $folderfile index inconsistence - ".__FILE__.':'.__LINE__);
            writehistory("db warning - msg $messageid in $folderfile index inconsistence - ".__FILE__.':'.__LINE__);
            return(-10);
         }

         if ($attr[$_STATUS] !~ /V/i) {
            $attr[$_STATUS].="V";
            $FDB{$messageid}=msgattr2string(@attr);
         }

         # 1. collect matched rules
         foreach my $r_rule (@filterrules) {
            my $ruletype=${$r_rule}[$_RULETYPE];
            my $is_matched=0;

            if ( $ruletype eq 'from' || $ruletype eq 'to' || $ruletype eq 'subject') {
               if ($decoded_header eq "") {
                  $decoded_header=ow::mime::decode_mimewords($header);
                  $decoded_header=~s/\s*\n\s+/ /sg; # concate folding lines
               }
               if (!defined($msg{from})) { # this is defined after parse_header is called
                  ow::mailparse::parse_header(\$decoded_header, \%msg);
               }
               if ($msg{$ruletype}=~/${$r_rule}[$_REGEX_TEXT]/
                   xor ${$r_rule}[$_INCLUDE] eq 'exclude') {
                   $is_matched=1;
               }

            } elsif ( $ruletype eq 'header' ) {
               if ($decoded_header eq "") {
                  $decoded_header=ow::mime::decode_mimewords($header);
                  $decoded_header=~s/\s*\n\s+/ /sg; # concate folding lines
               }
               if ($decoded_header=~/${$r_rule}[$_REGEX_TEXT]/
                   xor ${$r_rule}[$_INCLUDE] eq 'exclude') {
                   $is_matched=1;
               }

            } elsif ( $ruletype eq 'smtprelay' ) {
               if (!defined($r_smtprelays) ) {
                  ($r_smtprelays, $r_connectfrom, $r_byas)=ow::mailparse::get_smtprelays_connectfrom_byas_from_header($header);
               }
               my $smtprelays;
               foreach my $relay (@{$r_smtprelays}) {
                  $smtprelays.="$relay, ${$r_connectfrom}{$relay}, ${$r_byas}{$relay}, ";
               }
               if ($smtprelays=~/${$r_rule}[$_REGEX_TEXT]/
                   xor ${$r_rule}[$_INCLUDE] eq 'exclude') {
                   $is_matched=1;
               }

            } elsif ( $ruletype eq 'textcontent' ) {
               if ($currmessage eq "") {
                  seek($folderhandle, $attr[$_OFFSET], 0);
                  read($folderhandle, $currmessage, $attr[$_SIZE]);
               }
               if (!defined(@{$r_attachments})) {
                  ($header, $body, $r_attachments)=ow::mailparse::parse_rfc822block(\$currmessage);
               }

               # check body text
               if (!$is_body_decoded) {
                  if ( $attr[$_CONTENT_TYPE] =~ /^text/i ||
                       $attr[$_CONTENT_TYPE] eq 'N/A' ) {	# for text/plain. text/html
                     if ( $header =~ /content-transfer-encoding:\s+quoted-printable/i) {
                        $body = decode_qp($body);
                     } elsif ($header =~ /content-transfer-encoding:\s+base64/i) {
                        $body = decode_base64($body);
                     } elsif ($header =~ /content-transfer-encoding:\s+x-uuencode/i) {
                        $body = ow::mime::uudecode($body);
                     }
                  }
                  $is_body_decoded=1;
               }
               if ( $attr[$_CONTENT_TYPE] =~ /^text/i ||
                    $attr[$_CONTENT_TYPE] eq 'N/A' ) {		# for text/plain. text/html
                  if ($body=~/${$r_rule}[$_REGEX_TEXT]/
                      xor ${$r_rule}[$_INCLUDE] eq 'exclude') {
                      $is_matched=1;
                  }
               }

               # check attachments text if body text not match
               if (!$is_matched) {
                  if (!$is_attachments_decoded) {
                     foreach my $r_attachment (@{$r_attachments}) {
                        if ( ${$r_attachment}{'content-type'} =~ /^text/i ||
                             ${$r_attachment}{'content-type'} eq "N/A" ) { # read all for text/plain. text/html
                           if ( ${$r_attachment}{'content-transfer-encoding'} =~ /^quoted-printable/i ) {
                              ${${$r_attachment}{r_content}} = decode_qp( ${${$r_attachment}{r_content}});
                           } elsif ( ${$r_attachment}{'content-transfer-encoding'} =~ /^base64/i ) {
                              ${${$r_attachment}{r_content}} = decode_base64( ${${$r_attachment}{r_content}});
                           } elsif ( ${$r_attachment}{'content-transfer-encoding'} =~ /^x-uuencode/i ) {
                              ${${$r_attachment}{r_content}} = ow::mime::uudecode( ${${$r_attachment}{r_content}});
                           }
                        }
                     }
                     $is_attachments_decoded=1;
                  }
                  foreach my $r_attachment (@{$r_attachments}) {
                     if ( ${$r_attachment}{'content-type'} =~ /^text/i ||
                          ${$r_attachment}{'content-type'} eq "N/A" ) { # read all for text/plain. text/html
                        if (${${$r_attachment}{r_content}}=~/${$r_rule}[$_REGEX_TEXT]/
                            xor ${$r_rule}[$_INCLUDE] eq 'exclude') {
                           $is_matched=1;
                           last;	# leave attachments loop of this msg
                        }
                     }
                  }
               } # end !$is_matched bodytext

            } elsif ($ruletype eq 'attfilename') {
               if ($currmessage eq "") {
                  seek($folderhandle, $attr[$_OFFSET], 0);
                  read($folderhandle, $currmessage, $attr[$_SIZE]);
               }
               if (!defined(@{$r_attachments})) {
                  ($header, $body, $r_attachments)=ow::mailparse::parse_rfc822block(\$currmessage);
               }
               # check attachments
               foreach my $r_attachment (@{$r_attachments}) {
                  if (${$r_attachment}{filename}=~/${$r_rule}[$_REGEX_TEXT]/
                      xor ${$r_rule}[$_INCLUDE] eq 'exclude') {
                     $is_matched=1;
                     last;	# leave attachments loop of this msg
                  }
               }
            }

            if ($is_matched) {
               # cp msg to other folder and set reserved_in_folder or to_be_moved flag
               my $rulestr=join('@@@', @{$r_rule}[$_RULETYPE, $_INCLUDE, $_TEXT, $_DESTINATION]);
               my $appended;

               my ($matchcount, $matchdate)=split(":", $FILTERDB{$rulestr});
               $matchcount++; $matchdate=ow::datetime::gmtime2dateserial();
               $FILTERDB{$rulestr}="$matchcount:$matchdate";

               if ( ${$r_rule}[$_OP] eq 'move' || ${$r_rule}[$_OP] eq 'copy') {
                  if (${$r_rule}[$_DESTINATION] eq $folder) {
                     $reserved_in_folder=1;
                  } else {
                     $appended=append_message_to_folder($messageid, $folderhandle,
         				\@attr, \$currmessage, $user, ${$r_rule}[$_DESTINATION]);
                  }
               }
               if (!$reserved_in_folder &&
                   (${$r_rule}[$_OP] eq 'delete' || ${$r_rule}[$_OP] eq 'move')) {
                  if ($appended>=0) {
                     $to_be_moved=1;
                     $filtered_to_folder{'_ALL'}++;
                     $filtered_to_folder{${$r_rule}[$_DESTINATION]}++;
                  } else {
                     $ioerr++;
                     last;
                  }
               }
               last if (${$r_rule}[$_OP] eq 'move' || ${$r_rule}[$_OP] eq 'delete');
            }
         } # end @filterrules

         # 2. check matched smartrules if msg is not going to be moved
         if ($config{'enable_smartfilter'} && !$reserved_in_folder && !$to_be_moved) {
            # bypass smart filters for good messages
            if ($config{'smartfilter_bypass_goodmessage'} &&
                !$reserved_in_folder && !$to_be_moved ) {
               if ( ($header=~/^X\-Mailer: Open WebMail/m && $header=~/^X\-OriginatingIP: /m) ||
                    ($header=~/^In\-Reply\-To: /m && $header=~/^References: /m) ) {
                  $reserved_in_folder=1;
               }
            }

            # since if any smartrule matches, other smartrule would be skipped
            # so we use only one variable to record the matched smartrule.
            my $matchedsmartrule;	

            # filter message with bad format from if msg is not moved or deleted
            if (${$r_prefs}{'filter_badaddrformat'} &&
                !$reserved_in_folder && !$to_be_moved ) {
               my $badformat=0;
               my $fromaddr=(ow::tool::email2nameaddr($attr[$_FROM]))[1]; $fromaddr=~s/\@.*$//;
               if ($fromaddr=~/[^\d\w\-\._]/ ||
                   $fromaddr=~/^\d/ ||
                   ($fromaddr=~/\d/ && $fromaddr=~/\./) ) {
                  $badformat=1;
               }
               my ($toname, $toaddr)=ow::tool::email2nameaddr($attr[$_TO]);
               if ($toname=~/undisclosed-recipients/i && $toaddr=~/\@/) {
                  $badformat=1;
               }
               if ($badformat) {
                  $matchedsmartrule='filter_badaddrformat';
                  $to_be_moved=1;
               }
            } # end of checking bad format from

            # filter message whose from: is different than the envelope email address
            if ( ${$r_prefs}{'filter_fakedfrom'} &&
                !$reserved_in_folder && !$to_be_moved ) {
               my $is_software_generated=0;	# skip faked from check for msg generated by some software
               if ( ($header=~/^\QX-Delivery-Agent: TMDA\E/m &&
                     $header=~/^\QPrecedence: bulk\E/m &&
                     $messageid=~/\Q.TMDA@\E/) ||	# TMDA
                    ($header=~/^\QManaged-by: RT\E/m &&
                     $header=~/^\QRT-Ticket: \E/m &&
                     $header=~/^\QPrecedence: bulk\E/m) ) {	# Request Tracker
                  $is_software_generated=1;
               }
               if (!$is_software_generated) {
                  my $envelopefrom='';
                  $envelopefrom=$1 if ($header=~/\(envelope\-from (\S+).*?\)/s);
                  $envelopefrom=$1 if ($envelopefrom eq "" && $header=~/^From (\S+)/);

                  # compare user and domain independently
                  my ($hdr_user, $hdr_domain)=split(/\@/, (ow::tool::email2nameaddr($attr[$_FROM]))[1]);
                  my ($env_user, $env_domain)=split(/\@/, $envelopefrom);
                  if ($hdr_user ne $env_user ||
                      ($hdr_domain ne "" && $env_domain ne "" &&
                       $hdr_domain!~/\Q$env_domain\E/i &&
                       $env_domain!~/\Q$hdr_domain\E/i) ) {
                     $matchedsmartrule='filter_fakedfrom';
                     $to_be_moved=1;
                  }
               }
            } # end of checking fakedfrom

            # filter message from smtprelay with faked name if msg is not moved or deleted
            if ( ${$r_prefs}{'filter_fakedsmtp'} &&
                !$reserved_in_folder && !$to_be_moved ) {
               if (!defined($r_smtprelays) ) {
                  ($r_smtprelays, $r_connectfrom, $r_byas)=ow::mailparse::get_smtprelays_connectfrom_byas_from_header($header);
               }
               # move msg to trash if the first relay has invalid/faked hostname
               if ( defined(${$r_smtprelays}[0]) ) {
                  my $relay=${$r_smtprelays}[0];
                  my $connectfrom=${$r_connectfrom}{$relay};
                  my $byas=${$r_byas}{$relay};
                  my $is_private=0; $is_private=1 if ($connectfrom =~ /(?:\[10|\[172\.[1-3][0-9]|\[192\.168|\[127\.0)\./);

                  my $is_valid;
                  my @compare=( namecompare($connectfrom, $relay),
                                namecompare($byas, $relay),
                                namecompare($connectfrom, $byas) );
                  if ( $compare[0]>0 || $compare[1]>0 || $compare[2]>0 ||
                      ($compare[0]==0 && $compare[1]==0 && $compare[2]==0) ) {
                     $is_valid=1;
                  } else {	# all <=0 and at least one < 0
                     $is_valid=0;
                  }

                  # the last relay is the mail server
                  my $dstdomain=domain(${$r_smtprelays}[$#{$r_smtprelays}]);
                  if ($connectfrom !~ /\Q$dstdomain\E/i &&
                      !$is_private && !$is_valid ) {
                     $matchedsmartrule='filter_fakedsmtp';
                     $to_be_moved=1;
                  }
               }
            } # end of checking fakedsmtp

            # filter message with faked exe contenttype if msg is not moved or deleted
            if (${$r_prefs}{'filter_fakedexecontenttype'} &&
                !$reserved_in_folder && !$to_be_moved ) {
               if ($currmessage eq "") {
                  seek($folderhandle, $attr[$_OFFSET], 0);
                  read($folderhandle, $currmessage, $attr[$_SIZE]);
               }
               if (!defined(@{$r_attachments})) {
                  ($header, $body, $r_attachments)=ow::mailparse::parse_rfc822block(\$currmessage);
               }

               # check executable attachment and contenttype
               my $att_matched;
               foreach my $r_attachment (@{$r_attachments}) {
                  if ( ${$r_attachment}{filename} =~ /\.(?:exe|com|bat|pif|lnk|scr)$/i &&
                       ${$r_attachment}{'content-type'} !~ /application\/octet\-stream/i &&
                       ${$r_attachment}{'content-type'} !~ /application\/x\-msdownload/i ) {
                     $matchedsmartrule='filter_fakedexecontenttype';
                     $to_be_moved=1;
                     last;	# leave attachments loop of this msg
                  }
               }
            } # end of checking fakedexecontenttype

            if ($matchedsmartrule ne "") {
               my ($matchcount, $matchdate)=split(":", $FILTERDB{$matchedsmartrule});
               $matchcount++; $matchdate=ow::datetime::gmtime2dateserial();
               $FILTERDB{$matchedsmartrule}="$matchcount:$matchdate";

               my $appended=append_message_to_folder($messageid, $folderhandle,
      			\@attr, \$currmessage, $user, 'mail-trash');
               if ($appended>=0) {
                  $filtered_to_folder{'_ALL'}++;
                  $filtered_to_folder{'mail-trash'}++;
               } else {
                  $to_be_moved=0;
                  $ioerr++;
                  last;
               }
            }
         } # end of if enable_smartfilter

         # 3. mark to be moved message as zap
         if ($to_be_moved) {
            $attr[$_STATUS].='Z' if ($attr[$_STATUS]!~/Z/i);
            $FDB{$messageid}=msgattr2string(@attr);
            $FDB{'ZAPSIZE'}+=$attr[$_SIZE];
         }
      } # end of msg verify

      if (${$r_prefs}{'filter_repeatlimit'}>0 && !$to_be_moved && !$reserved_in_folder) {
         # store msgid with same '$from:$subject' to same array
         my $msgstr="$attr[$_FROM]:$attr[$_SUBJECT]";
         if (! defined($repeatlists{$msgstr}) ) {
            $repeatlists{$msgstr}=[];	# reference of null array
         }
         push (@{$repeatlists{$msgstr}}, $messageid);
      }

   } # end of messageids loop

   close ($folderhandle);
   $FDB{'METAINFO'}=ow::tool::metainfo($folderfile);
   ow::dbm::close(\%FDB, $folderdb);

   # remove repeated msgs with repeated count > ${$r_prefs}{'filter_repeatlimit'}
   my (@repeatedids, $fromsubject, $r_ids);
   while ( ($fromsubject,$r_ids) = each %repeatlists) {
      push(@repeatedids, @{$r_ids}) if ($#{$r_ids}>=${$r_prefs}{'filter_repeatlimit'});
   }
   if ($#repeatedids>=0) {
      my ($trashfile, $trashdb)=get_folderpath_folderdb($user, 'mail-trash');
      if (! ow::filelock::lock($trashfile, LOCK_EX|LOCK_NB) ) {
         ow::dbm::close(\%FILTERDB, $filterbookfile);
         ow::filelock::lock($folderfile, LOCK_UN);
         return -7;
      }
      my $moved=operate_message_with_ids('move', \@repeatedids, $folderfile, $folderdb,
      							$trashfile, $trashdb);
      ow::filelock::lock($trashfile, LOCK_UN);

      if ($moved>0) {
         my ($matchcount, $matchdate)=split(":", $FILTERDB{"filter_repeatlimit"});
         $matchcount+=$moved; $matchdate=ow::datetime::gmtime2dateserial();
         $FILTERDB{"filter_repeatlimit"}="$matchcount:$matchdate";
         $filtered_to_folder{'_ALL'}+=$moved;
         $filtered_to_folder{'mail-trash'}+=$moved;
      } elsif ($moved<0) {
         $ioerr++;
      }
   }

   ow::dbm::close(\%FILTERDB, $filterbookfile);

   my $zapped=folder_zapmessages($folderfile, $folderdb);
   # zap again if data error or index inconsistence
   $zapped=folder_zapmessages($folderfile, $folderdb) if ($zapped==-9||$zapped==-10);
   $ioerr++ if ($zapped<0);

   ow::filelock::lock($folderfile, LOCK_UN);

   return -9 if ($ioerr>0);

   open (FILTERCHECK, ">$filtercheckfile" ) or  return -8;
   print FILTERCHECK ow::tool::metainfo($folderfile);
   close (FILTERCHECK);

   return($filtered_to_folder{'_ALL'}, \%filtered_to_folder);
}

sub append_message_to_folder {
   my ($messageid, $source, $r_attr, $r_currmessage, $user, $destination)=@_;
   my %FDB2;
   my ($dstfile, $dstdb)=get_folderpath_folderdb($user, $destination);
   my $ioerr=0;
   my @attr=@{$r_attr};

   if ($$r_currmessage eq "") {
      seek($source, $attr[$_OFFSET], 0);
      read($source, $$r_currmessage, $attr[$_SIZE]);
   }

   if ($$r_currmessage !~ m/^From /) { # msg format error
      return -1;
   }

   if (! -f $dstfile) {
      open (DEST, ">$dstfile") or return -2;
      close (DEST);
   }

   ow::filelock::lock($dstfile, LOCK_EX|LOCK_NB) or return -3;

   if (update_folderindex($dstfile, $dstdb)<0) {
      ow::filelock::lock($dstfile, LOCK_UN);
      writelog("db error - Couldn't update index db $dstdb");
      writehistory("db error - Couldn't update index db $dstdb");
      return -4;
   }

   ow::dbm::open(\%FDB2, $dstdb, LOCK_EX) or return -5;

   if (!defined($FDB2{$messageid}) ) {	# append only if not found in dstfile
      if (! open(DEST, "+<$dstfile")) {
         ow::dbm::close(\%FDB2, $dstdb);
         return -6;
      }
      $attr[$_OFFSET]=(stat(DEST))[7];
      seek(DEST, $attr[$_OFFSET], 0);
      $attr[$_SIZE]=length(${$r_currmessage});
      print DEST ${$r_currmessage} or $ioerr++;
      close (DEST);

      if (!$ioerr) {
         $FDB2{$messageid}=msgattr2string(@attr);
         $FDB2{'NEWMESSAGES'}++ if ($attr[$_STATUS]!~/r/i);
         $FDB2{'INTERNALMESSAGES'}++ if (is_internal_subject($attr[$_SUBJECT]));
         $FDB2{'ALLMESSAGES'}++;
         $FDB2{'METAINFO'}=ow::tool::metainfo($dstfile);
      }
   }
   ow::dbm::close(\%FDB2, $dstdb);

   ow::filelock::lock($dstfile, LOCK_UN);
   return 0;
}

# hostname compare for loosely equal
# >0 match, <0 unmatch, ==0 unknow
sub namecompare {
   my ($a, $b)=@_;

   # no compare if any one is empty
   return  0 if ($a =~/^\s*$/ || $b =~/^\s*$/ );

   # chk if both names are invalid
   if ($a =~ /[\d\w\-_]+[\.\@][\d\w\-_]+/) {
      if ($b =~ /[\d\w\-_]+[\.\@][\d\w\-_]+/ ) {	# a,b are long
         # chk if any names conatains another
         return 1 if ($a=~/\Q$b\E/i || $b=~/\Q$a\E/i);
         # chk if both names belongs to same domain
         $a=domain( (split(/\s/, $a))[0] );
         $b=domain( (split(/\s/, $b))[0] );
         return 1 if ($a eq $b && $a =~/[\d\w\-_]+\.[\d\w\-_]+/);
      } else {						# a long, b short
         $b=(split(/\s/, $b))[0];
         return 1 if ($a=~/^\Q$b\E\./i || $a=~/\@\Q$b\E/ );
      }
   } else {
      if ($b =~ /[\d\w\-_]+[\.\@][\d\w\-_]+/ ) {	# a short, b long
         $a=(split(/\s/, $a))[0];
         return 1 if ($b=~/^\Q$a\E\./i || $b=~/\@\Q$a\E/ );
      } else {						# a, b are short
         return 0 if ($a eq $b);
      }
   }
   return -1;
}

# return domain part of a FQDN
sub domain {
   my @h=split(/\./, $_[0]);
   shift (@h);
   return(join(".", @h));
}
########## END FILTERMESSAGE #####################################

########## FILTERMESSAGE2 ########################################
# a wrapper of routine filtermessage()
sub filtermessage2 {
   my ($user, $folder, $r_prefs)=@_;
   my ($filtered, $r_filtered)=filtermessage($user, $folder, $r_prefs);
   if ($filtered==-10) {	# filter again if db inconsistence
      ($filtered, $r_filtered)=filtermessage($user, $folder, $r_prefs);
   }

   if ($filtered > 0) {
      my $dststr;
      foreach my $destination (sort keys %{$r_filtered}) {
         next if ($destination eq '_ALL' || $destination eq 'INBOX');
         $dststr .= ", " if ($dststr ne "");
         $dststr .= $destination;
         $dststr .= "(${$r_filtered}{$destination})" if (${$r_filtered}{$destination} ne $filtered);
      }
      writelog("filter message - filter $filtered msgs from INBOX to $dststr");
      writehistory("filter message - filter $filtered msgs from INBOX to $dststr");
   } elsif ($filtered == -1 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_open'} filter.check!");
   } elsif ($filtered == -2 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_open'} filter.book!");
   } elsif ($filtered == -3 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_lock'} filter.book db!");
   } elsif ($filtered == -4 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_lock'} INBOX!");
   } elsif ($filtered == -5 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_open'} INBOX!");
   } elsif ($filtered == -6 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_lock'} index db of INBOX!");
   } elsif ($filtered == -7 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_lock'} mail-trash!");
   } elsif ($filtered == -8 ) {
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_open'} filter.check!");
   } elsif ($filtered == -9 ) {
      openwebmailerror(__FILE__, __LINE__, "mailfilter I/O error!");
   }
   return($filtered, $r_filtered);
}
########## END FILTERMESSAGE2 ####################################

1;
