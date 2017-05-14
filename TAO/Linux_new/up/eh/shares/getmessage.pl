#
# getmessage.pl - get and parse a message
#
use strict;
use Fcntl qw(:DEFAULT :flock);

use vars qw(%config %lang_err);

sub getmessage {
   my ($user, $folder, $messageid, $mode) = @_;
   my ($folderfile, $folderdb)=get_folderpath_folderdb($user, $folder);
   my $folderhandle=do { local *FH };
   my $r_messageblock;
   my %message = ();

   ow::filelock::lock($folderfile, LOCK_SH|LOCK_NB) or
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_locksh'} $folderfile!");
   if (update_folderindex($folderfile, $folderdb)<0) {
      ow::filelock::lock($folderfile, LOCK_UN);
      openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_updatedb'} $folderdb");
   }
   open($folderhandle, "$folderfile");
   $r_messageblock=get_message_block($messageid, $folderdb, $folderhandle);
   close($folderhandle);
   ow::filelock::lock($folderfile, LOCK_UN);

   if (${$r_messageblock} eq "") {	# msgid not found
      writelog("db warning - msg $messageid in $folderfile index missing");
      writehistory("db warning - msg $messageid in $folderfile index missing");
      return \%message;

   } elsif (${$r_messageblock}!~/^From / ) {	# db index inconsistance
      writelog("db warning - msg $messageid in $folderfile index inconsistence - ".__FILE__.':'.__LINE__);
      writehistory("db warning - msg $messageid in $folderfile index inconsistence - ".__FILE__.':'.__LINE__);

      my %FDB;
      ow::dbm::open(\%FDB, $folderdb, LOCK_EX) or
         openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_lock'} $folderdb");
      $FDB{'METAINFO'}="ERR";
      ow::dbm::close(\%FDB, $folderdb);

      ow::filelock::lock($folderfile, LOCK_SH|LOCK_NB) or
         openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_locksh'} $folderfile!");

      # forced reindex since metainfo = ERR
      if (update_folderindex($folderfile, $folderdb)<0) {
         ow::filelock::lock($folderfile, LOCK_UN);
         openwebmailerror(__FILE__, __LINE__, "$lang_err{'couldnt_updatedb'} $folderdb");
      }

      open($folderhandle, "$folderfile");
      $r_messageblock=get_message_block($messageid, $folderdb, $folderhandle);
      close($folderhandle);

      ow::filelock::lock($folderfile, LOCK_UN);

      return \%message if (${$r_messageblock} eq "" );
   }

   # member: header, body, attachment
   #         return-path from to cc bcc reply-to date subject status
   #         message-id content-type encoding in-reply-to references priority 
   foreach (qw(from to date subject content-type)) { $message{$_}= 'N/A' }
   foreach (qw(return-path cc reply-to status in-reply-to references charset priority)) { $message{$_}='' }

   # $r_attachment is a reference to attachment array!
   if ($mode eq "all") {
      ($message{header}, $message{body}, $message{attachment})
		=ow::mailparse::parse_rfc822block($r_messageblock, "0", "all");
   } else {
      ($message{header}, $message{body}, $message{attachment})
		=ow::mailparse::parse_rfc822block($r_messageblock, "0", "");
   }
   return {} if ( $message{header} eq "" ); 	# return empty hash if no header found

   ow::mailparse::parse_header(\$message{header}, \%message);
   $message{status} .= $message{'x-status'} if (defined($message{'x-status'}));

   # recover incomplete header attr for msgs resent from mailing list, tricky!
   if ($message{'content-type'} eq 'N/A') {
      if (defined(${$message{attachment}}[0])) {	# msg has attachment(s)
         $message{'content-type'}=qq|multipart/mixed;|;
      } elsif ($message{body}=~/^\n*([A-Za-z0-9+]{50,}\n?)+/s) {
         $message{'content-type'}=qq|text/plain|;
         $message{'content-transfer-encoding'}='base64';
      } elsif ($message{body}=~/(=[\dA-F][\dA-F]){3}/i) {
         $message{'content-type'}=qq|text/plain|;
         $message{'content-transfer-encoding'}='quoted-printable';
      }
   }

   my($r_smtprelays, $r_connectfrom, $r_byas)
      =ow::mailparse::get_smtprelays_connectfrom_byas_from_header($message{header});
   foreach (@{$r_smtprelays}) {
      next if ($_!~/[\w\d\-_]+\.[\w\d\-_]+/);
      $message{smtprelay} = $_;
      foreach my $localdomain (@{$config{'domainnames'}}) {
         if ($message{smtprelay}=~$localdomain) { 
            $message{smtprelay}=''; last;
         }
      }
      last if ($message{smtprelay} ne '');
   }
   $message{smtprelay}=~s/[\[\]]//g;	# remove [] around ip addr in mailheader
					# since $message{smtprelay} may be put into filterrule
                        		# and we don't want [] be treat as regular expression

   foreach (qw(from reply-to to cc bcc subject)) {
      $message{$_}=ow::mime::decode_mimewords($message{$_}) if ($message{$_} ne 'N/A');
   }
   $message{status}.= "I" if ($message{priority}=~/urgent/i);
   $message{status} =~ s/\s//g;
   if ($message{'content-type'}=~/charset="?([^\s"';]*)"?\s?/i) {
      $message{charset}=$1;
   } elsif (defined(@{$message{attachment}})) {
      my @att=@{$message{attachment}};
      foreach my $i (0 .. $#att) {
         if (defined(${$att[$i]}{charset}) && ${$att[$i]}{charset} ne '') {
            $message{charset}=${$att[$i]}{charset};
            last;
         }
      }
   }

   return \%message;
}

1;
