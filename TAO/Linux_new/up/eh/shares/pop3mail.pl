#
# pop3mail.pl - pop3 mail retrieval routines
#
# 2003/05/25 tung.AT.turtle.ee.ncku.edu.tw
# 2002/03/19 eddie.AT.turtle.ee.ncku.edu.tw
#

use strict;
use Fcntl qw(:DEFAULT :flock);
use IO::Socket;
use MIME::Base64;

# extern vars, defined in caller openwebmail-xxx.pl
use vars qw(%config %prefs);

sub retrpop3mail {
   my ($pop3host, $pop3port, $pop3user, $pop3passwd, $pop3del, $uidldb, $spoolfile)=@_;
   my $remote_sock;

   $pop3host=ow::tool::untaint($pop3host);	# untaint for connection creation
   $pop3port=ow::tool::untaint($pop3port);
   $spoolfile=ow::tool::untaint($spoolfile);	# untaint for file creation
   $uidldb=ow::tool::untaint($uidldb);		# untaint for uidldb creation

   eval {
      local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
      alarm 30;
      $remote_sock=new IO::Socket::INET(   Proto=>'tcp',
                                           PeerAddr=>$pop3host,
                                           PeerPort=>$pop3port);
      alarm 0;
   };
   return(-11, "connect error") if ($@);		# eval error, it means timeout
   return(-11, "connect error") if (!$remote_sock);	# connect error

   $remote_sock->autoflush(1);
   $_=<$remote_sock>;
   return(-12, "server not ready") if (/^\-/);		# server not ready

   # try if server supports auth login(base64 encoding) first
   print $remote_sock "auth login\r\n";
   $_=<$remote_sock>;
   if (/^\+/) {
      print $remote_sock &encode_base64($pop3user);
      $_=<$remote_sock>;
      if (/^\-/) {		# username error
         close($remote_sock);
         return(-13, "user name error");
      }
      print $remote_sock &encode_base64($pop3passwd);
      $_=<$remote_sock>;
   }

   if (! /^\+/) {	# not supporting auth login or auth login failed
      print $remote_sock "user $pop3user\r\n";
      $_=<$remote_sock>;
      if (/^\-/) {		# username error
         close($remote_sock);
         return(-13, "user name error");
      }
      print $remote_sock "pass $pop3passwd\r\n";
      $_=<$remote_sock>;
      if (/^\-/) {		# password error
         close($remote_sock);
         return(-14, "password error");
      }
   }
   print $remote_sock "stat\r\n";
   $_=<$remote_sock>;
   if (/^\-/) {		# stat error
      close($remote_sock);
      return(-15, "pop3 'stat' error");
   }


   my ($mailcount, $retr_total)=(0, 0);
   my ($uidl_support, $uidl_field, $uidl, $last)=(0, 2, -1, 0);
   my (%UIDLDB, %uidldb);

   $mailcount=(split(/\s/))[1];
   if ($mailcount == 0) {		# no message
      print $remote_sock "quit\r\n";
      close($remote_sock);
      return 0;
   }

   # use 'uidl' to find the msg being retrieved last time
   print $remote_sock "uidl 1\r\n";
   $_ = <$remote_sock>;

   if (/^\-/) {	# pop3d not support uidl, try last command
      # use 'last' to find the msg being retrieved last time
      print $remote_sock "last\r\n";
      $_ = <$remote_sock>; s/^\s+//;
      if (/^\+/) { # server does support last
         $last=(split(/\s/))[1];		# +OK N
         if ($last eq $mailcount) {
            print $remote_sock "quit\r\n";
            close($remote_sock);
            return 0;
         }
      } else {			# both uidl and last not supported
         if (!$pop3del) {	# err if user want to reserve mail on pop3 server
            return(-16, "UIDL and LAST not supported");
         } else {		# fetch all messages and del them from server
            $last=0;
         }
      }

   } else {	# pop3d does support uidl
      $uidl_support=1;
      if (/^\+/) {
         $uidl_field=2;
      } else {
         $uidl_field=1;	# some broken pop3d return uidl without leading +
      }
      if (!ow::dbm::open(\%UIDLDB, $uidldb, LOCK_EX)) {
         close($remote_sock);
         return(-1, "uidldb lock error");
      }
   }

   # retr messages
   for (my $i=$last+1; $i<=$mailcount; $i++) {
      my ($msgcontent, $msgfrom, $msgdate)=("", "", "");

      if ($uidl_support) {
         print $remote_sock "uidl $i\r\n";
         $_ = <$remote_sock>;
         $uidl=(split(/\s/))[$uidl_field];
         if ( defined($UIDLDB{$uidl}) ) {		# already fetched before
            $uidldb{$uidl}=1; next;
         }
      }

      print $remote_sock "retr ".$i."\r\n";
      while (<$remote_sock>) {	# use loop to filter out verbose output
         if ( /^\+/ ) {
            next;
         } elsif (/^\-/) {
            if ($uidl_support) {
               @UIDLDB{keys %uidldb}=values %uidldb if ($retr_total>0);
               ow::dbm::close(\%UIDLDB, $uidldb);
            }
            close($remote_sock);
            return(-17, "pop3 'retr' error");
         } else {
            last;
         }
      }

      # first line of message
      if ( /^From / ) {
         $msgcontent = "";	#drop 1st line if containing msg delimiter
      } else {
         s/\s+$//;
         $msgcontent = "$_\n";
         $msgdate=$1 if ( /^Date:\s+(.*)$/i);
      }

      #####  read else lines of message
      while ( <$remote_sock>) {
         s/\s+$//;
         last if ($_ eq "." );	#end and exit while
         $msgcontent .= "$_\n";
         # get $msgfrom, $msgdate to compose the mail delimiter 'From xxxx' line
         if ( /\(envelope\-from \s*(.+?)\s*\)/i && $msgfrom eq "" ) {
            $msgfrom = $1;
         } elsif ( /^from:\s+(.+)$/i && $msgfrom eq "" ) {
            $_ = $1;
            if ($_=~ /^"?(.+?)"?\s*<(.*)>$/ ) {
               $_ = $2;
            } elsif ($_=~ /<?(.*@.*)>?\s+\((.+?)\)/ ) {
               $_ = $1;
            } elsif ($_=~ /<\s*(.+@.+)\s*>/ ) {
               $_ = $1;
            } else {
               $_=~ s/\s*(.+@.+)\s*/$1/;
            }
            $msgfrom = $_;

         } elsif ( /^Date:\s+(.*)$/i && $msgdate eq "" ) {
            $msgdate=$1;
         }
      }

      my $dateserial=ow::datetime::datefield2dateserial($msgdate);
      my $dateserial_gm=ow::datetime::gmtime2dateserial();
      if ($dateserial eq "" ||
          ow::datetime::dateserial2gmtime($dateserial) -
          ow::datetime::dateserial2gmtime($dateserial_gm) > 86400 ) {
         $dateserial=$dateserial_gm;	# use current time if msg time is newer than now for 1 day
      }
      if ($config{'deliver_use_GMT'}) {
         $msgdate=ow::datetime::dateserial2delimiter($dateserial, "", $prefs{'daylightsaving'});
      } else {
         $msgdate=ow::datetime::dateserial2delimiter($dateserial, ow::datetime::gettimeoffset(), $prefs{'daylightsaving'});
      }

      # append message to mail folder
      my $append=0;;
      if (! -f $spoolfile) {
         open(F, ">>$spoolfile"); close(F);
      }
      if (ow::filelock::lock($spoolfile, LOCK_EX)) {
         if (open(F,"+<$spoolfile")) {
            seek(F, 0, 2);	# seek to file end
            print F "From $msgfrom $msgdate\n$msgcontent\n";
            close(F);
            $append=1;
         }
         ow::filelock::lock($spoolfile, LOCK_UN);
      }
      if (!$append) {
         if ($uidl_support) {
            @UIDLDB{keys %uidldb}=values %uidldb if ($retr_total>0);
            ow::dbm::close(\%UIDLDB, $uidldb);
         }
         close($remote_sock);
         return(-3, "spool write error");
      }

      if ($pop3del) {
         print $remote_sock "dele $i\r\n";
         $_=<$remote_sock>;
         $uidldb{$uidl}=1 if ($uidl_support && !/^\+/);
      } else {
         $uidldb{$uidl}=1 if ($uidl_support);
      }
      $retr_total++;
   }

   print $remote_sock "quit\r\n";
   close($remote_sock);

   if ($uidl_support) {
      %UIDLDB=%uidldb if ($retr_total>0);
      ow::dbm::close(\%UIDLDB, $uidldb);
   }

   # return number of fetched mail
   return($retr_total);
}

1;
