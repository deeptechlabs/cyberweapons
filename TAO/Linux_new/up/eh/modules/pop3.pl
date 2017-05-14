package ow::pop3;
use strict;
#
# pop3.pl - fetch mail messages from pop3 server
#
# 2003/05/25 tung.AT.turtle.ee.ncku.edu.tw
# 2002/03/19 eddie.AT.turtle.ee.ncku.edu.tw
#

use Fcntl qw(:DEFAULT :flock);
use IO::Socket;
use MIME::Base64;
require "modules/dbm.pl";
require "modules/filelock.pl";
require "modules/tool.pl";
require "modules/datetime.pl";

sub fetchmail {
   my ($pop3host, $pop3port, $pop3ssl, 
       $pop3user, $pop3passwd, $pop3del, 
       $uidldb, $spoolfile, 
       $deliver_use_GMT, $daylightsaving, $loginonly)=@_;

   my $is_ssl_supported=ow::tool::has_module('IO/Socket/SSL.pm');
   my $socket;

   $pop3host=ow::tool::untaint($pop3host);	# untaint for connection creation
   $pop3port=ow::tool::untaint($pop3port);
   $spoolfile=ow::tool::untaint($spoolfile);	# untaint for file creation
   $uidldb=ow::tool::untaint($uidldb);		# untaint for uidldb creation

   eval {
      local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
      alarm 30;
      if ($pop3ssl && $is_ssl_supported) {
         $socket=new IO::Socket::SSL (Proto=>'tcp',
                                           PeerAddr=>$pop3host,
                                           PeerPort=>$pop3port);
      } else {
         $pop3port=110 if ($pop3ssl && !$is_ssl_supported);
         $socket=new IO::Socket::INET(Proto=>'tcp',
                                           PeerAddr=>$pop3host,
                                           PeerPort=>$pop3port);
      }
      alarm 0;
   };
   return(-11, "connection timeout") if ($@); 		# timeout
   return(-12, "connection refused") if (!$socket);	# connect refused

   eval {
      local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
      alarm 10;
      $socket->autoflush(1);
      $_=<$socket>;
      alarm 0;
   };
   return(-13, "server not ready") if ($@ || /^\-/);	# timeout or server not ready

   # try if server supports auth login(base64 encoding) first
   print $socket "auth login\r\n";
   $_=<$socket>;
   if (/^\+/) {
      print $socket &encode_base64($pop3user);
      $_=<$socket>;
      if (/^\-/) {		# username error
         close($socket);
         return(-14, "user name error");
      }
      print $socket &encode_base64($pop3passwd);
      $_=<$socket>;
   }

   if (! /^\+/) {	# not supporting auth login or auth login failed
      print $socket "user $pop3user\r\n";
      $_=<$socket>;
      if (/^\-/) {		# username error
         close($socket);
         return(-14, "user name error");
      }
      print $socket "pass $pop3passwd\r\n";
      $_=<$socket>;
      if (/^\-/) {		# password error
         close($socket);
         return(-15, "password error");
      }
   }

   if ($loginonly) {
      print $socket "quit\r\n";
      $_=<$socket>;	# wait +OK from server
      close($socket);
      return 0;
   }


   my ($mailcount, $retr_total)=(0, 0);
   my ($uidl_support, $uidl_field, $uidl, $last)=(0, 2, -1, 0);
   my (%UIDLDB, %uidldb);

   print $socket "stat\r\n";
   $_=<$socket>;
   if (/^\-/) {		# stat error
      close($socket);
      return(-16, "pop3 'stat' error");
   }

   $mailcount=(split(/\s/))[1];
   if ($mailcount == 0) {		# no message
      print $socket "quit\r\n";
      $_=<$socket>;	# wait +OK from server
      close($socket);
      return 0;
   }

   # use 'uidl' to find the msg being retrieved last time
   print $socket "uidl 1\r\n";
   $_ = <$socket>;

   if (/^\-/) {	# pop3d not support uidl, try last command
      # use 'last' to find the msg being retrieved last time
      print $socket "last\r\n";
      $_ = <$socket>; s/^\s+//;
      if (/^\+/) { # server does support last
         $last=(split(/\s/))[1];		# +OK N
         if ($last eq $mailcount) {
            print $socket "quit\r\n";
            $_=<$socket>;	# wait +OK from server
            close($socket);
            return 0;
         }
      } else {			# both uidl and last not supported
         if (!$pop3del) {	# err if user want to reserve mail on pop3 server
            return(-17, "UIDL and LAST not supported");
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
         close($socket);
         return(-1, "uidldb lock error");
      }
   }

   # retr messages
   for (my $i=$last+1; $i<=$mailcount; $i++) {
      my ($msgfrom, $msgdate)=("", "");
      my @msgcontent=();

      if ($uidl_support) {
         print $socket "uidl $i\r\n";
         $_ = <$socket>;
         $uidl=(split(/\s/))[$uidl_field];
         if ( defined($UIDLDB{$uidl}) ) {		# already fetched before
            $uidldb{$uidl}=1; next;
         }
      }

      print $socket "retr ".$i."\r\n";
      while (<$socket>) {	# use loop to filter out verbose output
         if ( /^\+/ ) {
            next;
         } elsif (/^\-/) {
            if ($uidl_support) {
               @UIDLDB{keys %uidldb}=values %uidldb if ($retr_total>0);
               ow::dbm::close(\%UIDLDB, $uidldb);
            }
            close($socket);
            return(-18, "pop3 RETR error");
         } else {
            last;
         }
      }

      # first line of message
      if ($_!~/^From /) {	# keep 1st line if it is not msg delimiter
         s/\s+$//;
         $msgdate=$1 if ( /^Date:\s+(.*)$/i);
         push(@msgcontent, $_);
      }

      #####  read else lines of message
      while ( <$socket>) {
         s/\s+$//;
         last if ($_ eq "." );	#end and exit while
         push(@msgcontent, $_);
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
      if ($deliver_use_GMT) {
         $msgdate=ow::datetime::dateserial2delimiter($dateserial, "", $daylightsaving);
      } else {
         $msgdate=ow::datetime::dateserial2delimiter($dateserial, ow::datetime::gettimeoffset(), $daylightsaving);
      }

      # append message to mail folder
      my $append=0;
      if (! -f $spoolfile) {
         open(F, ">>$spoolfile"); close(F);
      }
      if (ow::filelock::lock($spoolfile, LOCK_EX)) {
         if (open(F,"+<$spoolfile")) {
            my $err=0;
            my $origsize=(stat(F))[7];
            seek(F, $origsize, 0);	# seek to file end
            print F "From $msgfrom $msgdate\n" or $err++;
            foreach (@msgcontent) {
               last if ($err>0);
               print F $_, "\n" or $err++;
            }
            if (!$err && $#msgcontent>=0 &&
                $msgcontent[$#msgcontent] ne '') { # msg not ended with empty line
               print F "\n" or $err++;
            }
            if ($err) {
               truncate(F, $origsize);
            } else {
               $append=1;
            }
            close(F);
         }
         ow::filelock::lock($spoolfile, LOCK_UN);
      }
      if (!$append) {
         if ($uidl_support) {
            @UIDLDB{keys %uidldb}=values %uidldb if ($retr_total>0);
            ow::dbm::close(\%UIDLDB, $uidldb);
         }
         close($socket);
         return(-3, "spool write error");
      }

      if ($pop3del) {
         print $socket "dele $i\r\n";
         $_=<$socket>;
         $uidldb{$uidl}=1 if ($uidl_support && !/^\+/);
      } else {
         $uidldb{$uidl}=1 if ($uidl_support);
      }
      $retr_total++;
   }

   if ($uidl_support) {
      %UIDLDB=%uidldb if ($retr_total>0);
      ow::dbm::close(\%UIDLDB, $uidldb);
   }

   print $socket "quit\r\n";
   $_=<$socket>;	# wait +OK from server
   close($socket);
   return(-19, "pop3 QUIT did not succeed, mail may not have been deleted") if ($pop3del && !/^+/);
   return($retr_total);	# return number of fetched mail
}

1;
