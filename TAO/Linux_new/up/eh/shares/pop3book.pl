#
# pop3book.pl - read/write pop3book
#
use strict;
use Fcntl qw(:DEFAULT :flock);
use MIME::Base64;

sub readpop3book {
   my ($pop3book, $r_accounts) = @_;
   my $i=0;

   %{$r_accounts}=();

   if ( -f "$pop3book" ) {
      ow::filelock::lock($pop3book, LOCK_SH) or return -1;
      open (POP3BOOK,"$pop3book") or return -1;
      while (<POP3BOOK>) {
      	 chomp($_);
         my @a=split(/\@\@\@/, $_);
         my ($pop3host,$pop3port,$pop3ssl, $pop3user,$pop3passwd, $pop3del, $enable)=@a;
         if ($#a==5) {	# for backward comparibility
            ($pop3host,$pop3port, $pop3user,$pop3passwd, $pop3del, $enable)=@a;
            $pop3ssl=0;
         }
         $pop3passwd=decode_base64($pop3passwd);
         $pop3passwd=$pop3passwd^substr($pop3host,5,length($pop3passwd));
         ${$r_accounts}{"$pop3host:$pop3port\@\@\@$pop3user"} = "$pop3host\@\@\@$pop3port\@\@\@$pop3ssl\@\@\@$pop3user\@\@\@$pop3passwd\@\@\@$pop3del\@\@\@$enable";
         $i++;
      }
      close (POP3BOOK);
      ow::filelock::lock($pop3book, LOCK_UN);
   }
   return($i);
}

sub writepop3book {
   my ($pop3book, $r_accounts) = @_;

   $pop3book=ow::tool::untaint($pop3book);
   if (! -f "$pop3book" ) {
      open (POP3BOOK,">$pop3book") or return -1;
      close(POP3BOOK);
   }

   ow::filelock::lock($pop3book, LOCK_EX) or return -1;
   open (POP3BOOK,">$pop3book") or return -1;
   foreach (values %{$r_accounts}) {
     chomp($_);
     my ($pop3host,$pop3port,$pop3ssl, $pop3user,$pop3passwd, $pop3del, $enable)=split(/\@\@\@/, $_);
     # not secure, but better than plaintext
     $pop3passwd=$pop3passwd ^ substr($pop3host,5,length($pop3passwd));
     $pop3passwd=encode_base64($pop3passwd, '');
     print POP3BOOK "$pop3host\@\@\@$pop3port\@\@\@$pop3ssl\@\@\@$pop3user\@\@\@$pop3passwd\@\@\@$pop3del\@\@\@$enable\n";
   }
   close (POP3BOOK);
   ow::filelock::lock($pop3book, LOCK_UN);

   return 0;
}

1;
