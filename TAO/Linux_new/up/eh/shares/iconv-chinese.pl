#
# iconv-chinese.pl - charset coversion for big5<->gb
#
# The table and code were adopted from Encode::HanConvert written by
# Autrijus Tang <autrijus@autrijus.org>
#
# Since chinese conversion in iconv() is incomplete, we use this instead
#
use strict;
use vars qw(%config);
use Fcntl qw(:DEFAULT :flock);

sub mkdb_b2g {
   my %B2G;
   my $b2gdb=ow::tool::untaint("$config{'ow_etcdir'}/b2g");

   ow::dbm::open(\%B2G, $b2gdb, LOCK_EX, 0644) or return -1;
   open (T, "$config{'b2g_map'}");
   $_=<T>; $_=<T>;
   while (<T>) {
      /^(..)\s(..)/;
      $B2G{$1}=$2;
   }
   close(T);
   ow::dbm::close(\%B2G, $b2gdb);

   return 0;
}

sub mkdb_g2b {
   my %G2B;
   my $g2bdb=ow::tool::untaint("$config{'ow_etcdir'}/g2b");

   ow::dbm::open(\%G2B, $g2bdb, LOCK_EX, 0644) or return -1;
   open (T, "$config{'g2b_map'}");
   $_=<T>; $_=<T>;
   while (<T>) {
      /^(..)\s(..)/;
      $G2B{$1}=$2;
   }
   close(T);
   ow::dbm::close(\%G2B, $g2bdb);

   return 0;
}

# big5:       hi A1-F9,       lo 40-7E A1-FE (big5-1984, big5-eten, big5-cp950, big5-unicode)
# big5-hkscs: hi 88-F9,       lo 40-7E A1-FE
# big5E:      hi 81-8E A1-F9, lo 40-7E A1-FE
# from http://i18n.linux.org.tw/li18nux/big5/doc/big5-intro.txt
sub b2g { # use range of big5
   my $str = $_[0];
   my $b2gdb=ow::tool::untaint("$config{'ow_etcdir'}/b2g");

   if (ow::dbm::exist($b2gdb)) {
      my %B2G;
      ow::dbm::open(\%B2G, $b2gdb, LOCK_SH);
      $str =~ s/([\xA1-\xF9][\x40-\x7E\xA1-\xFE])/$B2G{$1}/eg;
      ow::dbm::close(\%B2G, $b2gdb);
   }
   return $str;
}

# gb2312-1980: hi A1-F7, lo A1-FE, range hi*lo
# gb12345    : hi A1-F9, lo A1-FE, range hi*lo
# gbk        : hi 81-FE, lo 40-7E 80-FE, range hi*lo
# from http://www.haiyan.com/steelk/navigator/ref/gbindex1.htm
sub g2b { # use range of gb2312
   my $str = $_[0];
   my $g2bdb=ow::tool::untaint("$config{'ow_etcdir'}/g2b");

   if (ow::dbm::exist($g2bdb)) {
      my %G2B;
      ow::dbm::open(\%G2B, $g2bdb, LOCK_SH);
      $str =~ s/([\xA1-\xF9][\xA1-\xFE])/$G2B{$1}/eg;
      ow::dbm::close(\%G2B, $g2bdb);
   }
   return $str;
}

1;
