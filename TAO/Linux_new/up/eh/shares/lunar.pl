#
# lunar.pl - convert solar calendar to chinese lunar calendar
#
# 2002/11/15 tung.AT.turtle.ee.ncku.edu.tw
#
use strict;
use vars qw(%config);
use Fcntl qw(:DEFAULT :flock);

sub mkdb_lunar {
   my %LUNAR;
   my $lunardb=ow::tool::untaint("$config{'ow_etcdir'}/lunar");

   ow::dbm::open(\%LUNAR, $lunardb, LOCK_EX, 0644) or return -1;
   open (T, "$config{'lunar_map'}");
   $_=<T>; $_=<T>;
   while (<T>) {
      my @a=split(/,/, $_);
      $LUNAR{$a[0]}="$a[1],$a[2]";
   }
   close(T);
   ow::dbm::close(\%LUNAR, $lunardb);

   return 0;
}

sub solar2lunar {
   my ($year, $month, $day)=@_;
   my ($lunar_year, $lunar_monthday);

   my $lunardb=ow::tool::untaint("$config{'ow_etcdir'}/lunar");
   if (ow::dbm::exist($lunardb)) {
      my %LUNAR;
      my $date=sprintf("%04d%02d%02d", $year, $month, $day);
      ow::dbm::open(\%LUNAR, $lunardb, LOCK_SH);
      ($lunar_year, $lunar_monthday)=split(/,/, $LUNAR{$date});
      ow::dbm::close(\%LUNAR, $lunardb);
   }
   return($lunar_year, $lunar_monthday);
}

1;
