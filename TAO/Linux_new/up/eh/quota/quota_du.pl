package ow::quota_du;
use strict;
#
# quota_du.pl - calc user quota by /usr/bin/du
#
# 2003/04/06 tung.AT.turtle.ee.ncku.edu.tw
#

# This module gets the user quotausage by running the 'du' program,
# it is recommended if your openwebmail user is not real unix user.
# To reduce the overhead introduced by running 'du', the quotausage info
# will be cached in $duinfo_db temporarily for $duinfo_lifetime seconds
#
# You may set $duinfo_lifetime to 0 to disable the cache
#

my $duinfo_db="/var/tmp/duinfo";
my $duinfo_lifetime=60;

########## No configuration required from here ###################

use Fcntl qw(:DEFAULT :flock);
require "modules/dbm.pl";
require "modules/filelock.pl";
require "modules/execute.pl";

#  0 : ok
# -1 : parameter format error
# -2 : quota system/internal error
sub get_usage_limit {
   my ($r_config, $user, $homedir, $uptodate)=@_;
   return(-1, "$homedir doesn't exist") if (!-d $homedir);

   my (%Q, $timestamp, $usage);
   my $now=time();

   if (!ow::dbm::exist("$duinfo_db") && $duinfo_lifetime>0) {
      my $mailgid=getgrnam('mail');
      ow::dbm::open(\%Q, $duinfo_db, LOCK_EX, 0664) or
         return(-2, "Quota db create error, $ow::dbm::errmsg");
      ow::dbm::close(\%Q, $duinfo_db);
      ow::dbm::chown($>, $mailgid, $duinfo_db) or
         return(-2, "Quota db chown error, $ow::dbm::errmsg");
   }

   if (!$uptodate && $duinfo_lifetime>0) {
      ow::dbm::open (\%Q, $duinfo_db, LOCK_EX, 0664) or
         return(-2, "Quota db open error, $ow::dbm::errmsg");
      ($timestamp, $usage)=split(/\@\@\@/, $Q{"$user\@\@\@$homedir"}) if (defined($Q{"$user\@\@\@$homedir"}));
      ow::dbm::close(\%Q, $duinfo_db);

      if ($now-$timestamp>=0 && $now-$timestamp<=$duinfo_lifetime) {
         return(0, "", $usage, -1);
      }
   }

   my ($stdout, $stderr, $exit, $sig)=ow::execute::execute('/usr/bin/du', '-sk', $homedir);
   return(-2, "exec /usr/bin/du error, $stderr") if ($exit||$sig);
   $usage=(split(/\s/, $stdout))[0];
   return(0, "", $usage, -1) if ($duinfo_lifetime==0);

   ow::dbm::open (\%Q, $duinfo_db, LOCK_EX, 0664) or
      return(-2, "Quota db open error, $ow::dbm::errmsg");
   $Q{"$user\@\@\@$homedir"}="$now\@\@\@$usage";
   ow::dbm::close(\%Q, $duinfo_db);

   return(0, "", $usage, -1);
}

1;
