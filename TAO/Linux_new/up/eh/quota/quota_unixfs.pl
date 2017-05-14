package ow::quota_unixfs;
use strict;
#
# quota_unixfs.pl - calc user quota by unix filesystem quota
#
# 2003/04/06 tung.AT.turtle.ee.ncku.edu.tw
#

# This module gets the user quotausage and quotalimit from the quota
# database of the unix filesystem (quotalimit = softlimit),
# it is recommended if your openwebmail user is standard unix user.

########## No configuration required from here ###################

use Quota;

#  0 : ok
# -1 : parameter format error
# -2 : quota system/internal error
sub get_usage_limit {
   my ($r_config, $user, $homedir, $uptodate)=@_;
   return(-1, "$homedir doesn't exist") if (!-d $homedir);
   my $uid=getpwnam($user);
   return (-1, "No such user") if (!defined($uid));

   # this routine doesn't care about the $uptodate flag
   # the usage/limit is directly from unixfs quota db everytime.

   $homedir .= "/." if ($homedir !~ m#/.$#);	# for automounter fs
   my $dev = Quota::getqcarg($homedir);
   return(-2, "Error in finding device for $homedir") if(!$dev);

   Quota::sync($dev);
   #if (Quota::sync($dev) && ($!!=1)) {	# ignore EPERM
   #   return(-2, Quota::strerr);	# quota not enabled mostly
   #}

   my ($bc,$bs) = (Quota::query($dev, $uid))[0,1];
   if(!defined($bc)) { ; # not enough privilege to query
      # $!==3,  no quota for this user, return no limit instead of error
      return(0, "", 0, 0) if ($!==3);
      return(-2, Quota::strerr);
   }

   return(0, "", $bc, $bs);	# block count, block soft limit
}

1;
