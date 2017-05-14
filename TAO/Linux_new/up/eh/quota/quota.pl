package ow::quota;
use strict;
#
# quota.pl - parent package of all quota modules
#
require "modules/suid.pl";
require "modules/tool.pl";

sub load {
   my $quotafile=$_[0];
   my $ow_cgidir=$INC[$#INC];	# get cgi-bin/openwebmail path from @INC
   ow::tool::loadmodule("ow::quota::internal",
                        "$ow_cgidir/quota", $quotafile,
                        "get_usage_limit");
}

sub get_usage_limit {
   my ($origruid, $origeuid, $origegid)=ow::suid::set_uid_to_root();
   my @results=ow::quota::internal::get_usage_limit(@_);
   ow::suid::restore_uid_from_root($origruid, $origeuid, $origegid);
   return @results;
}

1;
