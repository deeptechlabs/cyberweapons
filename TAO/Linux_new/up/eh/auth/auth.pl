package ow::auth;
use strict;
#
# auth.pl - parent package of all auth modules
#
require "modules/suid.pl";
require "modules/tool.pl";

sub load {
   my $authfile=$_[0];
   my $ow_cgidir=$INC[$#INC];	# get cgi-bin/openwebmail path from @INC
   ow::tool::loadmodule("ow::auth::internal",
                        "$ow_cgidir/auth", $authfile,
                        "get_userinfo",
                        "get_userlist",
                        "check_userpassword",
                        "change_userpassword");
}

sub get_userlist {
   my ($origruid, $origeuid, $origegid)=ow::suid::set_uid_to_root();
   my @results=ow::auth::internal::get_userlist(@_);
   ow::suid::restore_uid_from_root($origruid, $origeuid, $origegid);
   return @results;
}

sub get_userinfo {
   my ($origruid, $origeuid, $origegid)=ow::suid::set_uid_to_root();
   my @results=ow::auth::internal::get_userinfo(@_);
   ow::suid::restore_uid_from_root($origruid, $origeuid, $origegid);
   return @results;
}

sub check_userpassword {
   my ($origruid, $origeuid, $origegid)=ow::suid::set_uid_to_root();
   my @results=ow::auth::internal::check_userpassword(@_);
   ow::suid::restore_uid_from_root($origruid, $origeuid, $origegid);
   return @results;
}

sub change_userpassword {
   my ($origruid, $origeuid, $origegid)=ow::suid::set_uid_to_root();
   my @results=ow::auth::internal::change_userpassword(@_);
   ow::suid::restore_uid_from_root($origruid, $origeuid, $origegid);
   return @results;
}

1;
