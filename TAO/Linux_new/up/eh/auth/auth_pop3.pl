package ow::auth_pop3;
use strict;
#
# auth_pop3.pl - authenticate user with POP3 server
#
# 2002/03/08 tung.AT.turtle.ee.ncku.edu.tw
#

########## No configuration required from here ###################

use IO::Socket;
use MIME::Base64;
require "modules/tool.pl";
require "modules/pop3.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_pop3.conf', 'etc/auth_pop3.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
}

my $effectiveuser= $conf{'effectiveuser'} || 'nobody';

########## end init ##############################################

# routines get_userinfo() and get_userlist still depend on /etc/passwd
# you may have to write your own routines if your user are not form /etc/passwd

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   return(-2, 'User is null') if ($user eq '');

   my ($uid, $gid, $realname, $homedir) = (getpwnam($effectiveuser))[2,3,6,7];
   return(-4, "User $user doesn't exist") if ($uid eq "");

   # get other gid for this effective in /etc/group
   while (my @gr=getgrent()) {
      $gid.=' '.$gr[2] if ($gr[3]=~/\b$effectiveuser\b/ && $gid!~/\b$gr[2]\b/);
   }
   # use first field only
   $realname=(split(/,/, $realname))[0];
   # guess real homedir under sun's automounter
   $homedir="/export$homedir" if (-d "/export$homedir");

   return(0, '', $realname, $uid, $gid, $homedir);
}


#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist {	# only used by openwebmail-tool.pl -a
   my $r_config=$_[0];
   return(-1, "userlist() is not available in auth_pop3.pl");
}


#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user, $password)=@_;
   return (-2, "User or password is null") if ($user eq '' || $password eq '');

   my ($ret, $errmsg)=ow::pop3::fetchmail(${$r_config}{'authpop3_server'},
                                          ${$r_config}{'authpop3_port'},
                                          ${$r_config}{'authpop3_usessl'},
                                          $user, $password, 0,
                                          '', '',
                                          1, 'auto', 1);
   if ($ret==-11) {
      return (-3, "pop3 server ${$r_config}{'authpop3_server'}:${$r_config}{'authpop3_port'} timeout");
   } elsif ($ret==-12) {
      return (-3, "pop3 server ${$r_config}{'authpop3_server'}:${$r_config}{'authpop3_port'} connection refused");
   } elsif ($ret==-13) {
      return(-3, "pop3 server ${$r_config}{'authpop3_server'}:${$r_config}{'authpop3_port'} not ready");
   } elsif ($ret==-14) {
      return(-2, "pop3 server ${$r_config}{'authpop3_server'}:${$r_config}{'authpop3_port'} username error");
   } elsif ($ret==-15) {
      return(-4, "pop3 server ${$r_config}{'authpop3_server'}:${$r_config}{'authpop3_port'} password error");
   }
   return (0, '');
}


#  0 : ok
# -1 : function not supported
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub change_userpassword {
   my ($r_config, $user, $oldpassword, $newpassword)=@_;
   return (-2, "User or password is null") if ($user eq '' || $oldpassword eq '' || $newpassword eq '');
   return (-1, "change_password() is not available in authpop3.pl");
}

1;
