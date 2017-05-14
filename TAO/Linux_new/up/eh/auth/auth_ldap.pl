package ow::auth_ldap;
use strict;
#
# auth_ldap.pl - authenticate user with LDAP
#
# 2002/04/10 Kelson Vibber, kelson.AT.speed.net (fixed check_userpassword)
# 2002/01/27 Ivan Cerrato, pengus.AT.libero.it
#

########## No configuration required from here ###################

use Net::LDAP;
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_ldap.conf', 'etc/auth_ldap.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
} else {
   die "Config file auth_ldap.conf not found!";
}

my $ldapHost = $conf{'ldaphost'};
my $ou  = "ou=$conf{'ou'}";
my $cn  = "cn=$conf{'cn'}";
my $dc1 = "dc=$conf{'dc1'}";
my $dc2 = "dc=$conf{'dc2'}";
my $pwd = $conf{'password'};

my $ldapBase = "$dc1, $dc2";

########## end init ##############################################

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   return(-2, 'User is null') if ($user eq '');

   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");
   $ldap->bind (dn=>"$cn, $dc1, $dc2", password =>$pwd) or  return(-3, "LDAP error $@");

   my $list = $ldap->search (
                            base    => $ldapBase,
                            filter  => "(&(objectClass=posixAccount)(uid=$user))",
                            attrs   => ['uidNumber','gidNumber','gecos','homeDirectory']
                            ) or return(-3, "LDAP error $@");
   undef($ldap); # disconnect

   if ($list->count eq 0) {
      return (-4, "User $user doesn't exist");
   } else {
      my $entry = $list->entry(0);
      my ($uid, $gid, $gecos, $homedir);
      $gecos = $entry->get_value("gecos");
      $uid = $entry->get_value("uidNumber");
      $gid = $entry->get_value("gidNumber");
      $homedir = $entry->get_value("homeDirectory");
      return(0, '', $gecos, $uid, $gid, $homedir);
   }
}


#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist {      # only used by openwebmail-tool.pl -a
   my $r_config=$_[0];

   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");
   $ldap->bind (dn=>"$cn, $dc1, $dc2", password =>$pwd) or  return(-3, "LDAP error $@");

   my $list = $ldap->search (
                            base    => $ldapBase,
                            filter  => "(&(objectClass=posixAccount))",
                            attrs   => ['uid']
                            ) or return(-3, "LDAP error $@");
   undef($ldap); # disconnect

   my $num = $list->count;
   my @userlist=();
   for (my $i = 0; $i < $num; $i++) {
      my $entry = $list->entry($i);
      push (@userlist, $entry->get_value("uid"));
   }

   return (0, '', @userlist);
}


#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user, $password)=@_;
   return (-2, "User or password is null") if ($user eq '' || $password eq '');

   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");
   # $ldap->bind (dn=>"$cn, $dc1, $dc2", password =>$pwd) or  return(-3, "LDAP error $@");

   # Attempt to bind using the username and password provided.
   # (For a secure LDAP config, only auth should be allowed for
   # any user other than self and rootdn.)
   my $mesg = $ldap->bind (
                          dn       => "uid=$user, $ou, $dc1, $dc2",
                          password => $password
                          );

   undef($ldap);
   return (-4, 'username/password incorrect') if( $mesg->code != 0 );

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
   return (-2, "Password too short") if (length($newpassword)<${$r_config}{'passwd_minlen'});

   my ($ret, $errmsg)=check_userpassword($r_config, $user, $oldpassword);
   return($ret, $errmsg) if ($ret!=0);

   my @salt_chars = ('a'..'z','A'..'Z','0'..'9');
   my $salt = $salt_chars[rand(62)] . $salt_chars[rand(62)];
   my $encrypted = "{CRYPT}" . crypt($newpassword, $salt);

   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");
   $ldap->bind (dn=>"$cn, $dc1, $dc2", password =>$pwd) or  return(-3, "LDAP error $@");

   my $mesg = $ldap->modify (
                            dn      => "uid=$user, ou=People, $dc1, $dc2",
                            replace => {'userPassword'=>$encrypted}
                            );
   undef($ldap);

   return (0, '');
}

1;
