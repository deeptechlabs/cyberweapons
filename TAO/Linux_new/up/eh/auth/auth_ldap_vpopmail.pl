package ow::auth_ldap_vpopmail;
use strict;
#
# auth_ldap_vpopmail.pl - authenticate user with LDAP configured for vpopmail
#
# 2004/05/30 Andrea Siviero, sivix.AT.users.sourceforge.net (modified from auth_ldap.pl)
# 2002/04/10 Kelson Vibber, kelson.AT.speed.net (fixed check_userpassword)
# 2002/01/27 Ivan Cerrato, pengus.AT.libero.it
#

########## No configuration required from here ###################

use Net::LDAP;
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_ldap_vpopmail.conf', 'etc/auth_ldap_vpopmail.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
} else {
   die "Config file auth_ldap.conf not found!";
}

my $ldapHost = $conf{'ldaphost'};
my $ou  = "ou=$conf{'ou'}";
my $cn  = "cn=$conf{'cn'}";
my $o = "o=$conf{'o'}";

my $ldapBase = "$o";
my $effectiveuser= $conf{'effective'} || 'nobody';

########## end init ##############################################

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   return(-2, 'User is null') if (!$user);
   my ($user, $domain) =split(/@/,$user);

   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");
   $ldap->bind (dn=>"", password =>"") or  return(-3, "LDAP error $@");

   my $list = $ldap->search (
                            base    => $ldapBase,
                            filter  => "(&(objectClass=*)(uid=$user))",
                            attrs   => ['uid','gid','mailMessageStore']
                            ) or return(-3, "LDAP error $@");
   undef($ldap); # disconnect

   if ($list->count eq 0) {
      return (-4, "User $user doesn't exist");
   } else {
      my $entry = $list->entry(0);
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
}

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user, $password)=@_;
   return (-2, "User or password is null") if (!$user||!$password);

   my ($user, $domain) =split(/@/,$user);
   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");

   # Attempt to bind using the username and password provided.
   # (For a secure LDAP config, only auth should be allowed for
   # any user other than self and rootdn.)
   $ldap->bind (dn=>"", password =>"") or  return(-3, "LDAP error $@");

   my $list = $ldap->search (
                            base    => $ldapBase,
                            filter  => "(&(objectClass=*)(uid=$user))",
                            attrs   => ['userPassword']
                            ) or return(-3, "LDAP error $@");

   my $entry = $list->entry(0);
   my $vpwd = $entry->get_value("userPassword");
   my $passwd_hash =""; 
   if ($vpwd =~ s/({MD5}|{crypt})//i) {
      $passwd_hash = $password;
   } else {
      $passwd_hash = crypt($password,$vpwd);
   }

   my $mesg = $ldap->bind (dn => "uid=$user, $ou, $o", password => $passwd_hash);
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
   return (-2, "User or password is null") if (!$user||!$oldpassword||!$newpassword);
   return (-2, "Password too short") if (length($newpassword)<${$r_config}{'passwd_minlen'});

   my ($ret, $errmsg)=check_userpassword($r_config, $user, $oldpassword);
   return($ret, $errmsg) if ($ret!=0);

   my ($user, $domain) =split(/@/,$user);
   my @salt_chars = ('a'..'z','A'..'Z','0'..'9');
   my $salt = $salt_chars[rand(62)] . $salt_chars[rand(62)];
   my $encrypted = "{crypt}".crypt($newpassword, $salt);

   my $ldap = Net::LDAP->new($ldapHost) or return(-3, "LDAP error $@");
   $ldap->bind (dn=>"", password =>"") or  return(-3, "LDAP error $@");

   my $list = $ldap->search (
                            base    => $ldapBase,
                            filter  => "(&(objectClass=*)(uid=$user))",
                            attrs   => ['userPassword']
                            ) or return(-3, "LDAP error $@");

   my $entry = $list->entry(0);
   my $vpwd = $entry->get_value("userPassword");
   my $passwd_hash ="";
   if ($vpwd =~ s/({MD5}|{crypt})//i) {
      $passwd_hash = $oldpassword;
   } else {
      $passwd_hash = crypt($oldpassword,$vpwd);
   }

   my $mesg = $ldap->bind (dn => "uid=$user, $ou, $o", password => $passwd_hash);
   $mesg = $ldap->modify (
                         dn      => "uid=$user, $ou, $o",
                         replace => {'userPassword'=>$encrypted}
                         );
   undef($ldap);
   return (-4, 'username/password incorrect') if( $mesg->code != 0 );

   return (0, '');
}

1;
