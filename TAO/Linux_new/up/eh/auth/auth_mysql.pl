package ow::auth_mysql;
use strict;
#
# auth_mysql.pl - authenticate user with DBD::MySQL and Digest::MD5
#
# 2003/12/20 Yuan-Chung Hsiao, ychsiao.AT.linux.mis.stu.edu.tw (fix MD5 crypto & change password function)
# 2003/07/15 far, far.bbs.AT.abpe.org (add MD5 crypto)
# 2002/03/07 Alan Sung, AlanSung.AT.dragon2.net
#

########## No configuration required from here ###################

use DBI;
use Digest::MD5;
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_mysql.conf', 'etc/auth_mysql.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
} else {
   die "Config file auth_mysql.conf not found";
}

my $SQLHost = $conf{'sqlhost'};
my $sqlusr = $conf{'sqluser'};
my $sqlpwd = $conf{'sqlpwd'};

my $auth_db = $conf{'auth_db'} || 'auth_table';
my $auth_table = $conf{'auth_table'} || 'auth_user';
my $field_username = $conf{'field_username'} || 'username';
my $field_password = $conf{'field_password'} || 'password';
my $field_realname = $conf{'field_realname'} || 'realname';
my $field_uid = $conf{'field_uid'} || 'u_id';
my $field_gid = $conf{'field_gid'} || 'g_id';
my $field_home = $conf{'field_home'} || 'home';

my $pass_type = $conf{'pass_type'} || 'cleartxt';

########## end init ##############################################

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   return(-2, 'User is null') if ($user eq '');

   my $dbh = DBI->connect("dbi:mysql:$auth_db;host=$SQLHost", $sqlusr,$sqlpwd)
      or return(-3, "Cannot connect to db server: ".$DBI::errstr);
   my $queryStr =qq|select $field_uid, $field_gid, $field_realname, $field_home from $auth_table where strcmp($field_username , '$user')=0|;
   my $sth = $dbh->prepare($queryStr)
      or return(-3, "Can't prepare SQL statement: ".$dbh->errstr());
   $sth->execute
      or return(-3, "Can't execute SQL statement: ".$sth->errstr());

   if ($sth->rows eq 0) {
      $sth->finish;
      $dbh->disconnect or return(-3, "Disconnection failed: ".$DBI::errstr);
      return (-4, "User $user doesn't exist");
   } else {
      if (my $result = $sth->fetchrow_hashref()) {
         $sth->finish;
         $dbh->disconnect or return(-3, "Disconnection failed: ".$DBI::errstr);;
         return(0, '', $result->{$field_realname}, $result->{$field_uid}, $result->{$field_gid}, $result->{$field_home});
      } else {
         return(-3, "Can't fetch SQL result: ".$sth->errstr());
      }
   }
}


#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist {      # only used by openwebmail-tool.pl -a
   my $r_config=$_[0];

   my $dbh = DBI->connect("dbi:mysql:$auth_db;host=$SQLHost", $sqlusr,$sqlpwd)
      or return(-3, "Cannot connect to db server: ".$DBI::errstr);
   my $queryStr = qq|select $field_username from $auth_table|;
   my $sth = $dbh->prepare($queryStr)
      or return(-3, "Can't prepare SQL statement: ".$dbh->errstr());
   $sth->execute
      or return(-3, "Can't execute SQL statement: ".$sth->errstr());

   my (@userlist, @data);
   while (@data = $sth->fetchrow_array()) {	# only 1 field here
      push (@userlist, $data[0]);
   }
   $sth->finish;
   $dbh->disconnect or return(-3, "Disconnection failed: ".$DBI::errstr);

   return(0, '', @userlist)
}


#  0 : ok
# -1 : function not supported
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user, $password)=@_;
   return (-2, "User or password is null") if ($user eq '' || $password eq '');

   my $dbh = DBI->connect("dbi:mysql:$auth_db;host=$SQLHost", $sqlusr,$sqlpwd)
      or return(-3, "Cannot connect to db server: ".$DBI::errstr);
   my $queryStr = qq|select $field_username, $field_password from $auth_table where strcmp($field_username , '$user')=0|;
   my $sth = $dbh->prepare($queryStr)
      or return(-3, "Can't prepare SQL statement: ".$dbh->errstr());
   $sth->execute
      or return(-3, "Can't execute SQL statement: ".$sth->errstr());

   if ($sth->rows eq 0) {
      $sth->finish;
      $dbh->disconnect or return(-3, "Disconnection failed: ".$DBI::errstr);
      return (-4, "User $user doesn't exit");
   } else {
      if (my $result = $sth->fetchrow_hashref()) {
         $sth->finish;
         $dbh->disconnect or return(-3, "Disconnection failed: ".$DBI::errstr);
         my $tmp_pwd = $result->{$field_password};
         if ($pass_type eq "cleartxt") {
            if ($tmp_pwd eq $password) {
               return (0, '');
            } else {
               return (-4, 'Password incorrect');
            }
         } elsif ($pass_type eq "crypt") {
            if ($tmp_pwd eq crypt($password, $tmp_pwd)) {
               return (0, '');
            } else { 
               return (-4, 'Password incorrect');
            }
         } elsif ($pass_type eq "md5") {
            if ($tmp_pwd eq Digest::MD5::md5_hex($password)) {
               return (0,'');
            } else {
               return (-4, 'Password incorrect');
            }
         } else {
            return(-3, "Unknown password type: $pass_type");
         }
      } else {
         return(-3, "Can't fetch SQL result: ".$sth->errstr());
      }
   }
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

   if ($pass_type eq "crypt") { # encrypt the passwd
      my @salt_chars = ('a'..'z','A'..'Z','0'..'9');
      my $salt = $salt_chars[rand(62)] . $salt_chars[rand(62)];
      $newpassword = crypt($newpassword, $salt);
   }
   if ($pass_type eq "md5") {
      $newpassword = Digest::MD5::md5_hex($newpassword);
   }

   my $dbh = DBI->connect("dbi:mysql:$auth_db;host=$SQLHost", $sqlusr,$sqlpwd)
      or return(-3, "Cannot connect to db server: ".$DBI::errstr);
   my $queryStr = qq|update $auth_table set $field_password='$newpassword' where strcmp($field_username , '$user')=0|;
   my $sth = $dbh->prepare($queryStr)
      or return(-3, "Can't prepare SQL statement: ".$dbh->errstr());
   $sth->execute
      or return(-3, "Can't execute SQL statement: ".$sth->errstr());
   $dbh->disconnect or return(-3, "Disconnection failed: ".$DBI::errstr);

   return (0, '');
}

1;
