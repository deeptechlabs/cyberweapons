package ow::auth_pg;
use strict;
#
# auth_pgsql.pl - authenticate user with PostgreSQL
#
# 2002/04/05 Veselin Slavov, vess.AT.btc.net
#

########## No configuration required from here ###################

use Pg;
use MD5;
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_pg.conf', 'etc/auth_pg.conf.default')) ne "") {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
} else {
   die "Config file auth_pg.conf not found!";
}

my $PgHost	= $conf{'PgHost'};
my $PgPort	= $conf{'PgPort'};
my $PgBase 	= $conf{'PgBase'};
my $PgUser	= $conf{'PgUser'};
my $PgPass 	= $conf{'PgPass'};
my $PgPassType	= $conf{'PgPassType'};

########## end init ##############################################

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   return(-2, 'User is null') if ($user eq '');

   my $DB = Pg::connectdb("host='$PgHost' port='$PgPort' dbname='$PgBase' user='$PgUser' password='$PgPass'") or
      return(-3, "PgSQL server $PgHost connect error");
   my @ret=();
   my $q= qq/select "Uid", "Gid", "rname", "MailDir" from users where uname='$user'/;
   Pg::doQuery($DB, $q, \@ret) or
      return(-3, "PgSQL server $PgHost query error");
   undef($DB);

   return (-4, "User $user doesn't exist") if ($ret[0][0] eq '');

   my ($uid, $gid, $realname, $homedir);
   $uid      = $ret[0][0];
   $gid      = $ret[0][1];
   $realname = $ret[0][2];
   $homedir  = $ret[0][3];
   return(0, '', $realname, $uid, $gid, $homedir);
}


#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist {      # only used by openwebmail-tool.pl -a
   my $r_config=$_[0];

   my $DB = Pg::connectdb("host='$PgHost' port='$PgPort' dbname='$PgBase' user='$PgUser' password='$PgPass'") or
      return(-3, "PgSQL server $PgHost connect error");
   my $q="select uname from users";
   my @userlist=();
   Pg::doQuery($DB,$q,\@userlist) or
      return(-3, "PgSQL server $PgHost query error");
   undef($DB);

   return (0, '', @userlist);
}


#  0 : ok
# -1 : function not supported
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user, $password)=@_;
   return (-2, "User or password is null") if ($user eq '' || $password eq '');

   my $DB = Pg::connectdb("host='$PgHost' port='$PgPort' dbname='$PgBase' user='$PgUser' password='$PgPass'") or
      return(-3, "PgSQL server $PgHost connect error");
   my $q="select upass from users where uname='$user'";
   my @ret=();
   Pg::doQuery($DB,$q,\@ret) or
      return(-3, "PgSQL server $PgHost query error");
   undef($DB);

   return (-4, "User $user doesn't exist") if ($ret[0][0] eq '');

   my $tmp_pwd = $ret[0][0];
   $tmp_pwd =~ s/ //g;

   CASE: for ($PgPassType){
      /cleartxt/ && do {	#if cleartext password
         return(-4, 'Password incorrect') if ($tmp_pwd ne $password);
         last
      };

      /crypt/ && do {		#if crypto password
         return(-4, 'Password incorrect') if ($tmp_pwd ne crypt($password, $tmp_pwd));
         last
      };

      /md5/ && do {		#if md5 kode password
         my($m5) = new MD5;
         $m5->reset;
         $m5->add($password);
         my($mm)= $m5->digest();
         my($md5)= unpack("H*",$mm);
         return(-4, 'Password incorrect') if ($tmp_pwd ne $md5);
         last
      };

      return(-3, "Unknown password type: $PgPassType");
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
   return (-2,"Password too short") if (length($newpassword)<${$r_config}{'passwd_minlen'});

   my ($ret, $errmsg)=check_userpassword($r_config, $user, $oldpassword);
   return($ret, $errmsg) if ($ret!=0);

   my ($passwd);
   CASE: for ($PgPassType){
      /cleartxt/ && do {	#if cleartext password
         $passwd=$newpassword;
         $passwd =~ tr/[a-z][A-Z][0-9]~!@#()-_.//dcs; # ignore some symbols
         return (-2, 'Invalid char in password') unless $passwd eq $newpassword;
         last
      };

      /crypt/ && do {   	# if crypto password
         my @salt_chars = ('a'..'z','A'..'Z','0'..'9');
         my $salt = $salt_chars[rand(62)] . $salt_chars[rand(62)];
         $passwd = crypt($newpassword, $salt);
         last
      };

      /md5/ && do {		#if md5 kode password
         my($m5) = new MD5;
         $m5->reset;
         $m5->add($newpassword);
         my($mm)= $m5->digest();
         $passwd= unpack("H*",$mm);
         last
      };

      return(-3, "Unknown password type: $PgPassType");
   }

   my $DB = Pg::connectdb("host='$PgHost' port='$PgPort' dbname='$PgBase' user='$PgUser' password='$PgPass'") or
      return(-3, "PgSQL server $PgHost connect error");
   $DB->exec("update users set upass='$passwd' where uname='$user'");
      return(-3, "PgSQL server $PgHost exec error");
   undef($DB);

   return (0,'');
}

1;
