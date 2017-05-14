package ow::auth_mysql_vmail;
use strict;
#
# auth_mysql_vmail.pl - authenticate user with MySQL, where required fields
#                       are in more tables (like in vmail-sql).
# v1.5
# 2002/04/23 Zoltan Kovacs, werdy.AT.freemail.hu
#

########## No configuration required from here ###################

use DBI;
use Digest::MD5;
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_mysql_vmail.conf', 'etc/auth_mysql_vmail.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
} else {
   die "Config file auth_mysql_vmail.conf not found!";
}

########################
# MySQL access options #
########################
my %mysql_auth=(
   mysql_server         => $conf{'mysql_server'},
   mysql_database       => $conf{'mysql_database'},
   mysql_user           => $conf{'mysql_user'},
   mysql_passwd         => $conf{'mysql_passwd'},
   password_hash_method => $conf{'password_hash_method'} || "MD5"
);

#################
# MySQL queries #
#################
my %mysql_query=(
   userlist        => $conf{'userlist'},
   user_password   => $conf{'password'},
   user_homedir    => $conf{'homedir'},
   unix_user       => $conf{'unix_user'},
   change_password => $conf{'change_password'}
);

########## end init ##############################################

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   my ( $unix_user, $gid, $uid, $home, $key, $domain );

   return(-2, 'User is null') if ($user eq '');
   if ( $user =~ /^(.*)\@(.*)$/ ) {
      ($user, $domain) = ($1, $2);
   }

   mysql_command("USE $mysql_auth{mysql_database}")==0 or
      return(-3, "MySQL connect error");

   my $q;
   if ( $mysql_query{user_homedir} ) {
      $q=$mysql_query{user_homedir};
      $q=~s/_user_/$user/g; $q=~s/_domain_/$domain/g;
      ( $home ) = mysql_command($q);
   }
   $q=$mysql_query{unix_user};
   $q=~s/_user_/$user/g; $q=~s/_domain_/$domain/g;
   ( $unix_user ) = mysql_command($q);

   mysql_command("EXIT")==0 or
      return(-3, "MySQL disconnect error");

   ( $uid, $gid ) = ( getpwnam($unix_user) )[2,3];
   return (-4, "User $user doesn't exist") if ( $unix_user eq '' || $uid eq '' || $gid eq '');

   return (0, '', "",$uid,$gid,$home);
}

#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist { # only used by openwebmail-tool.pl -a
   my $r_config=$_[0];
   my @userlist;

   mysql_command("USE $mysql_auth{mysql_database}")==0 or
      return(-3, "MySQL connect error");

   @userlist = &mysql_command( $mysql_query{userlist} );

   mysql_command("EXIT")==0 or
      return(-3, "MySQL disconnect error");

   return (0, '', @userlist);
}

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user, $passwd)=@_;
   return (-2, "User or password is null") if ($user eq '' || $passwd eq '');

   my ( $passwd_hash, $domain );
   if ( $user =~ /^(.*)\@(.*)$/ ) { ($user,$domain) = ($1,$2); }

   mysql_command("USE $mysql_auth{mysql_database}")==0 or
      return(-3, "MySQL connect error");

   my $q=$mysql_query{user_password};
   $q=~s/_user_/$user/g; $q=~s/_domain_/$domain/g;
   ( $passwd_hash ) = &mysql_command($q);

   mysql_command("EXIT")==0 or
      return(-3, "MySQL disconnect error");

   if ( $mysql_auth{password_hash_method} =~ /plaintext/i ) {
      return (0,'') if ( $passwd_hash eq $passwd );
   } elsif ( $mysql_auth{password_hash_method} =~ /md5/i ) {
      $passwd_hash =~ s/^\{.*\}(.*)$/$1/;
      return (0, '') if ( $passwd_hash eq Digest::MD5::md5_hex($passwd) );
   }

   return (-4, 'username/password incorrect');
}


#  0 : ok
# -1 : function not supported
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub change_userpassword {
   my ($r_config, $user, $oldpasswd, $newpasswd)=@_;
   return (-2, "User or password is null") if ($user eq '' || $oldpasswd eq '' || $newpasswd eq '');
   return (-2, "Password too short") if (length($newpasswd)<${$r_config}{'passwd_minlen'});

   my ($ret, $errmsg)=check_userpassword($r_config, $user, $oldpasswd);
   return($ret, $errmsg) if ($ret!=0);

   my $domain;
   if ( $user =~ /^(.*)\@(.*)$/ ) { ($user,$domain) = ($1,$2); }

   mysql_command("USE $mysql_auth{mysql_database}")==0 or
      return(-3, "MySQL connect error");

   my $q=$mysql_query{change_password};
   $q=~s/_user_/$user/g; $q=~s/_domain_/$domain/g;
   if ( $mysql_auth{password_hash_method} =~ /plaintext/i ) {
      $q=~ s/_new_password_/$newpasswd/g;
   } elsif ( $mysql_auth{password_hash_method} =~ /md5/i ) {
      $newpasswd = "{md5}".Digest::MD5::md5_hex($newpasswd);
      $q =~ s/_new_password_/$newpasswd/g;
   }
   return (-3, 'MySQL update error') if ( mysql_command($q)!=0 );

   mysql_command("EXIT")==0 or
      return(-3, "MySQL disconnect error");

   return(0, '');
}


########## misc support routine ##################################

#  0 : ok
# -1 : MySQL error
sub mysql_command {
   my @query = @_;
   my (@result, @row, $sth);

   for ( 0 .. $#query ) {
      if ( $query[$_] =~ /^USE (.*)$/ ) {
         $main::dbh = DBI->connect("DBI:mysql:database=$1:host=$mysql_auth{mysql_server}",
				$mysql_auth{mysql_user},$mysql_auth{mysql_passwd}) or return -1;
         return 0;
      } elsif ( $query[$_] eq "EXIT" ) {
         $main::dbh->disconnect() or return -1;
         return 0;
      } elsif ( $query[$_] =~ /^SELECT/ ) {
         $sth = $main::dbh->prepare( $query[$_] );
         $sth->execute() or return -1;
         while ( @row = $sth->fetchrow_array ) { push @result,@row; }
         $sth->finish();
      } else {
         $main::dbh->do( $query[$_] ) or return -1;
         return 0;
      }
   }
   return (@result);
}

1;
