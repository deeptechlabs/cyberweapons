package ow::auth_pam;
use strict;
#
# auth_pam.pl - authenticate user with PAM
#
# 2002/08/01 webmaster.AT.pkgmaster.com
#            add check for nologin, validshell, cobaltuser 
#            based on work from Trevor.Paquette.AT.TeraGo.ca
# 2001/10/05 tung.AT.turtle.ee.ncku.edu.tw
#
# The code of check_userpassword and change_userpassword is from
# the example code of Authen::PAM by Nikolay Pelov <nikip.AT.iname.com>
# Webpage is available at http://www.cs.kuleuven.ac.be/~pelov/pam
#

########## No configuration required from here ###################

use Authen::PAM;
use Fcntl qw(:DEFAULT :flock);
require "modules/filelock.pl";
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_pam.conf', 'etc/auth_pam.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
}

my $servicename = $conf{'servicename'} || "openwebmail";
my $passwdfile_plaintext = $conf{'passwdfile_plaintext'} || "/etc/passwd";

my $check_nologin = $conf{'check_nologin'} || 'no';
my $check_shell = $conf{'check_shell'} || 'no';
my $check_cobaltuser = $conf{'check_cobaltuser'} || 'no';

########## end init ##############################################

# routines get_userinfo() and get_userlist still get data from a passwdfile
# instead of PAM, you may have to rewrite if it does notfit your requirement

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user)=@_;
   return(-2, 'User is null') if ($user eq '');

   my ($uid, $gid, $realname, $homedir);
   if ($passwdfile_plaintext eq "/etc/passwd") {
      ($uid, $gid, $realname, $homedir)= (getpwnam($user))[2,3,6,7];
   } else {
      if ($passwdfile_plaintext=~/\|/) { # maybe NIS, try getpwnam first
         ($uid, $gid, $realname, $homedir)= (getpwnam($user))[2,3,6,7];
      }
      if ($uid eq "") { # else, open file directly
         ($uid, $gid, $realname, $homedir)= (getpwnam_file($user, $passwdfile_plaintext))[2,3,6,7];
      }
   }
   return(-4, "User $user doesn't exist") if ($uid eq "");

   # get other gid for this user in /etc/group
   while (my @gr=getgrent()) {
      $gid.=' '.$gr[2] if ($gr[3]=~/\b$user\b/ && $gid!~/\b$gr[2]\b/);
   }
   # use first field only
   $realname=(split(/,/, $realname))[0];
   # guess real homedir under sun's automounter
   $homedir="/export$homedir" if (-d "/export$homedir");

   return(0, "", $realname, $uid, $gid, $homedir);
}


#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist {	# only used by openwebmail-tool.pl -a
   my $r_config=$_[0];

   my @userlist=();
   my $line;

   # a file should be locked only if it is local accessable
   if ( -f $passwdfile_plaintext) {
      ow::filelock::lock($passwdfile_plaintext, LOCK_SH) or
         return (-3, "Couldn't get read lock on $passwdfile_plaintext", @userlist);
   }
   open(PASSWD, $passwdfile_plaintext);
   while (defined($line=<PASSWD>)) {
      next if ($line=~/^#/);
      chomp($line);
      push(@userlist, (split(/:/, $line))[0]);
   }
   close(PASSWD);
   ow::filelock::lock($passwdfile_plaintext, LOCK_UN) if ( -f $passwdfile_plaintext);
   return(0, "", @userlist);
}

# globals passed to inner function to avoid closure effect
use vars qw($pam_user $pam_password $pam_newpassword $pam_convstate);

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my $r_config;
   local ($pam_user, $pam_password);	# localized global to make reentry safe
   ($r_config, $pam_user, $pam_password)=@_;
   return (-2, "User or password is null") if ($pam_user eq '' || $pam_password eq '');

   sub checkpwd_conv_func {
      my @res;
      while ( @_ ) {
         my $code = shift;
         my $msg = shift;
         my $ans = "";

         if ($code == PAM_PROMPT_ECHO_ON() ) {
            $ans = $pam_user;
         } elsif ($code == PAM_PROMPT_ECHO_OFF() ) {
            $ans = $pam_password;
         }
         push @res, (PAM_SUCCESS(),$ans);
#ow::tool::log_time("code:$code, msg:$msg, ans:$ans\n");	# debug
      }
      push @res, PAM_SUCCESS();
      return @res;
   }

   # disable SIG CHLD since authsys in PAM may fork process
   local $SIG{CHLD}; undef $SIG{CHLD};

   my ($pamh, $ret, $errmsg);
   if ( ref($pamh = new Authen::PAM($servicename, $pam_user, \&checkpwd_conv_func)) ) {
      my $error=$pamh->pam_authenticate();
      if ($error==0) {
         ($ret, $errmsg)= (0, "");
      } else {
         ($ret, $errmsg)= (-4, "pam_authticate() err $error, ".pam_strerror($pamh, $error));
      }
   } else {
      ($ret, $errmsg)= (-3, "PAM init error $pamh");
   }
   $pamh = 0;  # force Destructor (per docs) (invokes pam_close())

   return($ret, $errmsg) if ($ret<0);

   # emulate pam_nologin.so
   if ($check_nologin=~/yes/i && -e "/etc/nologin") {
      return (-4, "/etc/nologin found, all logins are suspended");
   }
   # emulate pam_shells.so
   if ($check_shell=~/yes/i && !has_valid_shell($pam_user)) {
      return (-4, "user $pam_user doesn't have valid shell");
   }
   # valid user on cobalt ?
   if ($check_cobaltuser=~/yes/i) {
      my $cbhttphost=$ENV{'HTTP_HOST'}; $cbhttphost=~s/:\d+$//;	# remove port number
      my $cbhomedir="/home/sites/$cbhttphost/users/$pam_user";
      if (!-d $cbhomedir) {
         return (-4, "This cobalt user $pam_user doesn't has homedir $cbhomedir");
      }
   }

   return (0, "");
}


#  0 : ok
# -1 : function not supported
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub change_userpassword {
   local ($pam_user, $pam_password, $pam_newpassword); # localized global to make reentry safe
   my $r_config;
   ($r_config, $pam_user, $pam_password, $pam_newpassword)=@_;
   return (-2, "User or password is null") if ($pam_user eq '' || $pam_password eq '' || $pam_newpassword eq '');

   local $pam_convstate=0;	# localized global to make reentry safe
   sub changepwd_conv_func {
      my @res;

      while ( @_ ) {
         my $code = shift;
         my $msg = shift;
         my $ans = "";

         if ($code == PAM_PROMPT_ECHO_ON() ) {
            $ans = $pam_user;
         } elsif ($code == PAM_PROMPT_ECHO_OFF() ) {
            if ($pam_convstate>1 || $msg =~ /new/i ) {
               $ans = $pam_newpassword;
            } else {
               $ans = $pam_password;
            }
            $pam_convstate++;
         }
         push @res, (PAM_SUCCESS(),$ans);
#ow::tool::log_time("code:$code, msg:$msg, ans:$ans\n");	# debug
      }
      push @res, PAM_SUCCESS();
      return @res;
   }

   # disable SIG CHLD since authsys in PAM may fork process
   local $SIG{CHLD}; undef $SIG{CHLD};

   my ($pamh, $ret, $errmsg);
   if (ref($pamh = new Authen::PAM($servicename, $pam_user, \&changepwd_conv_func)) ) {
      my $error=$pamh->pam_chauthtok();
      if ( $error==0 ) {
         ($ret, $errmsg)= (0, "");
      } else {
         ($ret, $errmsg)= (-4, "pam_authtok() err $error, ".pam_strerror($pamh, $error));
      }
   } else {
      ($ret, $errmsg)= (-3, "PAM init error $pamh");
   }
   $pamh = 0;  # force Destructor (per docs) (invokes pam_close())
   return($ret, $errmsg);
}


########## misc support routine ##################################

# this routie is slower than system getpwnam() but can work with file
# other than /etc/passwd. ps: it always return '*' for passwd field.
sub getpwnam_file {
   my ($user, $passwdfile_plaintext)=@_;
   my ($name, $passwd, $uid, $gid, $gcos, $dir, $shell);

   return("", "", "", "", "", "", "", "", "") if ($user eq "");

   open(PASSWD, "$passwdfile_plaintext");
   while(<PASSWD>) {
      next if (/^#/);
      chomp;
      ($name, $passwd, $uid, $gid, $gcos, $dir, $shell)=split(/:/);
      last if ($name eq $user);
   }
   close(PASSWD);

   if ($name eq $user) {
      return($name, "*", $uid, $gid, 0, "", $gcos, $dir, $shell);
   } else {
      return("", "", "", "", "", "", "", "", "");
   }
}

sub has_valid_shell {
   my $user=$_[0];

   my ($name, $shell);
   if ($passwdfile_plaintext eq "/etc/passwd") {
      $shell = (getpwnam($user))[8];
   } else {
      if ($passwdfile_plaintext=~/\|/) { # maybe NIS, try getpwnam first
         ($name, $shell)= (getpwnam($user))[0,8];
      }
      if ($name eq "") { # else, open file directly
         ($name, $shell) = (getpwnam_file($user, $passwdfile_plaintext))[0,8];
      }
   }
   return 0 if ($shell eq '');

   my $validshell = 0;
   if (open(ES, "/etc/shells")) {
      while(<ES>) {
         chomp;
         if( $shell eq $_ ) {
            $validshell = 1; last;
         }
      }
      close(ES);
   }
   return 0 if (!$validshell);

   return 1;
}

1;
