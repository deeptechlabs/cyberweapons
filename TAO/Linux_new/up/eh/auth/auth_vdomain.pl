package ow::auth_vdomain;
use strict;
#
# auth_vdomain.pl - authenticate virtual user on vm-pop3d+postfix system
#
# 2003/03/03 tung.AT.turtle.ee.ncku.edu.tw
#

########## No configuration required from here ###################

use Fcntl qw(:DEFAULT :flock);
require "modules/filelock.pl";
require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/auth_vdomain.conf', 'etc/auth_vdomain.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
}

# the user for all virtual users mailbox by default
my $local_uid=getpwnam($conf{'virtualuser'}||'nobody');

########## end init ##############################################

#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : user doesn't exist
sub get_userinfo {
   my ($r_config, $user_domain)=@_;
   return(-2, 'Not valid user@domain format') if ($user_domain !~ /(.+)[\@:!](.+)/);
   my ($user, $domain)=($1, $2);

   my ($localuser, $uid, $gid, $realname, $homedir) = (getpwuid($local_uid))[0,2,3,6,7];
   return(-3, "Uid $local_uid doesn't exist") if ($uid eq "");

   my $pwdfile="${$r_config}{'vdomain_vmpop3_pwdpath'}/$domain/${$r_config}{'vdomain_vmpop3_pwdname'}";
   return(-2, "Passwd file for domain $domain doesn't exist ") if (!-f $pwdfile);

   # check if virtual user exists in vdomain passwd file
   ow::filelock::lock($pwdfile, LOCK_SH) or
      return (-3, "Couldn't get read lock on $pwdfile");
   if (!open(PASSWD, $pwdfile)) {
      ow::filelock::lock($pwdfile, LOCK_UN);
      return (-3, "Couldn't get open $pwdfile");
   }
   my $found=0;
   while (<PASSWD>) {
      if (/^$user:/) {
         $found=1; last;
      }
   }
   close(PASSWD);
   ow::filelock::lock($pwdfile, LOCK_UN);
   return(-4, "User $user_domain doesn't exist") if (!$found);

   my $domainhome="$homedir/$domain";
   if ( ${$r_config}{'use_syshomedir'} && -d $homedir) {
      # mkdir domainhome so openwebmail.pl can create user homedir under this domainhome
      if (! -d $domainhome) {
         my $mailgid=getgrnam('mail');
         $domainhome = ow::tool::untaint($domainhome);
         mkdir($domainhome, 0750);
         return(-3, "Couldn't create domain homedir $domainhome") if (! -d $domainhome);
         chown($uid, $mailgid, $domainhome);
      }
   }

   # get other gid for the localuser in /etc/group
   while (my @gr=getgrent()) {
      $gid.=' '.$gr[2] if ($gr[3]=~/\b$localuser\b/ && $gid!~/\b$gr[2]\b/);
   }

   return(0, '', $user, $uid, $gid, "$domainhome/$user");
}


#  0 : ok
# -1 : function not supported
# -3 : authentication system/internal error
sub get_userlist {	# only used by openwebmail-tool.pl -a
   my $r_config=$_[0];

   my @userlist=();
   my $line;
   foreach my $domain (vdomainlist($r_config)) {
      my $pwdfile="${$r_config}{'vdomain_vmpop3_pwdpath'}/$domain/${$r_config}{'vdomain_vmpop3_pwdname'}";

      ow::filelock::lock($pwdfile, LOCK_SH) or
         return (-3, "Couldn't get read lock on $pwdfile");
      if (! open(PASSWD, $pwdfile)) {
         ow::filelock::lock($pwdfile, LOCK_UN);
         return (-3, "Couldn't get open $pwdfile");
      }
      while (defined($line=<PASSWD>)) {
         next if ($line=~/^#/);
         chomp($line);
         push(@userlist, (split(/:/, $line))[0]."\@$domain");
      }
      close(PASSWD);
      ow::filelock::lock($pwdfile, LOCK_UN);
   }
   return(0, '', @userlist);
}


#  0 : ok
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub check_userpassword {
   my ($r_config, $user_domain, $password)=@_;
   return (-2, "User or password is null") if ($user_domain eq '' || $password eq '');
   return (-2, 'Not valid user@domain format') if ($user_domain !~ /(.+)[\@:!](.+)/);
   my ($user, $domain)=($1, $2);

   my $pwdfile="${$r_config}{'vdomain_vmpop3_pwdpath'}/$domain/${$r_config}{'vdomain_vmpop3_pwdname'}";
   return (-4, "Passwd file $pwdfile doesn't exist") if (! -f $pwdfile);

   ow::filelock::lock($pwdfile, LOCK_SH) or
      return (-3, "Couldn't get read lock on $pwdfile");
   if ( ! open (PASSWD, $pwdfile) ) {
      ow::filelock::lock($pwdfile, LOCK_UN);
      return (-3, "Couldn't open $pwdfile");
   }
   my ($line, $u, $p);
   while (defined($line=<PASSWD>)) {
      chomp($line);
      ($u, $p) = (split(/:/, $line))[0,1];
      last if ($u eq $user); # We've found the user in virtual domain passwd file
   }
   close (PASSWD);
   ow::filelock::lock($pwdfile, LOCK_UN);

   return(-4, "User $user_domain doesn't exist") if ($u ne $user);
   return(-4, "Password incorrect") if (crypt($password,$p) ne $p);
   return (0, '');
}


#  0 : ok
# -1 : function not supported
# -2 : parameter format error
# -3 : authentication system/internal error
# -4 : password incorrect
sub change_userpassword {
   my ($r_config, $user_domain, $oldpassword, $newpassword)=@_;
   return (-2, "User or password is null") if ($user_domain eq '' || $oldpassword eq '' || $newpassword eq '');
   return (-2, 'Not valid user@domain format') if ($user_domain !~ /(.+)[\@:!](.+)/);
   my ($user, $domain)=($1, $2);

   my $pwdfile="${$r_config}{'vdomain_vmpop3_pwdpath'}/$domain/${$r_config}{'vdomain_vmpop3_pwdname'}";
   return (-4, "Passwd file $pwdfile doesn't exist") if (! -f $pwdfile);

   my ($u, $p, $encrypted);
   my $content="";
   my $line;

   ow::filelock::lock($pwdfile, LOCK_EX) or
      return (-3, "Couldn't get write lock on $pwdfile");
   if ( ! open (PASSWD, $pwdfile) ) {
      ow::filelock::lock($pwdfile, LOCK_UN);
      return (-3, "Couldn't open $pwdfile");
   }
   while (defined($line=<PASSWD>)) {
      $content .= $line;
      chomp($line);
      ($u, $p) = split(/:/, $line) if ($u ne $user);
   }
   close (PASSWD);

   if ($u ne $user) {
      ow::filelock::lock($pwdfile, LOCK_UN);
      return (-4, "User $user_domain doesn't exist");
   }
   if (crypt($oldpassword,$p) ne $p) {
      ow::filelock::lock($pwdfile, LOCK_UN);
      return (-4, "Incorrect password");
   }

   my @salt_chars = ('a'..'z','A'..'Z','0'..'9');
   my $salt = $salt_chars[rand(62)] . $salt_chars[rand(62)];
   if ($p =~ /^\$1\$/) {	# if orig encryption is MD5, keep using it
      $salt = '$1$'. $salt;
   }
   $encrypted= crypt($newpassword, $salt);

   my $oldline="$u:$p";
   my $newline="$u:$encrypted";
   if ($content !~ s/\Q$oldline\E/$newline/) {
      ow::filelock::lock($pwdfile, LOCK_UN);
      return (-3, "Unable to match entry for modification");
   }

   open(TMP, ">$pwdfile.tmp.$$") or goto authsys_error;
   print TMP $content or goto authsys_error;
   close(TMP) or goto authsys_error;

   # automic update passwd by rename
   my ($fmode, $fuid, $fgid) = (stat($pwdfile))[2,4,5];
   chown($fuid, $fgid, "$pwdfile.tmp.$$");
   chmod($fmode, "$pwdfile.tmp.$$");
   rename("$pwdfile.tmp.$$", $pwdfile) or goto authsys_error;

   ow::filelock::lock($pwdfile, LOCK_UN);
   return (0, '');

authsys_error:
   unlink("$pwdfile.tmp.$$");
   ow::filelock::lock($pwdfile, LOCK_UN);
   return (-3, "Unable to write $pwdfile");
}


########## misc support routine ##################################

sub vdomainlist {
   my $r_config=$_[0];
   my (@domainlist, $dir);
   opendir(D, ${$r_config}{'vdomain_vmpop3_pwdpath'});
   while (defined($dir=readdir(D))) {
      next if ($dir eq "." || $dir eq "..");
      # does domain passwd  file exist?
      if ( -f "${$r_config}{'vdomain_vmpop3_pwdpath'}/$dir/${$r_config}{'vdomain_vmpop3_pwdname'}" ) {
         push(@domainlist, $dir);
      }
   }
   closedir(D);
   return(@domainlist);
}

1;
