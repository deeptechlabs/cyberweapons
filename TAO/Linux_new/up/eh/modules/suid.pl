package ow::suid;
use strict;
#
# suid.pl - set ruid/euid/egid of process
#

########## No configuration required from here ###################

require "modules/tool.pl";

my %conf;
if (($_=ow::tool::find_configfile('etc/suid.conf', 'etc/suid.conf.default')) ne '') {
   my ($ret, $err)=ow::tool::load_configfile($_, \%conf);
   die $err if ($ret<0);
}
my $has_savedsuid_support = $conf{'has_savedsuid_support'} || 'no';

########## end init ##############################################

# openwebmail drop euid root after user has been authenticated
# this routine save root to ruid in case system doesn't support saved-euid
# so we can give up euid root temporarily and get it back later.
sub set_euid_egids {
   my ($euid, @egids)=@_;
   # trick: 2nd parm will be ignore, so we repeat parm 1 twice
   $) = join(" ", $egids[0], @egids);
   if ($> != $euid) {
      $<=$> if ($has_savedsuid_support ne 'yes' && $>==0);
      $> = $euid;
   }
   return;
}

# the following two are used to switch euid/euid back to root temporarily
# when user has been authenticated
sub set_uid_to_root {
   my ($origruid, $origeuid, $origegid)=( $<, $>, $) );
   $> = 0; 	# first set the user to root
   $) = 0; 	# set effective group to root
   $< = $>;	# set real user to root, 
                # some cmds checks ruid even euid is already root
   return ($origruid, $origeuid, $origegid);
}

sub restore_uid_from_root {
   my ($ruid, $euid, $egid)=@_;
   $) = $egid;
   $< = $ruid;
   $> = $euid;
   return;
}

1;
