package ow::execute;
use strict;
#
# execute.pl - execute external command in a secure way
#
# Since we call open3 with @cmd array,
# perl will call execvp() directly without shell interpretation.
# this is much secure than system()
#

use IPC::Open3;
use vars qw(*cmdOUT *cmdIN *cmdERR);
sub execute {
   my @cmd;
   foreach (@_) { /^(.*)$/ && push(@cmd, $1); }	# untaint all argument

   my ($childpid, $stdout, $stderr);
   my $mypid=$$;
   local $SIG{CHLD}; undef $SIG{CHLD};	# disable outside $SIG{CHLD} handler temporarily for wait()
   local $|=1;			# flush CGI related output in parent

   eval { $childpid = open3(\*cmdIN, \*cmdOUT, \*cmdERR, @cmd); };
   if ($@) {			# open3 return err only in child
      if ($$!=$mypid){ 		# child
         print STDERR $@;	# pass $@ to parent through stderr pipe
         exit 9;		# terminated
      }
   }

   while (1) {
      my ($rin, $rout, $ein, $eout, $buf)=('','','','','');
      my ($n, $o, $e)=(0,1,1);

      vec($rin, fileno(\*cmdOUT), 1) = 1;
      vec($rin, fileno(\*cmdERR), 1) = 1;
      $ein=$rin;

      $n=select($rout=$rin, undef, $eout=$ein, 30);
      last if ($n<0);	# read err => child dead?
      last if ($n==0);	# timeout

      if (vec($rout,fileno(\*cmdOUT),1)) {
         $o=sysread(\*cmdOUT, $buf, 16384);
         $stdout.=$buf if ($o>0);
      }
      if (vec($rout,fileno(\*cmdERR),1)) {
         $e=sysread(\*cmdERR, $buf, 16384);
         $stderr.=$buf if ($e>0);
      }
      last if ($n>0 && $o==0 && $e==0);
   }
   $childpid=wait;

   $|=0;
   return($stdout, $stderr, $?>>8, $?&255);
}

1;
