BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

package Math::TrulyRandom;

use DynaLoader;
@ISA = qw(DynaLoader);

bootstrap Math::TrulyRandom;

#
#	How on earth do we test for randomness?
#

print "1\n";




my $val1 = Math::TrulyRandom::rand();
my $val2 = Math::TrulyRandom::rand();
my $val3 = Math::TrulyRandom::rand();

print "1 ";
($val1 != $val2 || $val2 != $val3) || print "not ";
print "ok\n";
