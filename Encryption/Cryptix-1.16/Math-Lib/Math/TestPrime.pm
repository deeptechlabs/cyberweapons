
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Math::TestPrime;

use strict;
use Carp;

use Math::BigInteger;
use integer;


#
#	Make a table of the smaller primes
#	 for efficiency reaons
#
BEGIN
{
	push(@Math::TestPrime::primes, 2);
	my $p = 1;
	my $i;
	loop: while ($#Math::TestPrime::primes < 302)
	{
		$p += 2;
		my $s = int(sqrt($p));
		for ($i=0; $Math::TestPrime::primes[$i] <= $s; $i++)
		{
			next loop if (($p % $Math::TestPrime::primes[$i]) == 0);
		}
		push (@Math::TestPrime::primes, $p);
	}

	#
	#	Now convert to BigIntegers
	#
	for ($i=0; $Math::TestPrime::primes[$i] <= $#Math::TestPrime::primes; $i++)
	{
		$Math::TestPrime::primes[$i] = new Math::BigInteger $Math::TestPrime::primes[$i];
	}
}


sub smallFactor
{
	my $n = shift;

	my $zero = new Math::BigInteger;
	my $r = new Math::BigInteger;
	my $p;
	foreach $p (@Math::TestPrime::primes)
	{
		Math::BigInteger::mod($r, $n, new Math::BigInteger $p);
		return $p if (Math::BigInteger::cmp($r, $zero) == 0);
	}
	return 0;
}

sub isPrime
{
	my $p = shift;

	$p = new Math::BigInteger $p unless ref($p);
	return 0 if (smallFactor($p));

	my $r = new Math::BigInteger;
	my $one = new Math::BigInteger 1;

	my $p1 = $p->clone();
	$p1--;

	my $i = 0;
	for ($i = 0; $i < 4; $i++)
	{
		my $x = $Math::TestPrime::primes[$i];
		Math::BigInteger::mod_exp($r, $x, $p1, $p); # random return
		# ((x ^ (p-1)) % p) != 1 then p isn't prime
		if (Math::BigInteger::cmp($r, $one) != 0) { return 0 };
	}

	return 1;
}

#
#	This was going to be a Rabin-Miller test, but
#	I decided to used a Fermat test for now
#
#
#
#	my $p_bits = $p->bits();
#
#	my $p1 = clone Math::BigInteger $p;
#	$p1->dec();
#	my $b = $p1->bits();
#
#	my $m = new Math::BigInteger;
#	Math::BigInteger::reciprical($m, $p) || return 0;
#
#	my $i;
#	for ($i = 0; $i < 5; $i++)
#	{
#		my $a = randomMath::BigInteger($p_bits - 1);
#
#		#
#		#	Now perform Rabin-Miller test
#		#
#
#		for ($i = $b-1; $i >= 0; $i--)
#		{
#			Math::BigInteger::modmul_recip($r, $
#		}
#
#
#		my $j = 0;
#
#		my $z = new Math::BigInteger;
#		Math::BigInteger::mod_exp($z, $a, $m, $p);
#	}

1;
