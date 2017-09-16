
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::RSAKeyGen;

use strict;
use integer;

use Math::BigInteger;
use Math::Random;
use Crypt::RSASecretKeyPair;


#
#	Parameters - p,q, [e-start]
#		If e-start is present, it must be odd
#
sub deriveKeys
{
	my $p = shift;
	my $q = shift;
	my $e = shift;

	#
	#	Ensure p < q
	#
	if (Math::BigInteger::cmp($p, $q) >= 0)
	{
		my $t = $p;
		$p = $q;
		$q = $t;
	}

	my $t1 = $p; $t1--;
	my $t2 = $q; $t2--;

	# phi(n) = (p-1)*(q-1)
	my $phi = new Math::BigInteger;
	Math::BigInteger::mul($phi, $t1, $t2);

	# G(n) = gcd(p-1,q-1)
	my $gcdphi = new Math::BigInteger;
	Math::BigInteger::gcd($gcdphi, $t1, $t2);

	# F(n) = phi(n)/G(n)
	Math::BigInteger::div($t1, $t2, $phi, $gcdphi);

	my $one = new Math::BigInteger 1;
	# Set E to default starting point - NB MUST BE ODD!!!
	$e = new Math::BigInteger 3 unless ref($e);
	# Try odd Es until we get one
	for (;;)
	{
		Math::BigInteger::gcd($t2, $e, $phi);
		last if (Math::BigInteger::cmp($t2, $one) == 0);
		$e++; $e++;
	}

	# Compute d so that (e*d) mod F(n) = 1
	my $d = new Math::BigInteger;
	Math::BigInteger::inverse_modn($d, $e, $t1);

	# Compute u so that (p*u) mod q = 1
	my $u = new Math::BigInteger;
	Math::BigInteger::inverse_modn($u, $p, $q);

	#	n = p * q
	my $n = new Math::BigInteger;
	Math::BigInteger::mul($n, $p, $q);

	my $sk = new Crypt::RSASecretKeyPair($n, $e, $d, $p, $q, $u);
	return $sk unless ref($sk);

	my $err = $sk->test();
	defined $err && return $err;

	$sk;
}


#
#	Generate P and Q for an n-bit N
#	When complete, called deriveKeys and return the RSASecretKeyPair.
#	An optional bit of code can be passed as a third parameter
#	which is called for every random prime that is tried
#
sub generateKeys
{
	my $ris = shift;
	my $nbits = shift;
	my $cb = shift;

	ref($ris) || return "random-input-stream missing";

	#
	# What is the minimum?
	# I know the code will break sometime around here,
	# but I'm not exactly sure at what minimum.
	#
	if ($nbits < 16)
	{
		warn("Number of bits too small ($nbits)");
		return;
	}

	#
	#	P and Q must be the same length, since PGP needs it
	#
	my $pbits = int(($nbits) / 2);
	my $qbits = int(($nbits) / 2);

	my $p;
	my $q;

	#
	#	Two ways of doing this - random try each time or
	#	incementing last try by two
	#

	$p = Math::Random::randomSpecial($ris, $pbits, "11", "1");
	do {
		$p--; $p--;
		defined($cb) && &{$cb}(0);
	} while (!Math::TestPrime::isPrime($p));

	$q = Math::Random::randomSpecial($ris, $qbits, "11", "1");
	do {
		$q--; $q--;
		defined($cb) && &{$cb}(1);
	} while (!Math::TestPrime::isPrime($q));

#	do {
#		defined($cb) && &{$cb}(0);
#		$p = Math::Random::randomSpecial($ris, $pbits, "11", "1");
#	} while (!Math::TestPrime::isPrime($p));
#
#	do {
#		defined($cb) && &{$cb}(1);
#		$q = Math::Random::randomSpecial($ris, $qbits, "11", "1");
#	} while (!Math::TestPrime::isPrime($q));

	my $e = new Math::BigInteger 17;
	my $sk = Crypt::RSAKeyGen::deriveKeys($p, $q, $e);

	$sk;
}

1;
