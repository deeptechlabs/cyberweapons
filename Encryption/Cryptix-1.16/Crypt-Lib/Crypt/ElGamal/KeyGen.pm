#
# Copyright (C) 1997 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

package Crypt::ElGamal::KeyGen;

use strict;
use integer;

use Math::BigInteger;
use Math::Random;
use Crypt::ElGamal::SecretKey;


sub createKey
{
	my $ris = shift;
	my $keylen = shift;
	my $cb = shift;

	my $p = Math::Random::randomSpecial($ris, $keylen, "1", "1");
	do {
		$p--; $p--;
		defined($cb) && &{$cb}(0);
	} while (!Math::TestPrime::isPrime($p));


	# g is a random number between 1 and 64 bits shorter than p
	my $bits = $keylen - (1 + ord($ris->read(1)) % 64);
	my $g = Math::Random::randomSpecial($ris, $bits, "1", "1");

	# x is a random number between 1 and 256 bits shorter than p
	$bits = $keylen - (1 + ord($ris->read(1)));
	my $x = Math::Random::randomSpecial($ris, $bits, "1", "1");

	# y = g**x mod p
	my $y = new Math::BigInteger;
	Math::BigInteger::mod_exp($y, $g, $x, $p);

	return new Crypt::ElGamal::SecretKey $p, $g, $y, $x;
}

1;
