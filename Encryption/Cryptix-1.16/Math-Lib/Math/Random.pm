
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Math::Random;

use strict;
use integer;

use Math::BigInteger;
use Math::TestPrime;


sub randomBigInteger
{
	my $ris = shift;
	my $bits = shift;

	return "random-input-stream missing" unless ref($ris);

	my $bytes = 1 + int(($bits-1)/8);
	my $d = $ris->read($bytes);

	my $msb = ord(substr($d, 0, 1));
	$msb &= (0xFF >> (8 - (($bits-1) % 8)));
	$msb |= (1 << (($bits-1) % 8));
	substr($d, 0, 1) = pack("C", $msb);

	restore Math::BigInteger $d;
}

sub randomOdd
{
	my $ris = shift;
	my $bits = shift;

	return "random-input-stream missing" unless ref($ris);

	my $bytes = 1 + int(($bits-1)/8);
	my $d = $ris->read($bytes);

	my $msb = ord(substr($d, 0, 1));
	$msb &= (0xFF >> (8 - (($bits-1) % 8)));
	$msb |= (1 << (($bits-1) % 8));
	substr($d, 0, 1) = pack("C", $msb);

	my $lsb = ord(substr($d, -1, 1));
	$lsb |= 0x01;
	substr($d, -1, 1) = pack("C", $lsb);

	restore Math::BigInteger $d;
}

#
#	Return a random number with hbits as most significant bits
#	and lbits as least significant bits
#	The hbits and lbits parameters are binary strings.
#	NB - This will not work correctly for small (eg 8 bit) numbers
#
sub randomSpecial
{
	my $ris = shift;
	my $bits = shift;
	my $hbits = shift;
	my $lbits = shift;

	return "random-input-stream missing" unless ref($ris);

	my $mbits = $bits;
	$mbits -= length($lbits);
	$mbits -= length($hbits);
	my $mbytes = 1 + int(($mbits-1)/8);

	my $mb = unpack("B*", $ris->read($mbytes));
	$mb = substr($mb, 0, $mbits);
	my $n = $hbits.$mb.$lbits;
	if (($bits % 8) != 0)
	{
		$n = substr("0000000", 0, 8 - ($bits % 8)) . $n;
	}
	restore Math::BigInteger pack("B*", $n);
}



#
#	The following need tidying up
#
#	Where am I using them? (Gary)
#


sub random3
{
	my $ris = shift;
	my $bits = shift;

	return "random-input-stream missing" unless ref($ris);

	randomSpecial($bits, "11", "1");
}

sub randomPrime
{
	my $ris = shift;
	my $bits = shift;

	return "random-input-stream missing" unless ref($ris);

	for(;;)
	{
		my $n = random3($bits);
#		do {
			return $n if isPrime($n);
#			$n->inc();
#			$n->inc();
#		} while ($n->bits() == $bits);
	}
}

1;
