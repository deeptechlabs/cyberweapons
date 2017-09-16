#
# Copyright (C) 1997 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

package Crypt::ElGamal::PublicKey;

use strict;
use integer;

use Math::BigInteger;
use Math::Random;


sub p { shift->{'p'}; }
sub g { shift->{'g'}; }
sub y { shift->{'y'}; }

#
#	Returns the number of bits in P
#
sub bits { shift->{'p'}->bits(); }

#
#	Returns the number of bytes in P
#		(NB. These are not all usuable for encryption - always
#		set the first byte (MSB) to zero).
#
sub size { int((shift->{'p'}->bits())/8); }


#
# Create a new public key
#
sub new
{
	my $class = shift; my $self = {}; bless $self, $class;

	$self->{'p'} = shift->clone();
	$self->{'g'} = shift->clone();
	$self->{'y'} = shift->clone();

	$self;
}

#
# Encrypt a message
# Usage: $key->encrypt($random_stream, $msg);
# Returns a ciphertext object (a two element anonymous array)
#
sub encrypt
{
	my $self = shift;
	my $ris = shift;
	my $msg = shift;

	# Choose a random k relatively prime to p-1
	my $k = $self->random_k($ris);

	# a (ciphertext) = g**k mod p
	my $a = new Math::BigInteger;
	Math::BigInteger::mod_exp($a, $self->{'g'}, $k, $self->{'p'});

	# b (ciphertext) = y**k * M mod p
	my $b = new Math::BigInteger;
	my $t = new Math::BigInteger;
	Math::BigInteger::mod_exp($t, $self->{'y'}, $k, $self->{'p'});
	Math::BigInteger::mul_mod($b, $t, $msg, $self->{'p'});

	# a and b make the ciphertext
	return [ $a, $b ];
}

#
# Verify a signature
# Usage: $key->verify($message, $signature);
# Returns true if signature is valid
#
sub verify
{
	my $self = shift;
	my $msg = shift;
	my $sig = shift;

	my $a = $sig->[0];
	my $b = $sig->[1];

	# y**a * a**b mod p
	my $t1 = new Math::BigInteger;
	Math::BigInteger::mod_exp($t1, $self->{'y'}, $a, $self->{'p'});
	my $t2 = new Math::BigInteger;
	Math::BigInteger::mod_exp($t2, $a, $b, $self->{'p'});
	my $t3 = new Math::BigInteger;
	Math::BigInteger::mul_mod($t3, $t1, $t2, $self->{'p'});

	# g**M mod p
	Math::BigInteger::mod_exp($t1, $self->{'g'}, $msg, $self->{'p'});

	return (Math::BigInteger::cmp($t1, $t3) == 0);
}

#
# Returns a random number relatively prime to p-1
# and between 1 and 64 bits shorter than p
#
sub random_k
{
	my $self = shift;
	my $ris = shift;

	my $p = $self->{'p'};
	my $p1 = $p;
	$p1--;

	# Create a random number between 1 and 64 bits shorter than p
	my $bits = $p->bits();
	$bits -= (1 + ord($ris->read(1)) % 64);
	my $k = Math::Random::randomSpecial($ris, $bits, "1", "1");

	#
	# Find the first relatively prime to p-1 (counting down)
	#
	my $one = new Math::BigInteger 1;
	my $r = new Math::BigInteger;
	do {
		$k--; $k--;
		Math::BigInteger::gcd($r, $k, $p1);
	} while (Math::BigInteger::cmp($r, $one) != 0);

	$k;
}

#
# Return this key as a displayable string
#
sub asString
{
	my $self = shift;

	my $p = $self->{'p'};
	my $g = $self->{'g'};
	my $y = $self->{'y'};

	"p: $p\ng: $g\ny: $y";
}

#
# Given a message digest, return a fingerprint
#
sub fingerprintFromMessageDigest
{
	my $self = shift;
	my $md = shift;

	$md->add($self->{'p'}->save());
	$md->add($self->{'g'}->save());
	$md->add($self->{'y'}->save());
	$md->digestAsHash();
}

1;
