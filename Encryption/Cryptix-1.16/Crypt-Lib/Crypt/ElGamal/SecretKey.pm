#
# Copyright (C) 1997 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

package Crypt::ElGamal::SecretKey;

use Crypt::ElGamal::PublicKey;
@ISA = qw( Crypt::ElGamal::PublicKey );

use strict;
use integer;

use Math::BigInteger;
use Math::Random;

# The secret component
sub x { shift->{'x'}; }

#
# Create a new secret key
#
sub new
{
	my $class = shift; my $self = {}; bless $self, $class;

	$self->{'p'} = shift->clone();
	$self->{'g'} = shift->clone();
	$self->{'y'} = shift->clone();
	$self->{'x'} = shift->clone();

	$self;
}

#
# Create a public key from this secret key
#
sub publicKey
{
	my $self = shift;
	new Crypt::ElGamal::PublicKey $self->{'p'}, $self->{'g'}, $self->{'y'};
}

#
# Decrypt a ciphertext object
# Usage: $key->decrypt(ciphertext)
# Returns the plaintext
#
sub decrypt
{
	my $self = shift;
	my $ciphertext = shift;

	my $a = $ciphertext->[0];
	my $b = $ciphertext->[1];

	# M (plaintext) = b/a**x mod p
	my $msg = new Math::BigInteger;
	my $t1 = new Math::BigInteger;
	my $t2 = new Math::BigInteger;
	Math::BigInteger::mod_exp($t1, $a, $self->{'x'}, $self->{'p'});
	Math::BigInteger::inverse_modn($t2, $t1, $self->{'p'});
	Math::BigInteger::mul_mod($msg, $b, $t2, $self->{'p'});

	$msg;
}

#
# Sign a message
# Usage: $key->sign($random_stream, $msg)
# Returns a signature object (a two element anonymous array)
#
sub sign
{
	my $self = shift;
	my $ris = shift;
	my $msg = shift;

	# Choose a random k relatively prime to p-1
	my $k = $self->random_k($ris);

	# a (signature) = g**k mod p
	my $a = new Math::BigInteger;
	Math::BigInteger::mod_exp($a, $self->{'g'}, $k, $self->{'p'});

	# b (signature) such that M = (xa + kb) mod (p-1) (using extended Euclid)
	my $b = new Math::BigInteger;
	my $t1 = new Math::BigInteger;
	my $t2 = new Math::BigInteger;
	my $zero = new Math::BigInteger;
	my $p1 = $self->{'p'};
	$p1--;
	Math::BigInteger::mul_mod($t1, $self->{'x'}, $a, $p1);
	Math::BigInteger::sub($t2, $msg, $t1);
	Math::BigInteger::mod($t1, $t2, $p1);
	while (Math::BigInteger::cmp($t1, $zero) == -1)
	{
		Math::BigInteger::add($t1, $t1, $p1);
	}
	Math::BigInteger::inverse_modn($t2, $k, $p1);
	Math::BigInteger::mul_mod($b, $t1, $t2, $p1);

	[ $a, $b ];
}

1;
