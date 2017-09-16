#
# Copyright (C) 1997 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

package Crypt::DSA::SecretKey;

use Crypt::DSA::PublicKey;
@ISA = qw( Crypt::DSA::PublicKey );

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
	new Crypt::DSA::PublicKey $self->{'p'}, $self->{'g'}, $self->{'y'};
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

	[ $r, $s ];

	if (self.q<=K):
	    raise error, 'K is greater than q'
        r=pow(self.g, K, self.p) % self.q
        s=(Inverse(K, self.q)*(M+self.x*r)) % self.q
}

1;
