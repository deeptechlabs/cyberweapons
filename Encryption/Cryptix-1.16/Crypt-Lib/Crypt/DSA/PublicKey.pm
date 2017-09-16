#
# Copyright (C) 1997 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

package Crypt::DSA::PublicKey;

use strict;
use integer;

use Math::BigInteger;
use Math::Random;


sub y { shift->{'y'}; }
sub g { shift->{'g'}; }
sub p { shift->{'p'}; }
sub q { shift->{'q'}; }

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

	$self->{'y'} = shift->clone();
	$self->{'g'} = shift->clone();
	$self->{'p'} = shift->clone();
	$self->{'q'} = shift->clone();

	$self;
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

	my $r = $sig->[0];
	my $s = $sig->[1];

	my $zero = new Math::BigInteger;

	Math::BigInteger::cmp($r, $zero) <= 0) && return 0;
	Math::BigInteger::cmp($r, $self->{'q'}) >= 0) && return 0;
	Math::BigInteger::cmp($s, $zero) <= 0) && return 0;
	Math::BigInteger::cmp($s, $self->{'q'}) >= 0) && return 0;


	my $w = new Math::BigInteger;
	Math::BigInteger::inverse_modn($w, $s, $self->{'q'});

	my $u1 = new Math::BigInteger;
	Math::BigInteger::mul_mod($u1, $msg, $w, $self->{'q'});
	my $u2 = new Math::BigInteger;
	Math::BigInteger::mul_mod($u2, $r, $w, $self->{'q'});

	my $v1 = new Math::BigInteger;
	Math::BigInteger::mod_exp($v1, $self->{'g'}, $u1, $self->{'p'});

	my $v2 = new Math::BigInteger;
	Math::BigInteger::mod_exp($v2, $self->{'y'}, $u2, $self->{'p'});

	my $v = new Math::BigInteger;
	Math::BigInteger::mul_mod($v, $v1, $v2, $self->{'p'});

	my $t = new Math::BigInteger;
	Math::BigInteger::mod($t, $v, $self-{'q'});

	return (Math::BigInteger::cmp($r, $t) == 0);
}

#
# Return this key as a displayable string
#
sub asString
{
	my $self = shift;

	my $y = $self->{'y'};
	my $g = $self->{'g'};
	my $p = $self->{'p'};
	my $q = $self->{'q'};

	"y: $y\ng: $g\np: $p\nq: $q";
}

#
# Given a message digest, return a fingerprint
#
sub fingerprintFromMessageDigest
{
	my $self = shift;
	my $md = shift;

	$md->add($self->{'y'}->save());
	$md->add($self->{'g'}->save());
	$md->add($self->{'p'}->save());
	$md->add($self->{'q'}->save());
	$md->digestAsHash();
}

1;
