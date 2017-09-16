
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::RSASecretKeyPair;

use Crypt::RSAKey;
@ISA = qw( Crypt::RSAKey );

use strict;

use Crypt::RSAPublicKey;

sub new
{
	my $type = shift; my $self = {}; bless $self;

	$self->{'n'} = shift->clone();
	$self->{'e'} = shift->clone();
	$self->{'d'} = shift->clone();
	$self->{'p'} = shift->clone();
	$self->{'q'} = shift->clone();
	$self->{'u'} = shift->clone();

	my $r = $self->insane();
	return $r if $r;

	$self;
}

sub d { shift->{'d'}; }
sub p { shift->{'p'}; }
sub q { shift->{'q'}; }
sub u { shift->{'u'}; }

sub publicKey
{
	my $self = shift;
	new Crypt::RSAPublicKey $self->{'n'}, $self->{'e'};
}

sub crypt
{
	my $self = shift;
	my $key = shift;
	my $msg = shift;

	my $p = $self->{'p'};
	my $q = $self->{'q'};
	my $u = $self->{'u'};

	my $zero = new Math::BigInteger;
	my $r = new Math::BigInteger;
	my $p1 = $p;
	my $q1 = $q;
	$p1--;
	$q1--;
	my $dmp1 = new Math::BigInteger;
	my $dmq1 = new Math::BigInteger;
	Math::BigInteger::mod($dmp1, $key, $p1);
	Math::BigInteger::mod($dmq1, $key, $q1);

	my $iqmp = new Math::BigInteger;
	Math::BigInteger::inverse_modn($iqmp, $q, $p);

	my $m1 = new Math::BigInteger;
	my $r1 = new Math::BigInteger;

	#
	# Return value of BigInteger methods not properly defined
	# with later Perl.
	#

	# m1 = ((msg mod p) ^ dmq1) ) mod p
	Math::BigInteger::mod($r1, $msg, $p);
	Math::BigInteger::mod_exp($m1, $r1, $dmp1, $p);

	# r = ((msg mod q) ^ dmp1) ) mod q
	Math::BigInteger::mod($r1, $msg, $q);
	Math::BigInteger::mod_exp($r, $r1, $dmq1, $q);

	Math::BigInteger::sub($r1, $r, $m1);
	if (Math::BigInteger::cmp($r1, $zero) < 0) { Math::BigInteger::add($r1, $r1, $q); }

	Math::BigInteger::mul($r, $r1, $u);
	Math::BigInteger::mod($r1, $r, $q);
	Math::BigInteger::mul($r, $r1, $p);
	Math::BigInteger::add($r1, $r, $m1);

	$r1;
}

sub publicEncrypt
{
	my $self = shift;
	my $msg = shift;

	$self->crypt($self->{'e'}, $msg);
}

sub privateEncrypt
{
	my $self = shift;
	my $msg = shift;

	$self->crypt($self->{'d'}, $msg);
}

#
#	This is a duplicate - why is it here?
#
sub decrypt
{
	my $self = shift;
	my $msg = shift;

	$self->crypt($self->{'d'}, $msg);
}

#
#	A bit of sanity checking ...
#	Returns undef if insane
#
sub insane
{
	my $self = shift;

	my $one = new Math::BigInteger;
	$one++;

	#
	#	First check pq == n
	#
	my $t = new Math::BigInteger;
	Math::BigInteger::mul($t, $self->{'p'}, $self->{'q'});
	return "pq != n" if (Math::BigInteger::cmp($self->{'n'}, $t));

	#
	#	and now check (p < q)
	#
	return "p >= q" unless (Math::BigInteger::cmp($self->{'p'}, $self->{'q'}) < 0);

	#
	#	and now check (p*u) mod q = 1, (assuming p<q)
	#
	Math::BigInteger::mul_mod($t, $self->{'p'}, $self->{'u'}, $self->{'q'});
	return "(p*u) mod q != 1" if Math::BigInteger::cmp($one, $t);

	undef;
}

sub test
{
	my $self = shift;

	my $sanity = $self->insane();
	defined $sanity || return $sanity;

	#
	#	Now do a signature/verification
	#
	my $i = 0;
	my $data = '';
	for ($i = 0; $i < 16; $i++)
	{
		$data .= pack("C", 7 + ($i * 3));
	}
	my $msg = restore Math::BigInteger $data;
	my $encmsg = $self->privateEncrypt($msg);
	my $msg2 = $self->publicEncrypt($encmsg);
	if ($data ne $msg2->save())
	{
		return "Key test failed\nmsg = $msg\nedmsg=$msg2";
	}
	undef;
}

sub asString
{
	my $self = shift;

	my $n = $self->{'n'};
	my $e = $self->{'e'};
	my $d = $self->{'d'};
	my $p = $self->{'p'};
	my $q = $self->{'q'};
	my $u = $self->{'u'};
			
	my $retval = "n: $n\n";
	$retval .= "e: $e\n";

	#
	#	Shouldn't really store these confidential ones ...
	#
	$retval .= "d: $d\n";
	$retval .= "p: $p\n";
	$retval .= "q: $q\n";
	$retval .= "u: $u\n";

	$retval;
}

1;
