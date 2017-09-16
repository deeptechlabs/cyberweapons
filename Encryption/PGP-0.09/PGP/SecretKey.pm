#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::SecretKey;

use Stream::Streamable;
use PGP::PublicKey;
use Crypt::RSASecretKeyPair;
@ISA = qw( Stream::Streamable Crypt::RSASecretKeyPair PGP::PublicKey );

use strict;

use Math::MPI;
use Crypt::RSAKeyGen;


sub new
{
	my $type = shift; my $self = {}; bless $self;

	my $n = shift;
	my $e = shift;
	my $d = shift;
	my $p = shift;
	my $q = shift;
	my $u = shift;

	ref($n) || return "$n not a reference";
	ref($e) || return "$e not a reference";
	ref($d) || return "$d not a reference";
	ref($p) || return "$p not a reference";
	ref($q) || return "$q not a reference";
	ref($u) || return "$u not a reference";

	$self->{'n'} = $n;
	$self->{'e'} = $e;
	$self->{'d'} = $d;
	$self->{'p'} = $p;
	$self->{'q'} = $q;
	$self->{'u'} = $u;

	my $r = $self->insane();
	return $r if $r;

	$self;
}

sub generate
{
	my $class = shift;
	my %args = @_;

	my $ris = $args{'-ris'};
	ref $ris || return "-ris argument missing";

	my $size = $args{'-size'};
	defined $size || return "-size argument missing";

	my $cb = $args{'-cb'};

	my $sk = Crypt::RSAKeyGen::generateKeys($ris, $size, $cb);
	ref($sk) || return $sk;

	newFromSecretKey $class $sk;
}

sub newFromSecretKey
{
	my $type = shift; my $self = {}; bless $self;

	my $sk = shift;
	ref($sk) || return "$sk argument missing";

	$self->{'n'} = $sk->n();
	$self->{'e'} = $sk->e();
	$self->{'d'} = $sk->d();
	$self->{'p'} = $sk->p();
	$self->{'q'} = $sk->q();
	$self->{'u'} = $sk->u();

	my $r = $self->insane();
	return $r if $r;

	$self;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self;
	my $dis = shift;

	my $n = restoreFromDataStream Math::MPI $dis; ref($n) || return $n;
	my $e = restoreFromDataStream Math::MPI $dis; ref($e) || return $e;
	my $d = restoreFromDataStream Math::MPI $dis; ref($d) || return $d;
	my $p = restoreFromDataStream Math::MPI $dis; ref($p) || return $p;
	my $q = restoreFromDataStream Math::MPI $dis; ref($q) || return $q;
	my $u = restoreFromDataStream Math::MPI $dis; ref($u) || return $u;

	$self->{'n'} = $n->asBigInteger();
	$self->{'e'} = $e->asBigInteger();
	$self->{'d'} = $d->asBigInteger();
	$self->{'p'} = $p->asBigInteger();
	$self->{'q'} = $q->asBigInteger();
	$self->{'u'} = $u->asBigInteger();

	my $r = $self->insane();
	return $r if $r;

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	my $n = new Math::MPI $self->{'n'};
	my $e = new Math::MPI $self->{'e'};
	my $d = new Math::MPI $self->{'d'};
	my $p = new Math::MPI $self->{'p'};
	my $q = new Math::MPI $self->{'q'};
	my $u = new Math::MPI $self->{'u'};

	$n->saveToDataStream($dos);
	$e->saveToDataStream($dos);
	$d->saveToDataStream($dos);
	$p->saveToDataStream($dos);
	$q->saveToDataStream($dos);
	$u->saveToDataStream($dos);
}

sub display
{
	my $self = shift;

	my $n = $self->{'n'};
	my $e = $self->{'e'};
	my $d = $self->{'d'};
	my $p = $self->{'p'};
	my $q = $self->{'q'};
	my $u = $self->{'u'};

	print "n: \t$n\n";
	print "e: \t$e\n";

	#
	#	Shouldn't really display these confidential ones ...
	#
	print "d: \t$d\n";
	print "p: \t$p\n";
	print "q: \t$q\n";
	print "u: \t$u\n";
}

1;
