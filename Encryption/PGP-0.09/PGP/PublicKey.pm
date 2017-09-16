#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::PublicKey;

use Crypt::RSAPublicKey;      
use Stream::Streamable;      
@ISA = qw( Stream::Streamable Crypt::RSAPublicKey );


use strict;

use Math::MPI;
use Crypt::MD5;


sub n { shift->{'n'}; }
sub e { shift->{'e'}; }

sub new
{
	my $class = shift; my $self = {}; bless $self, $class;

	my $n = shift;
	my $e = shift;
	return "$n - not a reference" unless ref($n);
	return "$e - not a reference" unless ref($e);

	$self->{'n'} = $n;
	$self->{'e'} = $e;

	$self;
}

sub restoreFromDataStream
{
	my $class = shift;
	my $dis = shift;

	my $n = restoreFromDataStream Math::MPI $dis; return $n unless ref($n);
	my $e = restoreFromDataStream Math::MPI $dis; return $e unless ref($e);

	$n = $n->asBigInteger(); return $n unless ref($n);
	$e = $e->asBigInteger(); return $e unless ref($e);

	new PGP::PublicKey $n, $e;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	my $n = new Math::MPI $self->n();
	my $e = new Math::MPI $self->e();

	$n->saveToDataStream($dos);
	$e->saveToDataStream($dos);
}

sub id
{
    my $self = shift;

	substr($self->n()->save(), -8, 8);
}

sub fingerprint
{
	my $self = shift;
	Crypt::MD5->hash($self->n()->save().$self->e()->save());
}

sub asString
{   
    my $self = shift;

    my $n = $self->n();
    my $e = $self->e();
    my $fingerprint = $self->fingerprint();
	 
	my $retval = '';
	$retval .= "  N = $n\n";
	$retval .= "  E = $e\n";
	$retval .= "  Fingerprint = $fingerprint\n";
}

1;
