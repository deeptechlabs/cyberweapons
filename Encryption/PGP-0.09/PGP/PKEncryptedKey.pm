#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::PKEncryptedKey;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

use Math::MPI;
use PGP::DEK;


sub key_id { shift->{'key_id'}; }
sub alg { shift->{'alg'}; }
sub version { shift->{'version'}; }


sub new
{   
	my $type = shift; my $self = {}; bless $self, $type;
	my $pk = shift;
	my $key = shift;
	my $ris = shift;

	ref($ris) || return "random-input-stream parameter missing";

	$self->{'version'} = 2;
	$self->{'alg'} = 1;

	my $dek = PGP::DEK::encode($key, $pk->size(), $ris);
	ref($dek) || return $dek;

	$self->{'key_id'} = $pk->id();
	$self->{'c'} = $pk->crypt($dek);

	$self;
}

sub restoreFromDataStream
{   
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;


	my $version = $dis->readByte();
	($version == 2 || $version == 3) || return "Unsupported version ($version)";

	$self->{'key_id'} = $dis->read(8);

	my $alg = $dis->readByte();
	($alg == 1) || return "Unsupported public key algorithm ($alg)";

	my $mpi = restoreFromDataStream Math::MPI $dis;
	ref($mpi) || return "Could not read MPI ($mpi)";

	$self->{'c'} = $mpi->asBigInteger();
	$self->{'version'} = $version;
	$self->{'alg'} = $alg;

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;
	   
	my $c = new Math::MPI $self->{'c'};

	$dos->writeByte($self->version());
	$dos->write($self->{'key_id'});
	$dos->writeByte($self->alg());
	$c->saveToDataStream($dos);
}

sub decrypt
{
	my $self = shift;
	my $sk = shift;

	my $id = $self->key_id();
	if ($sk->id() ne $id)
	{
		my $id_asc = unpack("H*", $id);
		my $skid_asc = unpack("H*", $sk->id());
		return (undef, "Invalid secret key (key id is $id_asc, message expects $skid_asc)");
	}

	my ($key, $err);
	($key, $err) = PGP::DEK::decode($sk->decrypt($self->{'c'}));
	if (defined $err)
	{
		return (undef, "Bad DEK in public key encrypted packet ($err)");
	}

	($key, undef);
}

sub asString
{
	my $self = shift;

	#
	# algorithm byte (is 1 for RSA)
	#
	(
		"alg:".$self->{'alg'},
		"ciphertext:".unpack("H*", $self->{'c'}->save())
	);
}

1;
