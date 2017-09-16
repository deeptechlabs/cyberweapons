#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.4 $
# $State: Release_0_09 $
#

package PGP::KeyRingEntry;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

use PGP::KeyRingTrust;
use PGP::PacketFactory;

# This should really be a factory class
use PGP::PublicKeyRingEntry;
use PGP::SecretKeyRingEntry;


sub key			{ my $key = shift->{'key'}; ref $key || die "Undefined key ($key)"; $key; }
sub key_trust	{ shift->{'key_trust'}; }
sub ids			{ shift->{'ids'}; }
sub sigs		{ shift->{'sigs'}; }
sub id			{ shift->key()->id(); }
sub fingerprint	{ shift->key()->fingerprint(); }
sub publicKey	{ shift->key()->publicKey(); }

# For clarity
sub cert		{ shift->key(); }

sub new
{
	my $class = shift; my $self = {}; bless $self, $class;
	$self->{'key'} = shift;
	my $key_trust = shift;

	my $key_flags = 2;	# What is the default?
	$key_flags = $key_trust->flags() if (defined $key_trust);

	$self->{'key_trust'} = $key_flags;
	$self->{'ids'} = [];
	$self->{'sigs'} = [];
	$self;
}

sub addId
{
	my $self = shift;
	my $id = shift;
	my $id_trust = shift;

	my $id_flags = 3;	# What is the default?
	$id_flags = $id_trust->flags() if (defined $id_trust);

	push @{$self->ids()}, { 'id' => $id, 'flags' => $id_flags };
}

sub addSignature
{
	my $self = shift;
	my $sig = shift;

	push @{$self->{'sigs'}}, $sig;
}

sub hasId
{
	my $self = shift;
	my $id = shift;

	foreach (@{$self->ids()})
	{
		return 1 if ($_->{'id'}->id() =~ m/$id/);
	}
	undef;
}

sub hasExactId
{
	my $self = shift;
	my $id = shift;

	foreach (@{$self->ids()})
	{
		return 1 if ($_->{'id'}->id() eq $id);
	}
	undef;
}

sub restoreFromDataStream
{
	my $type = shift;
	my $dis = shift;

	my $self;

	my $packet = PGP::PacketFactory::restore($dis);
	ref $packet || return "Could not read first PGP packet";

	#
	#	Read the public/secret certificate
	#
	# This should really be a factory class
	#
	my $key = $packet;
	my $id;
	if (ref($packet) eq "PGP::PublicKeyCertificate")
	{
		$packet = PGP::PacketFactory::restore($dis);

		my $key_trust = undef;
		if (ref($packet) eq "PGP::KeyRingTrust")
		{
			$key_trust = $packet;
			$packet = PGP::PacketFactory::restore($dis);
		}

		$id = $key->publicKey()->id();
		defined $id || die "Could not get key id";
		$self = new PGP::PublicKeyRingEntry $key, $key_trust;
	}
	elsif (ref($packet) eq "PGP::SecretKeyCertificate")
	{
		$packet = PGP::PacketFactory::restore($dis);

		my $key_trust = undef;
		if (ref($packet) eq "PGP::KeyRingTrust")
		{
			$key_trust = $packet;
			$packet = PGP::PacketFactory::restore($dis);
		}

		$id = $key->publicKey()->id();
		defined $id || die "Could not get key id";
		$self = new PGP::SecretKeyRingEntry $key, $key_trust;
	}
	else
	{
		die "Bad format public key ring (".ref($packet).")";
	}

	#
	#	Check for a possible revocation
	#
	if (ref($packet) eq "PGP::Signature")
	{
		if ($packet->isRevocation())
		{
			$packet = PGP::PacketFactory::restore($dis);
			last unless defined $packet;
			return $packet unless ref $packet;
		}
		else
		{
			my $c = $packet->classification();
			return "Bad format public key ring (signature on key, not user-id) (classification = $c)";
		}
	}

	#
	#	Read the user IDs
	#
	while (ref($packet) eq "PGP::UserId")
	{
		my $idp = $packet;
		my $id_trust;

		$packet = PGP::PacketFactory::restore($dis);

		$id_trust = undef;
		if (defined $packet) # If we are cut short, do what we can
		{
			return "Corrupt keyring entry ($packet)" unless ref $packet;

			if (ref($packet) eq "PGP::KeyRingTrust")
			{
				$id_trust = $packet;
				$packet = PGP::PacketFactory::restore($dis);
			}
			else
			{
				$id_trust = new PGP::KeyRingTrust;
			}
		}

		$self->addId($idp, $id_trust);

		#
		# Now we should look for some comment/signature packets
		# Do it later ...
		while (defined ($packet))
		{
			last if (ref($packet) eq "PGP::PublicKeyCertificate"
					or ref($packet) eq "PGP::SecretKeyCertificate");
			$packet = PGP::PacketFactory::restore($dis);
			last unless defined $packet;
			return $packet unless ref $packet;

			if (ref($packet) eq "PGP::Signature")
			{
				$self->addSignature($packet);
			}
		}
	}

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	PGP::PacketFactory::save($dos, $self->key());
	PGP::PacketFactory::save($dos, new PGP::KeyRingTrust $self->{'key_trust'});

	foreach (@{$self->ids()})
	{
		my $id = $_;
		PGP::PacketFactory::save($dos, $id->{'id'});
		PGP::PacketFactory::save($dos, new PGP::KeyRingTrust $id->{'flags'});
	}
}

sub asString
{
	my $self = shift;

	my $keyid = unpack("H*", $self->key()->publicKey()->id());
	my $retval = "Key id: $keyid\n";

	foreach (@{$self->ids()})
	{
		my $id = $_;
		$retval .= "User id: " . $id->{'id'}->asString() . "\n";
	}

	foreach (@{$self->sigs()})
	{
		my $sig = $_;
		$retval .= "Signature: ". $sig->asString(). "\n";
	}

	$retval .= $self->key()->asString();
	$retval
}

1;
