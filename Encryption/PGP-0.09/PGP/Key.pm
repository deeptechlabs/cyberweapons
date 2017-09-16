#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::Key;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

use PGP::PacketFactory;


sub cert		{ shift->{'cert'}; }
sub ids			{ @{shift->{'ids'}}; }
sub id			{ shift->cert()->id(); }
sub fingerprint	{ shift->cert()->fingerprint(); }
sub publicKey	{ shift->cert()->publicKey(); }


sub new
{
	my $class = shift; my $self = {}; bless $self, $class;
	my %args = @_;

	$self->{'cert'} = $args{'-cert'};
	if (defined $args{'-ids'})
	{
		$self->{'ids'} = [ @{$args{'-ids'}} ];
	}
	else
	{
		$self->{'ids'} = [];
	}
	$self;
}

sub addId
{
	my $self = shift;
	my $id = shift;

	push @{$self->{'ids'}}, $id;
}

sub hasId
{
	my $self = shift;
	my $id = shift;

	foreach ($self->ids())
	{
		return 1 if ($_->{'id'}->id() =~ m/$id/);
	}
	undef;
}

sub hasExactId
{
	my $self = shift;
	my $id = shift;

	foreach ($self->ids())
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
	my $cert = $packet;
	my $id;
	if (ref($packet) eq "PGP::PublicKeyCertificate")
	{
		$packet = PGP::PacketFactory::restore($dis);

		$id = $cert->publicKey()->id();
		$self = new PGP::Key ('-cert' => $cert);
	}
	elsif (ref($packet) eq "PGP::SecretKeyCertificate")
	{
		$packet = PGP::PacketFactory::restore($dis);

		$id = $cert->publicKey()->id();
		$self = new PGP::Key ('-cert' => $cert);
	}
	else
	{
		return "Bad format public key ring (".ref($packet).")";
	}

	#
	#	Read the user IDs
	#
	while (ref($packet) eq "PGP::UserId")
	{
		my $idp = $packet;

		$self->addId($idp);

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
		}
	}

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	PGP::PacketFactory::save($dos, $self->cert());

	foreach ($self->ids())
	{
		PGP::PacketFactory::save($dos, $_);
	}
}

sub asString
{
	my $self = shift;

	my $keyid = unpack("H*", $self->cert()->publicKey()->id());
	my $retval = "Key id: $keyid\n";

	foreach ($self->ids())
	{
		my $id = $_;
		$retval .= "User id: " . $id->{'id'}->asString() . "\n";
	}

	$retval .= $self->cert()->asString();
	$retval
}

1;
