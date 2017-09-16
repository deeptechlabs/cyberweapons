#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.4 $
# $State: Release_0_09 $
#

package PGP::KeyRing;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );


use strict;

use PGP::PacketFactory;
use PGP::PublicKeyRingEntry;
use PGP::SecretKeyRingEntry;


sub new
{
	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'keys'} = [];

	$self;
}

sub open
{
	my $class = shift;
	my $file = shift;

	defined $file || return "Missing filename";
	if (-f $file)
	{
		my $kr = restoreFromFile $class $file;
		# ref $kr && return $kr;	# Potentially dangerous, since we may overwrite corrupt keyrings
		defined $kr && return $kr;	# Return it if it is an object or an error
	}

	new $class;
}

sub update
{
	my $self = shift;
	my $file = shift;

	$self->saveToFile($file);
}

sub add
{
	my $self = shift;
	my $entry = shift;

	my $id = $entry->id();
	$self->{'keys_by_id'}{$id} = $entry->save();

	$self->{'keys_by_fingerprint'}{$entry->fingerprint()} = $id;

	foreach(@{$entry->ids()})
	{
		my $idx = $_->{'id'};
		defined $self->{'keys_by_userid'}{$idx} && die "User id \"$idx\" already in keyring";

		$self->{'keys_by_userid'}{$idx} = $id;
	}

	unshift @{$self->{'keys'}}, $id;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	$self->{'keys'} = [];

	my $next_entry;
	my $entry;
	my $entry_data;
	my $packet;
	while (defined ($packet = PGP::PacketFactory::restore($dis)))
	{
		die "Problems reading packet ($packet)" unless ref $packet;

		if (ref($packet) eq "PGP::PublicKeyCertificate")
		{
			$next_entry = "PGP::PublicKeyRingEntry";
		}
		elsif (ref($packet) eq "PGP::SecretKeyCertificate")
		{
			$next_entry = "PGP::SecretKeyRingEntry";
		}
		else
		{
			return "bad format keyring ($packet)";
		}
		$entry_data = PGP::PacketFactory::saveAsString($packet);

		while (defined ($packet = PGP::PacketFactory::restore($dis)))
		{
			die "Problems reading packet ($packet)" unless ref $packet;

			last if (ref($packet) eq "PGP::PublicKeyCertificate"
				|| ref($packet) eq "PGP::SecretKeyCertificate");

			$entry_data .= PGP::PacketFactory::saveAsString($packet);
		}

		my $entry = $next_entry->restore($entry_data);
		ref $entry || return "Failed to create key ring entry ($entry)";

		$self->add($entry);

		last unless defined $packet;

		redo;
	}

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	foreach(@{$self->{'keys'}})
	{
		$dos->write($self->{'keys_by_id'}{$_});	
	}
}

# #
# #	Get public key details
# #
# sub getKeyDetails
# {
# 	my $self = shift;
# 	my $id = shift;
# 
# 	$self->{"$id"};
# }

#
#	Get whole entry using expression
#
sub get
{
	my $self = shift;
	my $rid = shift;

	my ($userid, $id);
	while (($userid, $id) = each %{$self->{'keys_by_userid'}})
	{
#		return getById($id) if ($userid =~ m/$rid/);
		return $self->getById($id) if ($userid =~ m/$rid/);
	}
	undef;
}

sub getByHexId { my $self = shift; my $id = shift; $self->getById(pack("H*", $id)); }

#
#	Get whole entry using key id
#
sub getById
{
	my $self = shift;
	my $id = shift;

	return $self->{'keys_by_id'}{$id};
}

#
#	Get whole entry using key fingerprint
#
sub getByFingerprint
{
	my $self = shift;
	my $fp = shift;

	return $self->{'keys_by_fingerprint'}{$fp};
}

#
#	Get whole entry by exact user id
#
sub getByExactUserId
{
	my $self = shift;
	my $rid = shift;

	my $id = $self->{'keys_by_userid'}{$rid};
	defined $id || return;

	$self->getById($id);
}

#
#	Get a key certificate
#
sub getKey
{
	my $self = shift;
	my $rid = shift;

	my $key = restore PGP::KeyRingEntry $self->get($rid);
	ref $key || return $key;

	$key->key();
}

sub asString
{
	my $self = shift;

	my $retval = '';
	foreach(@{$self->{'keys'}})
	{
		my $key = restore PGP::KeyRingEntry $self->{'keys_by_id'}{$_};
		$retval .= $key->asString();
		$retval .= "\n";
	}
	$retval;
}

sub allKeysByExpression
{
	my $self = shift;
	my $rid = shift;

	my $ret = [];
	my ($key, $val);
	while(($key, $val) = each %{$self->{'keys_by_userid'}})
	{
		push @$ret, $self->getById($val) if ($key =~ m/$rid/);
	}
	$ret;
}

sub allKeysByUserID
{
	my $self = shift;

	my $ret = [];
	my ($key, $val);
	while(($key, $val) = each %{$self->{'keys_by_userid'}})
	{
		push @$ret, [ $key, $self->getById($val) ];
	}
	$ret;
}

sub allKeysByID { allKeysByUserID @_; }

1;
