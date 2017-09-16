#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::PacketFactory;

use strict;

use PGP::PacketHeader;
use PGP::PKEncryptedKey;
use PGP::ConvEncryptedData;
use PGP::Signature;
use PGP::SecretKeyCertificate;
use PGP::PublicKeyCertificate;
use PGP::KeyRingTrust;
use PGP::UserId;
use PGP::LiteralData;
use PGP::CompressedData;


BEGIN {
#
#	The size fields are required for PGP 2.x compatibility
#
%PGP::PacketFactory::types = (
	'PGP::PKEncryptedKey'		=> { 'no' => 1, 'size' => 2 },
	'PGP::Signature'			=> { 'no' => 2, 'size' => 2 },
	'PGP::SecretKeyCertificate'	=> { 'no' => 5, 'size' => 2 },
	'PGP::PublicKeyCertificate'	=> { 'no' => 6, 'size' => 2 },
	'PGP::CompressedData'		=> { 'no' => 8, 'size' => 2 },
	'PGP::ConvEncryptedData'	=> { 'no' => 9, 'size' => 2 },
	'PGP::LiteralData'			=> { 'no' => 11, 'size' => 2 },
	'PGP::KeyRingTrust'			=> { 'no' => 12, 'size' => 1 },
	'PGP::UserId'				=> { 'no' => 13, 'size' => 1 },
	'PGP::Comment'				=> { 'no' => 14, 'size' => 1 }
);

	my ($key, $data);
	while (($key, $data) = each %PGP::PacketFactory::types)
	{
		$PGP::PacketFactory::typesByNo{$data->{'no'}} = $key;
	}
};

sub save
{
	my $dos = shift;
	my $packet = shift;

	return "undefined data-output" unless ref($dos);

	#
	#	Undefined packet
	#
	unless (defined($packet))
	{
		return "undefined packet";
	}

	my $ref = ref($packet);
	return "Unknown packet-type ($ref)" unless (exists $PGP::PacketFactory::types{$ref});

	my $body = $packet->save();

	#
	#	Should really do a bit of checking to ensure
	#	the body length does not exceed the maximum for
	#	the packet type (eg. 255 for UserId)
	#
	my $length = length($body);
	my $type = $PGP::PacketFactory::types{$ref}->{'no'};
	my $size = $PGP::PacketFactory::types{$ref}->{'size'};

	my $hdr = new PGP::PacketHeader $type, $length, $size;
	ref($hdr) || return $hdr;

	$hdr->saveToDataStream($dos);
	$dos->write($body);

	undef;
}

sub saveAsString
{
	my $packet = shift;

	(defined($packet)) || die "undefined packet";

	my $ref = ref($packet);
	exists $PGP::PacketFactory::types{$ref} || die "Unknown packet-type ($ref)";

	my $body = $packet->save();

	#
	#	Should really do a bit of checking to ensure
	#	the body length does not exceed the maximum for
	#	the packet type (eg. 255 for UserId)
	#
	my $type = $PGP::PacketFactory::types{$ref}->{'no'};
	my $size = $PGP::PacketFactory::types{$ref}->{'size'};
	my $hdr = new PGP::PacketHeader $type, length($body), $size;
	ref($hdr) || die $hdr;

	$hdr->save().$body;
}

sub restore
{
	my $dis = shift;

	return "undefined data-input" unless ref($dis);

	my $hdr = restoreFromDataStream PGP::PacketHeader $dis;
	return $hdr unless ref($hdr);

	my $data;
	if (defined $hdr->len())
	{
		$data = $dis->read($hdr->len());
	}
	else
	{
		$data = $dis->readAll();
	}
	return "EOF" unless defined $data;

	my $type = $hdr->type();
	my $class = $PGP::PacketFactory::typesByNo{$type};
	defined $class || return "Unknown type ($type)";

	restore $class $data;
}

sub restoreFromString
{
	my $sis = new Stream::StringInput shift;
	my $dis = new Stream::DataInput $sis;

	restore $dis;
}

1;
