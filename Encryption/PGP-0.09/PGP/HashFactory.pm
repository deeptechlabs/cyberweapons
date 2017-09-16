#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

#
#	The names in here are really screwed up/
#	They need chaning.
#

package PGP::HashFactory;

use strict;

use Crypt::HashMD5;
use Crypt::HashSHA;


#
#	I don't like the method names in the module
#	I may decide to change them! - Gary
#

#
#	This is still a hack
#	other codes are hardcoded below ...
#
%PGP::HashFactory::table = (
	# None is 0
	'Crypt::HashMD5' => 1,
	'Crypt::HashSHA' => 2,
);

sub save
{
	my $dos = shift;
	my $hash = shift;

	return "undefined data-output" unless ref($dos);

	#
	#	Undefined is a null byte
	#
	unless (defined($hash))
	{
		$dos->writeByte(0);
		return;
	}

	my $ref = ref($hash);
	return "Unknown hash-type ($ref)" unless (exists $PGP::HashFactory::table{$ref});

	my $code = $PGP::HashFactory::table{$ref};

	$dos->writeByte($code);
	$dos->write($$hash);

	undef;
}

sub saveAsString
{
	my $hash = shift;

	return "\0" unless defined($hash);	# Undefined is a null byte

	my $ref = ref($hash);
	return "Unknown hash-type ($ref)" unless (exists $PGP::HashFactory::table{$ref});

	my $code = $PGP::HashFactory::table{$ref};

	pack("C a*", $code, $$hash);
}

sub restore
{
	my $dis = shift;

	return "undefined data-input" unless ref($dis);

	my $code = $dis->readByte();
	return undef if ($code == 0);

	my $type;
	if    ($code == 1) { $type = "Crypt::HashMD5"; }
	elsif ($code == 2) { $type = "Crypt::HashSHA"; }
	else { return "Unknown type ($code)"; }

	restoreFromDataStream $type $dis;
}

sub restoreFromData
{
	my $data = shift;

	my $type = ord(substr($data, 0, 1));
	substr($data, 0, 1) = '';

	defined $type || return "Type not defined";
	return undef if ($type == 0);

	defined $data || return "Data not defined";

	my $class;
	if    ($type eq 1) { $class = "Crypt::HashMD5"; }
	elsif ($type eq 2) { $class = "Crypt::HashSHA"; }
	else { return "Unknown type ($type)"; }

	$class->restore($data);
}

sub restoreFromString
{
	my $str = shift;

	return undef if ($str eq "");

	my ($type, $data);
	($type, $data) = split(':', $str);
	defined $type || return "Type not defined ($str)";
	defined $data || return "Data not defined ($str)";

	my $class;
	if    ($type eq 'MD5') { $class = "Crypt::HashMD5"; }
	elsif ($type eq 'SHA') { $class = "Crypt::HashSHA"; }
	else { return "Unknown type ($type)"; }

	$class->restore(pack("H*", $data));
}

1;
