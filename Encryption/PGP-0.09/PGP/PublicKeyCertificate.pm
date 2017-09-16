#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::PublicKeyCertificate;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;
use integer;
use POSIX;

use PGP::PublicKey;
use PGP::KeyCertificate;

use overload
	'""' => \&asString;


#
#	TODO
#
#	Make a key factory so that this code
#	doesn't have to deal with algorithm bytes
#


sub version { shift->[0]; }
sub timestamp { shift->[1]; }
sub validity { shift->[2]; }
sub alg { shift->[3]; }
sub pk { shift->[4]; }

sub fingerprint { shift->pk()->fingerprint(); }
sub publicKey { shift->pk(); }
sub size { shift->pk()->size(); }
sub id { shift->pk()->id(); }


sub new
{
	my $type = shift;
	my %args = @_;

	my $version = $args{'-version'};
	$version = 2 unless defined $version;

	my $timestamp = $args{'-timestamp'};
	$timestamp = time() unless defined $timestamp;

	my $validity = $args{'-validity'};
	$validity = 0 unless defined $validity;

	my $pk = $args{'-key'};
	ref $pk || return "-key argument missing";

	(ref($pk) eq 'PGP::PublicKey') or $pk = new PGP::PublicKey $pk->n(), $pk->e();

	my $self = [ $version, $timestamp, $validity, 1, $pk ];
	bless $self, $type;
}

sub restoreFromDataStream
{
	my $type = shift;
	my $dis = shift;

	my $version = $dis->readByte();
	my $timestamp = $dis->readTime();
	my $validity = $dis->readInt16();
	my $alg = $dis->readByte();

	my $pk = restoreFromDataStream PGP::PublicKey $dis;
	return "Could not read public key ($pk)" unless ref $pk;

	my $self = [ $version, $timestamp, $validity, 1, $pk ];
	bless $self, $type;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	$dos->writeByte($self->version());
	$dos->writeTime($self->timestamp());
	$dos->writeInt16($self->validity());
	$dos->writeByte($self->alg());
	$self->pk()->saveToDataStream($dos);
}

sub asString
{
	my $self = shift;

	my $retval = "version byte: \t" . $self->version() . "\n";
	$retval .= "Timestamp: \t" . POSIX::ctime($self->timestamp());
	$retval .= "validity (days): \t" . $self->validity() . "\n";
	#
	# algorithm byte (is 1 for RSA)
	#
	$retval .= "Public key alg: \t" . $self->alg() . "\n";

	$retval .= "Public key:\n";
	$retval .= $self->pk()->asString();
}

1;
