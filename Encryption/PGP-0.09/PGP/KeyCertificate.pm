#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::KeyCertificate;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;
use integer;
use POSIX;

use overload
	'""' => \&asString;


sub version { shift->[0]; }
sub timestamp { shift->[1]; }
sub validity { shift->[2]; }
sub alg { shift->[3]; }


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

	my $self = [ $version, $timestamp, $validity, 1 ];
	bless $self, $type;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = []; bless $self, $type;
	my $dis = shift;

	$self->[0] = $dis->readByte();
	$self->[1] = $dis->readTime();
	$self->[2] = $dis->readInt16();
	$self->[3] = $dis->readByte();

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	$dos->writeByte($self->version());
	$dos->writeTime($self->timestamp());
	$dos->writeInt16($self->validity());
	$dos->writeByte($self->alg());
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
	$retval;
}

1;
