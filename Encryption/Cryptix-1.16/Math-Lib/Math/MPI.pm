#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

#
#	IMPORTANT!  This module is due to change from being an
#	object to a utility class
#	Please refrain from using the deprecated methods
#
#	Thanks - Gary.Howland@sytstemics.com
#

package Math::MPI;

#
#	Module for reading/writing PGP style multi-precision integers (MPIs)
#

use Stream::Streamable;
@ISA = qw(Stream::Streamable );

use strict;
use integer;

use Math::BigInteger;


#
# Deprecated
#
sub new
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $bi = shift;

	ref($bi) || die "Usage: new MPI BigInteger ($bi)";

	$self->{'bits'} = $bi->bits();
	$self->{'data'} = $bi->save();

	$self;
}

#
# Deprecated
#
sub asBigInteger
{
	restore Math::BigInteger shift->{'data'};
}

#
# Deprecated
#
sub restoreFromDataStream
{
	usage("input-stream") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	my $bits = $dis->readInt16();
	die "Failed to read MPI header" unless defined $bits;

	my $bytes = (($bits-1)/8)+1;

	my $data = $dis->read($bytes);
	die "Failed to read full MPI" if (length($data) != $bytes);

	$self->{'bits'} = $bits;
	$self->{'data'} = $data;

	$self;
}

#
# Deprecated
#
sub saveToDataStream
{
	usage("output-stream") unless @_ == 2;

	my $self = shift;
	my $dos = shift;

	$dos->writeInt16($self->{'bits'});
	$dos->write($self->{'data'});
	undef;
}

sub readBigInteger
{
	usage("input-stream") unless @_ == 1;

	my $dis = shift;

	my $bits = $dis->readInt16();
	die "Failed to read MPI header" unless defined $bits;

	my $bytes = (($bits-1)/8)+1;

	my $data = $dis->read($bytes);
	die "Failed to read full MPI" if (length($data) != $bytes);

	restore Math::BigInteger $data;
}

sub writeBigInteger
{
	usage("output-stream big-integer") unless @_ == 2;

	my $dos = shift;
	my $bi = shift;

	$dos->writeInt16($bi->bits());
	$dos->write($bi->save());
}

1;
