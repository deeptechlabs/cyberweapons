#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::KeyRingTrust;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

use overload
	'""' => \&asString;


sub flags { my $self = shift; $$self; }

sub new
{
	my $type = shift;
	my $self = shift;
	bless \$self, $type;
}

sub restoreFromDataStream
{
	my $type = shift;
	my $dis = shift;

	$type->new($dis->readByte());
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	$dos->writeByte($self->flags());
}

sub asString
{
	my $self = shift;

	$self->flags();
}

1;
