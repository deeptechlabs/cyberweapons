#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.3 $
# $State: Release_0_09 $
#

package PGP::UserId;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

#
#	This should have an overloaded comparison
#
use overload
	'""' => \&asString;

sub id { my $self = shift; $$self; }

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

	$type->new($dis->readAll());
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	$dos->write($self->id());
}

sub asString { "User id: ".shift->id(); }

1;
