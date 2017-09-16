
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::MessageHash;

#
#	Should add overloading for comparisons
#	and overloading for printing would be nice
#	but I don't think they can be inherited at
#	present (so we will do it in derived classes)
#

use Stream::Streamable;
@ISA = qw(Stream::Streamable);

use strict;
use Carp;



use overload
	'cmp' => "cmp",
	'<=>' => "cmp",
	'""' => "asString";

sub new
{
	my $type = shift;
	my $data = shift;

	return "Incorrect length" unless (length($data) == $type->size());

	my $self = \$data;
	bless $self, $type;
}


sub data
{
	my $self = shift;
	$$self;
}

# sub newFromDigestor
# {
# 	shift->digestAsHash();
# }

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	$dos->write($$self);
}

sub restoreFromDataStream
{
	my $type = shift;
	my $dis = shift;

	my $size = $type->size();
	my $data = $dis->read($size);

	return "Failed to restore" unless (length($data) == $size);

	my $self = \$data;
	bless $self, $type;
}

sub asString
{
	my $self = shift;

	$self->name() . ":" . unpack("H*", $$self);
}

sub cmp
{
	my($cx, $cy) = @_;

	croak("Arguments are of different types") unless (ref($cx) eq ref($cy));

	$$cx cmp $$cy;
}

1;
