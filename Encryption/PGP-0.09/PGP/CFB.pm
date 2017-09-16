#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::CFB;

use Crypt::CFB;
@ISA = qw( Crypt::CFB );

use strict;

sub encrypt
{
	usage("encrypt data") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	$self->next_block();
	$self->SUPER::encrypt($data);
}

sub decrypt
{
	usage("decrypt data") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	$self->next_block();
	$self->SUPER::decrypt($data);
}

1;
