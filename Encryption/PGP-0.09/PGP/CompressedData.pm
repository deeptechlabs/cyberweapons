#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::CompressedData;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;


sub data { shift->{'compressed_data'}; }

sub new
{   
	my $type = shift; my $self = {}; bless $self, $type;
	my $msg = shift;

	$self->{'alg'} = 1;	# Zip
	$self->{'compressed_data'} = $msg;

	$self;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	$self->{'alg'} = $dis->readByte();
	$self->{'compressed_data'} = $dis->readAll();

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;
	   
	$dos->writeByte($self->{'alg'});
	$dos->write($self->data());
}

sub asString
{
	my $self = shift;

	my $retval = "Alg: \t" . $self->{'alg'} . "\n";
	$retval .= "Data: \t" . unpack("H*", $self->data()) . "\n";
	$retval;
}

1;
