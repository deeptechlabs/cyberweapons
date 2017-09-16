#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::LiteralData;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;


sub data { shift->{'literal_data'}; }

sub new
{   
	my $type = shift; my $self = {}; bless $self, $type;
	my $msg = shift;

	$self->{'mode'} = 'b';	# Binary
	$self->{'filename'} = '';
	$self->{'timestamp'} = time();
	$self->{'literal_data'} = $msg;

	$self;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	$self->{'mode'} = $dis->read(1);
	$self->{'filename'} = $dis->read($dis->readByte());
	$self->{'timestamp'} = $dis->readTime();
	$self->{'literal_data'} = $dis->readAll();

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;
	   
	$dos->write($self->{'mode'});
	$dos->writeByte(length($self->{'filename'}));
	$dos->write($self->{'filename'}) unless $self->{'filename'} eq '';
	$dos->writeTime($self->{'timestamp'});
	$dos->write($self->data());
}

sub asString
{
	my $self = shift;

	my $retval = "Mode: \t" . $self->{'mode'} . "\n";
	$retval .= "Filename: \t" . $self->{'filename'} . "\n";
	$retval .= "Timestamp: \t" . POSIX::ctime($self->{'timestamp'});
	$retval .= "Data: \t" . unpack("H*", $self->data()) . "\n";
	$retval;
}

1;
