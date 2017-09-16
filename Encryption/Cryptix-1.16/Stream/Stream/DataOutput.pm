
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Stream::DataOutput;

#
#	Stream::DataOutput
#
#		Inherits from Stream::Output (write, skip & writeAll)
#
#		Implements Stream::DataOutput (the write* functions)
#
#		Uses an Stream::Output for its input
#


use strict;
use Carp;

use Stream::DataEncoding qw(/^encode/ );


sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}

sub new
{
	usage("output-stream") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'os'} = shift || croak("output-stream undefined");

	$self;
}

sub write
{
	usage("data") unless @_ == 2;

	my $self = shift;
	my $data = shift || usage("data");
	$self->{'os'}->write($data);
}

sub writeByte
{
	usage("byte") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	$self->{'os'}->write(encodeByte($data));
}

sub writeInt16
{
	usage("int16") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	$self->{'os'}->write(encodeInt16($data));
}

sub writeInt32
{
	usage("int32") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	$self->{'os'}->write(encodeInt32($data));
}

sub writeFloat
{
	usage("float") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	$self->{'os'}->write(encodeFloat($data));
}

sub writeDouble
{
	usage("double") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	$self->{'os'}->write(encodeDouble($data));
}

sub writeTime
{
	usage("time") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	$self->{'os'}->write(encodeTime($data));
}

sub writeLength
{
	usage("length") unless @_ == 2;

	my $self = shift;
	my $len = shift;

	$self->{'os'}->write(encodeLength($len));
}

sub writeString
{
	usage("string") unless @_ == 2;

	my $self = shift;
	my $str = shift;

	$self->{'os'}->write(encodeString($str));
}

1;
