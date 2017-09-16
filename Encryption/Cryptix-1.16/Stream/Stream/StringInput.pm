
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Stream::StringInput;


#
#	Stream::StringInput
#
#		Inherits from Stream::Input, redefining all of it's member
#		functions:
#			read
#			skip
#			readAll
#

use strict;
use Carp;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}

sub new
{
	usage("string") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'data'} = shift;
	defined $self->{'data'} || return "Undefined parameter";

	$self;
}

sub read
{
	usage("count") unless @_ == 2;

	my $self = shift;
	my $count = shift;

	return if (length($self->{'data'}) == 0);

	my $retval = substr($self->{'data'}, 0, $count);
	substr($self->{'data'}, 0, $count) = '';
	$retval;
}

sub skip
{
	usage("count") unless @_ == 2;

	my $self = shift;
	my $count = shift;

	substr($self->{'data'}, 0, $count) = '';
	return;
}

sub readAll
{
	usage unless @_ == 1;

	my $self = shift;

	my $retval = $self->{'data'};
	$self->{'data'} = '';
	$retval;
}

sub eoi
{
	usage("eoi") unless @_ == 1;

	my $self = shift;
	return (length($self->{'data'}) == 0);
}   
					  
1;
