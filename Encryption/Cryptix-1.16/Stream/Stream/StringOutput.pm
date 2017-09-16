
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Stream::StringOutput;

#
#	Stream::StringOutput
#
#		Inherits from Stream::Output, redefining all of it's member
#		functions:
#			write
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
	usage("") unless @_ == 1;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'data'} = '';

	$self;
}

sub write
{
	usage("data") unless @_ == 2;

	my $self = shift;
	my $data = shift;
	defined $data || usage("data");

	$self->{'data'} .= $data;
}


sub data
{
	usage("") unless @_ == 1;

	shift->{'data'};
}

1;
