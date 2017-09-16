
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Math::PseudoRandomStream;

#
#	This module should really be able to take
#	arbitrary PRNGs, but as yet does not.
#

use strict;
use Carp;
use Math::PRSG;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}


sub new
{
	usage("seed") unless (@_ == 2);

	my $type = shift; my $self = {}; bless $self, $type;
	my $seed = shift;

	croak("Incorrect length seed (must be 20 bytes)") if (length($seed) != 20);

	$self->{'prsg'} = new Math::PRSG $seed;
	$self->{'buf'} = $self->{'prsg'}->clock();

	$self;
}

sub seed
{
	usage("seed") unless @_ == 2;

	my $self = shift;
	my $seed = shift;

	$self->{'prsg'}->seed($seed);
}

sub read
{
	usage("count") unless @_ == 2;

	my $self = shift;
	my $count = shift;

	while ($count > length($self->{'buf'}))
	{
		$self->{'buf'} .= $self->{'prsg'}->clock();
	}

	my $r = substr($self->{'buf'}, 0, $count);
	substr($self->{'buf'}, 0, $count) = '';
	$r;
}

sub skip
{
	usage("count") unless @_ == 2;

	my $self = shift;
	my $count = shift;

	$self->read($count);
	return;
}

sub readAll { croak("Cannot readAll on an infinite stream"); }

sub eoi
{
	usage("eoi") unless @_ == 1;

	return 0;
}   
					  
1;
