
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::CSRandomStream;

#
#	This module should really be able to take
#	arbitrary PRNG and hash functions, but as yet does not.
#

use strict;
use Carp;

use Math::PRSG;
use Crypt::SHA;


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
	$self->{'md'} = new Crypt::SHA;
	$self->{'buf'} = $self->clock();

	$self;
}

sub seed
{
	usage("seed") unless @_ == 2;

	my $self = shift;
	my $seed = shift;

	$self->{'prsg'}->seed($seed);
}

sub clock
{
	usage("") unless @_ == 1;

	my $self = shift;

	my $r = $self->{'prsg'}->clock();
	$self->{'md'}->add($r);
	$r = $self->{'md'}->digest();
	$self->{'md'}->reset();
	$self->{'md'}->add($r);
	$r;
}

sub read
{
	usage("count") unless @_ == 2;

	my $self = shift;
	my $count = shift;

	while ($count > length($self->{'buf'}))
	{
		$self->{'buf'} .= $self->clock();
	}

	my $r = substr($self->{'buf'}, 0, $count);
	substr($self->{'buf'}, 0, $count) = '';
	$r;
}

sub readNonZero
{
	usage("count") unless @_ == 2;

	my $self = shift;
	my $count = shift;

	my $r = '';
	my $i;
	do {
		$r .= $self->read($count - length($r));
		for ($i = 0; $i < length($r); $i++)
		{
			if (ord(substr($r, $i, 1)) == 0)
			{
				substr($r, $i, 1) = '';
			}
		}
	} while (length($r) != $count);
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
