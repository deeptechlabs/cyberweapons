
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::IDEA;


require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
# @ISA = qw(Exporter DynaLoader Crypt::BlockCipher);

# Items to export into callers namespace by default
@EXPORT =	qw();

# Other items we are prepared to export if requested
@EXPORT_OK =	qw();

my $VERSION = "1.03";                       # see Crypt-*/Makefile.PL
bootstrap Crypt::IDEA $VERSION;



use strict;
use Carp;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}


sub blocksize { 8; }
sub keysize { 16; }

sub new
{
	usage("new IDEA key") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'ks'} = Crypt::IDEA::expand_key(shift);

	$self;
}

sub encrypt
{
	usage("encrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::IDEA::crypt($data, $data, $self->{'ks'});

	$data;
}

sub decrypt
{
	usage("decrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	#
	# Cache Decrypt key schedule
	#
	$self->{'dks'} = Crypt::IDEA::invert_key($self->{'ks'})
										unless exists $self->{'dks'};

	Crypt::IDEA::crypt($data, $data, $self->{'dks'});

	$data;
}

1;
