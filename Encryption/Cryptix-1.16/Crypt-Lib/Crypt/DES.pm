
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::DES;

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
# @ISA = qw(Exporter DynaLoader Crypt::BlockCipher);

# Items to export into callers namespace by default
@EXPORT =	qw();

# Other items we are prepared to export if requested
@EXPORT_OK =	qw();

$VERSION = "1.03";                       # see Crypt-*/Makefile.PL
bootstrap Crypt::DES $VERSION;




use strict;
use Carp;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}

sub blocksize { 8; }
sub keysize { 8; }

sub new
{
	usage("new DES key") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'ks'} = Crypt::DES::expand_key(shift);

	$self;
}

sub encrypt
{
	usage("encrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::DES::crypt($data, $data, $self->{'ks'}, 1);

	$data;
}

sub decrypt
{
	usage("decrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::DES::crypt($data, $data, $self->{'ks'}, 0);

	$data;
}

1;
