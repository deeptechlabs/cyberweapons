
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::DES3EDE;

use strict;
use Carp;
use Crypt::DES;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}

sub blocksize { 8; }
sub keysize { 24; }

sub new
{
	usage("new DES3EDE key") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;
	my $key = shift;

	usage("incorrect length key") unless (length($key) == 24);

	$self->{'des1'} = new Crypt::DES substr($key, 0, 8);
	$self->{'des2'} = new Crypt::DES substr($key, 8, 8);
	$self->{'des3'} = new Crypt::DES substr($key, 16, 8);

	$self;
}

sub encrypt
{
	usage("encrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	$self->{'des3'}->encrypt(
		$self->{'des2'}->decrypt(
			$self->{'des1'}->encrypt($data)
		)
	);
}

sub decrypt
{
	usage("decrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	$self->{'des3'}->decrypt(
		$self->{'des2'}->encrypt(
			$self->{'des1'}->decrypt($data)
		)
	);
}

1;
