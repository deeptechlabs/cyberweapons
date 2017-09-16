
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::CFB;

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
	usage("new Crypt::CFB block-cipher") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	my $cipher = shift;
	$self->{'cipher'} = $cipher;
	$self->{'blocksize'} = $cipher->blocksize();
	$self->reset();

	$self;
}

sub keysize { shift->{'cipher'}->keysize(); }

sub next_block { shift->{'spare'} = ''; }

sub reset
{
	my $self = shift;

	$self->{'spare'} = "";
	$self->{'iv'} = "\0" x $self->{'blocksize'};
}

sub encrypt
{
	usage("encrypt data") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	my $retval = "";
	my $iv = $self->{'iv'};

	my $out = $self->{'spare'};
	my $size = length($out);
	while (length($data) > 0)
	{
		unless ($size)
		{
			# NB - The following is probably more efficient
			# but we don't check for the second arg yet etc.
			# $self->{'cipher'}->encrypt($iv, $out);
			$out = $self->{'cipher'}->encrypt($iv);
			$size = $self->{'blocksize'};
		}
		my $in = substr($data, 0, $size);
		my $len = length($in);
		$size -= $len;
		substr($data, 0, $len) = '';

		$in ^= substr($out, 0, $len);
		substr($out, 0, $len) = '';

		substr($iv, 0, $len) = '';
		$iv .= $in;

		$retval .= $in;
	}

	$self->{'spare'} = $out;
	$self->{'iv'} = $iv;

	$retval;
}

sub decrypt
{
	usage("decrypt data") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	my $retval = "";
	my $iv = $self->{'iv'};

	my $out = $self->{'spare'};
	my $size = length($out);
	while (length($data) > 0)
	{
		unless ($size)
		{
			# NB - The following is probably more efficient
			# but we don't check for the second arg yet etc.
			# $self->{'cipher'}->encrypt($iv, $out);
			$out = $self->{'cipher'}->encrypt($iv);
			$size = $self->{'blocksize'};
		}
		my $in = substr($data, 0, $size);
		my $len = length($in);
		substr($data, 0, $len) = '';
		$size -= $len;

		substr($iv, 0, $len) = '';
		$iv .= $in;
		$in ^= substr($out, 0, $len);

		substr($out, 0, $len) = '';
		$retval .= $in;
	}

	$self->{'spare'} = $out;
	$self->{'iv'} = $iv;

	$retval;
}

1;
