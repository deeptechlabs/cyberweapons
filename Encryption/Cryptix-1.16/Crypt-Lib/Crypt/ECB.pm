
#
# Many thanks to Adam Back for developing this package.
#

package Crypt::ECB;

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
	usage("new Crypt::ECB block-cipher") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	my $cipher = shift;
	$self->{'cipher'} = $cipher;

	$self;
}

sub encrypt
{
	usage("encrypt data") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	my $retval = "";
	my $size = $self->{'cipher'}->blocksize();

	while (length($data) > 0)
	{
		my $in = substr($data, 0, $size);
		substr($data, 0, $size) = '';
		my $out;

		# NB - The following is probably more efficient
		# but we don't check for the second arg yet etc.
		# $self->{'cipher'}->encrypt($iv, $out);
		$out = $self->{'cipher'}->encrypt($in);

		$retval .= $out;
	}

	$retval;
}

sub decrypt
{
	usage("decrypt data") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	my $retval = "";
	my $size = $self->{'cipher'}->blocksize();

	while (length($data) > 0)
	{
		my $in = substr($data, 0, $size);
		substr($data, 0, $size) = '';
		my $out;

		# NB - The following is probably more efficient
		# but we don't check for the second arg yet etc.
		# $self->{'cipher'}->encrypt($iv, $out);
		$out = $self->{'cipher'}->decrypt($in);

		$retval .= $out;
	}

	$retval;
}

1;
