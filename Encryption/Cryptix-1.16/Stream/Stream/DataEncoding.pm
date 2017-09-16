
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Stream::DataEncoding;

require 5.000;
require Exporter;

@ISA = qw(Exporter);
@EXPORT_OK = qw(
	encodeByte
	encodeInt16
	encodeInt32
	encodeFloat
	encodeDouble
	encodeLength
	encodeTime
	encodeString
	encodeArray
	decodeByte
	decodeInt16
	decodeInt32
	decodeFloat
	decodeDouble
	decodeLength
	decodeTime
	decodeString
	decodeArray
);

use strict;
use Carp;

sub encodeByte { pack("C", shift); }
sub encodeInt16 { pack("n", shift); }
sub encodeInt32 { pack("N", shift); }
sub encodeFloat { pack("N", unpack("l", pack("f", shift))); }
sub encodeDouble
{
	my ($l1, $l2) = unpack("l l", pack("d", shift));
	pack("N N", $l2, $l1);	# Machine dependant!
}
sub encodeLength
{
	my $l = shift;

	croak("Negative length") if ($l < 0);

	my $retval = pack("C", ($l & 0x7F));
	$l = $l >> 7;

	while ($l != 0)
	{
		$retval = pack("C", (0x80 | ($l & 0x7F))) . $retval;
		$l = $l >> 7;
	}

	$retval;
}

sub encodeTime { pack("N", shift); }
sub encodeString
{
	my $str = shift;
	encodeLength(length($str)) . $str;
}

sub decodeByte { unpack("C", shift); }
sub decodeInt16 { unpack("s", pack("s", unpack("n", shift))); }
sub decodeUnsignedInt16 { unpack("n", shift); }
sub decodeInt32 { unpack("l", pack("l", unpack("N", shift))); }
sub decodeUnsignedInt32 { unpack("N", shift); }
sub decodeFloat { unpack("f", pack("l", unpack("N", shift))); }
sub decodeDouble
{
	my ($l1, $l2) = unpack("N N", shift);	# Machine dependant!
	unpack("d", pack("l l", $l2, $l1));
}

sub decodeLength
{
	my $data = shift;

	my $s = 0;
	my $i = 0;
	for(;;)
	{
		return if (length($data) < $i);

		my $n = ord(substr($data, $i++, 1));
		$s = ($s << 7) + (0x7F & $n);
		last if ($n < 128);		# Last octet
	}
	$s;
}
sub decodeTime { unpack("N", shift); }
sub decodeString { substr(shift, 2); }

#
#	More utility functions
#
sub encodeArray
{
	my $data = shift;
	my $tmp = '';
	foreach (@$data) { $tmp .= Stream::DataEncoding::encodeString($_); }
	$tmp;
}

sub decodeArray
{
	my $sis = new Stream::StringInput shift;
	ref $sis || return $sis;
	my $dis = new Stream::DataInput $sis;
	ref $dis || return $dis;

	my $str;
	my $result = []; 
	while (defined ($str = $dis->readString()))
	{   
		push @$result, $str;
	}
	$result;
}

1;
