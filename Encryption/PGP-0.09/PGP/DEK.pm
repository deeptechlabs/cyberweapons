#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::DEK;

use Math::BigInteger;

use strict;


sub encode
{
	my $key = shift;
	my $size = shift;
	my $ris = shift;

	return "random-input-stream undefined" unless ref($ris);

									# 22 = 2 + 2 + 16 + 2
	my $d = pack("n a* n a*", 2, $ris->readNonZero($size-22), 1, $key);
	$d .= pack("n", unpack("%16C*", $key));	# Docs say csum is on $d, not $key!

	restore Math::BigInteger $d;
}

sub decode
{
	my $bi = shift;

	my $plain = $bi->save();

	if (ord($plain) != 2)
	{
		$! = 1;
		return (undef, "Bad start of decrypted data");
	}

	my $sum = unpack("n", substr($plain, -2, 2));
	substr($plain, -2, 2) = '';
	if (unpack("%16C*", substr($plain, -16, 16)) != $sum)
	{
		return (undef, "Bad checksum for decrypted data");
	}

	my $i = 0;
	for ($i = 0; $i < length($plain); $i++)
	{
		last if (ord(substr($plain, $i, 1)) == 0);
	}
	if ((ord(substr($plain, $i)) != 0) || (ord(substr($plain, $i+1)) != 1))
	{
		return (undef, "Bad start of message in decrypted data");
	}

	substr($plain, 0, $i+2) = '';

	$! = 0;
	($plain, undef);
}

1;
