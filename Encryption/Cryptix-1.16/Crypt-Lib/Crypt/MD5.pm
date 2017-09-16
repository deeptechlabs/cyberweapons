
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::MD5;

use Exporter;
use DynaLoader;
use Crypt::MessageDigest;
@ISA = qw(Exporter DynaLoader Crypt::MessageDigest);

$VERSION = '1.08';                       # see Crypt-*/Makefile.PL
bootstrap Crypt::MD5 $VERSION;

use Crypt::HashMD5;

sub digestAsHash
{
	new Crypt::HashMD5 shift->digest();
}

1;
