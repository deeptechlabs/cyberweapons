
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::SHA0;

use Exporter;
use DynaLoader;
use Crypt::MessageDigest;
@ISA = qw(Exporter DynaLoader Crypt::MessageDigest);

my $VERSION = "1.03";                       # see Crypt-*/Makefile.PL
bootstrap Crypt::SHA0 $VERSION;

use Crypt::HashSHA0;

sub digestAsHash
{
	new Crypt::HashSHA0 shift->digest();
}

1;
