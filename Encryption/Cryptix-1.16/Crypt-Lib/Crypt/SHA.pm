
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::SHA;

use Exporter;
use DynaLoader;
use Crypt::MessageDigest;
@ISA = qw(Exporter DynaLoader Crypt::MessageDigest);

my $VERSION = "1.03";                       # see Crypt-*/Makefile.PL
bootstrap Crypt::SHA $VERSION;

use Crypt::HashSHA;

sub digestAsHash
{
	new Crypt::HashSHA shift->digest();
}

1;
