
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::StreamCipher;

#
#	Crypt::StreamCipher - an abstract base class
#

use strict;
use Carp;

sub usage
{   
	my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)";
}


sub new { carp("Cannot call undefined function in abstract base class"); }
sub encrypt { carp("Cannot call undefined function in abstract base class"); }
sub decrypt { carp("Cannot call undefined function in abstract base class"); }
sub keysize { carp("Cannot call undefined function in abstract base class"); }

1;
