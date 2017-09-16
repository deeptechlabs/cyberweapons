
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::RSAKey;

use strict;


sub n { shift->{'n'}; }
sub e { shift->{'e'}; }

#
#	Returns the number of bits in N
#
sub bits { shift->{'n'}->bits(); }

#
#	Returns the number of bytes in N
#		(NB. These are not all usuable for encryption - always
#		set the first byte (MSB) to zero).
#
sub size { int((shift->{'n'}->bits())/8); }

1;
