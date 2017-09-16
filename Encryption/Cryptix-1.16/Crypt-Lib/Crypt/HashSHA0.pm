
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::HashSHA0;

# Tempting ...
# @HashSHA0::ISA = qw(Crypt::HashSHA0);

use Crypt::MessageHash;
@ISA = qw(Crypt::MessageHash);

sub size { 20; }
sub name { "SHA0"; }

#
#	These should really be inherited
#
use overload
	'cmp' => "cmp",
	'<=>' => "cmp",
	'""' => "asString";

1;
