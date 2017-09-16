
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Crypt::HashMD5;

# Tempting ...
# @HashMD5::ISA = qw(Crypt::HashMD5);

use Crypt::MessageHash;
@ISA = qw(Crypt::MessageHash);

sub size { 16; }
sub name { "MD5"; }

#
#   These should really be inherited
#
use overload 
	'cmp' => "cmp",
	'<=>' => "cmp",
	'""' => "asString";

1;
