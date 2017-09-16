
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Math::PRSG;

require DynaLoader;
@ISA = qw(DynaLoader);

my $VERSION = "1.03";                       # see Math-*/Makefile.PL
bootstrap Math::PRSG $VERSION;

1;
