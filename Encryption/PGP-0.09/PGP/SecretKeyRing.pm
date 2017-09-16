#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::SecretKeyRing;

use PGP::KeyRing;
@ISA = qw( PGP::KeyRing );

sub open { shift->SUPER::open(shift || "secring.pgp"); }
sub update { shift->SUPER::update(shift || "secring.pgp"); }
