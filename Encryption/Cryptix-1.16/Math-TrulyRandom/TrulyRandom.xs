/*
Perl Extension for the random function
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "truerand.h"

MODULE = Math::TrulyRandom		PACKAGE = Math::TrulyRandom

PROTOTYPES: DISABLE

long
rand()
    CODE:
	{
		RETVAL = truerand();
	}
	OUTPUT:
	RETVAL

int
rand_n(n)
	int	n
    CODE:
	{
		RETVAL = n_truerand(n);
	}
	OUTPUT:
	RETVAL
