/*
Perl Extension for the SHA-0 Message-Digest Algorithm

This module by Uwe Hollerbach <uh@alumni.caltech.edu>
following example of MD5 module

This extension may be distributed under the same terms
as Perl. The SHA-0 code is in the public domain.
new(packname = "Crypt::SHA0")
	char *	packname
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "sha.h"

typedef SHA_INFO	* Crypt__SHA0;

MODULE = Crypt::SHA0		PACKAGE = Crypt::SHA0	PREFIX = sha0_

PROTOTYPES: DISABLE



Crypt::SHA0
new(packname = "Crypt::SHA0")
	char *	packname
    CODE:
	{
	    RETVAL = (SHA_INFO *) safemalloc(sizeof(SHA_INFO));
	    sha0_init(RETVAL);
	}
    OUTPUT:
	RETVAL

void
DESTROY(context)
	Crypt::SHA0	context
    CODE:
	{
	    safefree((char *) context);
	}

void
reset(context)
	Crypt::SHA0	context
    CODE:
	{
	    sha0_init(context);
	}

void
add(context, ...)
	Crypt::SHA0	context
    CODE:
	{
	    SV *svdata;
	    STRLEN len;
	    unsigned char *data;
	    int i;

	    for (i = 1; i < items; i++) {
		data = (unsigned char *) (SvPV(ST(i), len));
		sha0_update(context, data, len);
	    }
	}

char *
digest(context)
	Crypt::SHA0	context
    CODE:
	{
	    unsigned char d_str[20];

	    sha0_final(context);
	    d_str[ 0] = (unsigned char) ((context->digest[0] >> 24) & 0xff);
	    d_str[ 1] = (unsigned char) ((context->digest[0] >> 16) & 0xff);
	    d_str[ 2] = (unsigned char) ((context->digest[0] >>  8) & 0xff);
	    d_str[ 3] = (unsigned char) ((context->digest[0]      ) & 0xff);
	    d_str[ 4] = (unsigned char) ((context->digest[1] >> 24) & 0xff);
	    d_str[ 5] = (unsigned char) ((context->digest[1] >> 16) & 0xff);
	    d_str[ 6] = (unsigned char) ((context->digest[1] >>  8) & 0xff);
	    d_str[ 7] = (unsigned char) ((context->digest[1]      ) & 0xff);
	    d_str[ 8] = (unsigned char) ((context->digest[2] >> 24) & 0xff);
	    d_str[ 9] = (unsigned char) ((context->digest[2] >> 16) & 0xff);
	    d_str[10] = (unsigned char) ((context->digest[2] >>  8) & 0xff);
	    d_str[11] = (unsigned char) ((context->digest[2]      ) & 0xff);
	    d_str[12] = (unsigned char) ((context->digest[3] >> 24) & 0xff);
	    d_str[13] = (unsigned char) ((context->digest[3] >> 16) & 0xff);
	    d_str[14] = (unsigned char) ((context->digest[3] >>  8) & 0xff);
	    d_str[15] = (unsigned char) ((context->digest[3]      ) & 0xff);
	    d_str[16] = (unsigned char) ((context->digest[4] >> 24) & 0xff);
	    d_str[17] = (unsigned char) ((context->digest[4] >> 16) & 0xff);
	    d_str[18] = (unsigned char) ((context->digest[4] >>  8) & 0xff);
	    d_str[19] = (unsigned char) ((context->digest[4]      ) & 0xff);

	    ST(0) = sv_2mortal(newSVpv(d_str, 20));
	}
