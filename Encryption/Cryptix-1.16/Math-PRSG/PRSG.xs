/*
 *	Perl Extension for the PRSG functions
 *
 *	Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 *	All rights reserved.
 */


#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "prsg.h"

typedef PRSG_INFO *	Math__PRSG;

MODULE = Math::PRSG		PACKAGE = Math::PRSG

Math::PRSG
new(packname = "Math::PRSG", seed)
	char *			packname
	unsigned char *	seed = NO_INIT
	STRLEN			input_len = NO_INIT
    CODE:
	{
		seed = (unsigned char *) SvPV(ST(1), input_len);
		if (input_len != 20)
			croak("seed must be 20 bytes long");

	    RETVAL = (PRSG_INFO *) safemalloc(sizeof(PRSG_INFO));
	    prsg_seed(RETVAL, seed);
	}
    OUTPUT:
	RETVAL

void
DESTROY(context)
	Math::PRSG	context
    CODE:
	{
	    safefree((char *) context);
	}

void
seed(context, seed)
	Math::PRSG			context
	unsigned char *	seed = NO_INIT
	STRLEN			input_len = NO_INIT
    CODE:
	{
		seed = (unsigned char *) SvPV(ST(1), input_len);
		if (input_len != 20)
			croak("seed must be 20 bytes long");

	    prsg_seed(context, seed);
	}

char *
clock(context)
	Math::PRSG	context
    CODE:
	{
	    unsigned char d_str[20];

	    prsg_clock(context);
	    d_str[ 0] = (unsigned char) ((context->reg[4] >> 24) & 0xff);
	    d_str[ 1] = (unsigned char) ((context->reg[4] >> 16) & 0xff);
	    d_str[ 2] = (unsigned char) ((context->reg[4] >>  8) & 0xff);
	    d_str[ 3] = (unsigned char) ((context->reg[4]      ) & 0xff);
	    d_str[ 4] = (unsigned char) ((context->reg[3] >> 24) & 0xff);
	    d_str[ 5] = (unsigned char) ((context->reg[3] >> 16) & 0xff);
	    d_str[ 6] = (unsigned char) ((context->reg[3] >>  8) & 0xff);
	    d_str[ 7] = (unsigned char) ((context->reg[3]      ) & 0xff);
	    d_str[ 8] = (unsigned char) ((context->reg[2] >> 24) & 0xff);
	    d_str[ 9] = (unsigned char) ((context->reg[2] >> 16) & 0xff);
	    d_str[10] = (unsigned char) ((context->reg[2] >>  8) & 0xff);
	    d_str[11] = (unsigned char) ((context->reg[2]      ) & 0xff);
	    d_str[12] = (unsigned char) ((context->reg[1] >> 24) & 0xff);
	    d_str[13] = (unsigned char) ((context->reg[1] >> 16) & 0xff);
	    d_str[14] = (unsigned char) ((context->reg[1] >>  8) & 0xff);
	    d_str[15] = (unsigned char) ((context->reg[1]      ) & 0xff);
	    d_str[16] = (unsigned char) ((context->reg[0] >> 24) & 0xff);
	    d_str[17] = (unsigned char) ((context->reg[0] >> 16) & 0xff);
	    d_str[18] = (unsigned char) ((context->reg[0] >>  8) & 0xff);
	    d_str[19] = (unsigned char) ((context->reg[0]      ) & 0xff);

	    ST(0) = sv_2mortal(newSVpv(d_str, 20));
	}
