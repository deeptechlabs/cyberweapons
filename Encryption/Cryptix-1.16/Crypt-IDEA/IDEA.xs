/*
 *	Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 *	All rights reserved.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "idea.h"

MODULE = Crypt::IDEA		PACKAGE = Crypt::IDEA		PREFIX = idea_

char *
idea_expand_key(key)
	char *	key = NO_INIT
	STRLEN	key_len = NO_INIT
    CODE:
	{
		idea_ks	ks;

		key = (char *) SvPV(ST(0), key_len);
		if (key_len != sizeof(idea_user_key))
			croak("Invalid key");

		idea_expand_key((u_int16_t *)key, ks);

		ST(0) = sv_2mortal(newSVpv((char *)ks, sizeof(ks)));
	}

char *
idea_invert_key(ks)
	char *	ks = NO_INIT
	STRLEN	ks_len = NO_INIT
    CODE:
	{
		u_int16_t	iks[52];

		ks = (char *) SvPV(ST(0), ks_len);
		if (ks_len != sizeof(idea_ks))
			croak("Invalid key schedule");

		idea_invert_key((u_int16_t *)ks, iks);

		ST(0) = sv_2mortal(newSVpv((char *)iks, sizeof(iks)));
	}

void
idea_crypt(input, output, ks)
	char *	input = NO_INIT
	SV *	output
	char *	ks = NO_INIT
	STRLEN	input_len = NO_INIT
	STRLEN	output_len = NO_INIT
	STRLEN	ks_len = NO_INIT
	CODE:
	{
		input = (char *) SvPV(ST(0), input_len);
		if (input_len != 8)
			croak("input must be 8 bytes long");

		ks = (char *) SvPV(ST(2), ks_len);
		if (ks_len != sizeof(idea_ks))
			croak("Invalid key schedule");

		if (output == &sv_undef)
			output = sv_newmortal();
		output_len = 8;

		if (!SvUPGRADE(output, SVt_PV))
			croak("cannot use output argument as lvalue");

		idea_crypt((u_int16_t *)input, (u_int16_t *)SvGROW(output, output_len), (u_int16_t *)ks);

		SvCUR_set(output, output_len);
		*SvEND(output) = '\0';
		(void) SvPOK_only(output);
		SvTAINT(output);

		ST(0) = output;
	}
