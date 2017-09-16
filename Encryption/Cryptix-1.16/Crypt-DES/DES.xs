/*
 *	Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 *	All rights reserved.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "des.h"

MODULE = Crypt::DES		PACKAGE = Crypt::DES		PREFIX = des_
PROTOTYPES: DISABLE

char *
des_expand_key(key)
	char *	key = NO_INIT
	STRLEN	key_len = NO_INIT
    CODE:
	{
		des_ks	ks;

		key = (char *) SvPV(ST(0), key_len);
		if (key_len != sizeof(des_user_key))
			croak("Invalid key");

		des_expand_key((u_int8_t *)key, ks);

		ST(0) = sv_2mortal(newSVpv((char *)ks, sizeof(ks)));
	}

void
des_crypt(input, output, ks, enc_flag)
	char *	input = NO_INIT
	SV *	output
	char *	ks = NO_INIT
	int enc_flag
	STRLEN	input_len = NO_INIT
	STRLEN	output_len = NO_INIT
	STRLEN	ks_len = NO_INIT
	CODE:
	{
		input = (char *) SvPV(ST(0), input_len);
		if (input_len != 8)
			croak("input must be 8 bytes long");

		ks = (char *) SvPV(ST(2), ks_len);
		if (ks_len != sizeof(des_ks))
			croak("Invalid key schedule");

		if (output == &sv_undef)
			output = sv_newmortal();
		output_len = 8;

		if (!SvUPGRADE(output, SVt_PV))
			croak("cannot use output argument as lvalue");

		des_crypt(input, SvGROW(output, output_len), (u_int32_t *)ks, enc_flag);

		SvCUR_set(output, output_len);
		*SvEND(output) = '\0';
		(void) SvPOK_only(output);
		SvTAINT(output);

		ST(0) = output;
	}
