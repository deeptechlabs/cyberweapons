#include	"des.h"
#include	"local_def.h"
#include	"version.h"

/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 * Additional restrictions due to national laws governing the use, import or
 * export of cryptographic software is the responsibility of the software user,
 * importer or exporter to follow.
 *
 *					     _
 *					Stig Ostholm
 *					Department of Computer Engineering
 *					Chalmers University of Technology
 */

/*
 * des_ofb8_encrypt
 *
 *	Eight bit Output Feedback.
 *
 *	Data Encryption Standard encrypytion/decryption procedure.
 *
 */

int	des_ofb8_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec,
	int			encrypt)
#else
	input, output, length, schedule, ivec, encrypt)
des_cblock		*input;
des_cblock		*output;
int			length;
des_key_schedule	schedule;
des_cblock		*ivec;
int			encrypt;
#endif
{
	register unsigned char	c, *inp, *outp;
	des_cblock		tmp_ivec;
	register des_cblock	*ivecp;


	if (des_return_ivec) {
		ivecp = ivec;
	} else {
		COPY_8(tmp_ivec, (*ivec));
		ivecp = (des_cblock *) tmp_ivec;
	}
	inp = (unsigned char *) input;
	outp = (unsigned char *) output;
	while (length-- > 0) {
		VOID des_dea(ivecp, ivecp, schedule, DES_ENCRYPT);
		c = **ivecp;
		SHIFT_RIGHT_8((*ivecp), c);
		*outp++ = *inp++ ^ c;
	}
	
	return 0;
}
