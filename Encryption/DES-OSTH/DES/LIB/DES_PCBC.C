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
 * des_pcbc_encrypt
 *
 *	Modified Cipher Block Chaining.
 *
 */

int	des_pcbc_encrypt(
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
	register int		i;
	des_cblock		c, b, tmp_ivec;
	register des_cblock	*ivecp;


	if (des_return_ivec) {
		ivecp = ivec;
	} else {
		COPY_8(tmp_ivec, (*ivec));
		ivecp = (des_cblock *) tmp_ivec;
	}
	if (encrypt) {
		for (; length >= DES_BLOCK_BYTES;
		       length -= DES_BLOCK_BYTES, output++, input++) {
			COPY_8(c, (*input));
			XOR2_8(b, c, (*ivecp));
			VOID des_dea((des_cblock *) b, output, schedule,
				     DES_ENCRYPT);
			XOR2_8((*ivecp), c, (*output));
		}
		/* Padd with zeros. */
		if (length > 0) {
			ZERO_8(c);
			for (i = 0; i < length; i++)
				c[i] = (*input)[i];
			XOR2_8(b, c, (*ivecp));
			VOID des_dea((des_cblock *) b, output, schedule,
				     DES_ENCRYPT);
			if (des_return_ivec) {
				XOR2_8((*ivecp), c, (*output));
			}
		}
	} else
		for (; length > 0;
		       length -= DES_BLOCK_BYTES, output++, input++) {
			COPY_8(c, (*input));
			VOID des_dea(input, output, schedule, DES_DECRYPT);
			XOR_8((*output), (*ivecp));
			XOR2_8((*ivecp), c, (*output));
		}
		/* There is no ide to use padding in decryption */

	return 0;
}
