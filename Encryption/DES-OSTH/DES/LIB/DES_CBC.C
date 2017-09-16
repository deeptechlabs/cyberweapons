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
 * des_cbc_encrypt
 *
 *	Cipher Block Chaining.
 *
 */

int	des_cbc_encrypt(
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
	des_cblock		c, tmp_ivec;
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
			XOR_8((*ivecp), (*input));
			VOID des_dea(ivecp, ivecp, schedule, DES_ENCRYPT);
			COPY_8((*output), (*ivecp));
		}
		/* Padd with zeros. */
		if (length > 0) {
			for (i = 0; i < length; i++)
				(*ivecp)[i] ^= (*input)[i];
			VOID des_dea(ivecp, ivecp, schedule, DES_ENCRYPT);
			COPY_8((*output), (*ivecp));
		}
	} else
		for (; length > 0;
		       length -= DES_BLOCK_BYTES, output++, input++) {
			COPY_8(c, (*input));
			VOID des_dea(input, output, schedule, DES_DECRYPT);
			XOR_8((*output), (*ivecp));
			COPY_8((*ivecp), c);
		}
		/* There is no idea to use padding in decryption */

	return 0;
}
