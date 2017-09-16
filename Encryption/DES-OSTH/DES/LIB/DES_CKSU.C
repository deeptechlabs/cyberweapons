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
 * des_cbc_cksum
 *
 *	Cipher Block Chaining Checksum.
 *
 */

unsigned long	des_cbc_cksum(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	int			length,
	des_key_schedule	schedule,
	des_cblock		*ivec)
#else
	input, output, length, schedule, ivec)
des_cblock		*input;
des_cblock		*output;
int			length;
des_key_schedule	schedule;
des_cblock		*ivec;
#endif
{
	register int		i;
	register des_cblock	*ivecp;
	des_cblock		tmp_ivec;
	register unsigned long	res;


	if (des_return_ivec) {
		ivecp = ivec;
	} else {
		COPY_8(tmp_ivec, (*ivec));
		ivecp = (des_cblock *) tmp_ivec;
	}

	for (; length >= DES_BLOCK_BYTES; length -= DES_BLOCK_BYTES, input++) {
		XOR_8((*ivecp), (*input));
		VOID des_dea(ivecp, ivecp, schedule, DES_ENCRYPT);
	}
	if (length > 0) {
		/* This method procuces zero padding ! */
		for (i = 0; i < length; i++)
			(*ivecp)[i] ^= (*input)[i];
		VOID des_dea(ivecp, ivecp, schedule, DES_ENCRYPT);
	}
	COPY_8((*output), (*ivecp));

	res  = (*output)[7];
	res <<= UNSIGNED_CHAR_BITS;
	res |= (*output)[6];
	res <<= UNSIGNED_CHAR_BITS;
	res |= (*output)[5];
	res <<= UNSIGNED_CHAR_BITS;
	res |= (*output)[4];

	return	res;
}
