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
 * des_ecb2_encrypt
 *
 *	Electronic Code Book.
 *
 *	Data Encryption Standard encrypytion/decryption procedure.
 *	The procedure does only encrypt/decrypt 64 bit/8 byte blocks.
 *
 */

int	des_ecb2_encrypt(
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
	register int	i;
	des_cblock	b;


	for (; length >= DES_BLOCK_BYTES; length -= DES_BLOCK_BYTES) {
		VOID des_dea(input, output, schedule, encrypt);
		input++;
		output++;
	}
	/* Padd with zeros if neccessary */
	if (length > 0 && encrypt) {
		ZERO_8(b);
		for (i = 0; i < length; i++)
			b[i] = (*input)[i];
		VOID des_dea((des_cblock *) b, output, schedule, DES_ENCRYPT);
	}

	return 0;
}
