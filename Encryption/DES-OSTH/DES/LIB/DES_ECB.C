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
 * des_ecb_encrypt
 *
 *	Electronic Code Book.
 *
 *	Data Encryption Standard encrypytion/decryption procedure.
 *	This routine is the same a des_dea. It is included to be
 *	compatible with the MIT implemetation.
 *
 */

int	des_ecb_encrypt(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	des_key_schedule	schedule,
	int			encrypt)
#else
	input, output, schedule, encrypt)
des_cblock		*input, *output;
des_key_schedule	schedule;
int			encrypt;
#endif
{
	return des_dea(input, output, schedule, encrypt);
}
