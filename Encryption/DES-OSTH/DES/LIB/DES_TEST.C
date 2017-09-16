#include	"des.h"
#include	"local_def.h"
#include	"parity.h"
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
 * des_test_key_parity
 *
 *	Checks if a key has correct parity.
 *
 *	result 1 => the key has correct parity.
 *	result 0 => the key has incorrect parity:
 *
 */

int     des_test_key_parity(
#ifdef __STDC__
	des_cblock *key)
#else
	key)
des_cblock	*key;
#endif
{
	register int            n;


	for (n = 0; n < DES_BLOCK_BYTES; n++)
		if ((*key)[n] != parity_tab[(*key)[n]])
			return 0;

	return 1;
}
