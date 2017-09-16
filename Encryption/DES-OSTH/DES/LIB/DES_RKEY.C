#include	"des.h"
#include	"compile.h"
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
 * des_random_key
 *
 *	The routine returns a random generated DES key.
 *
 */

int	des_random_key(
#ifdef __STDC__
	des_cblock *key)
#else
	key)
des_cblock	*key;
#endif
{
	/* Make a random 64-bit block. */
	VOID des_random_cblock(key);

	/* Parity adjust the key. */
	VOID des_set_key_parity(key);

	return 0;
}
