#include	"des.h"
#include	"local_def.h"
#include	"key_weak.h"
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
 * des_is_weak_key
 *
 *	Checks for keys that produces an internal key scheudle that has
 *	the property K1 = K2 = ... = K16. There is a total of four weak keys.
 *
 *	The key must have correct parity.
 *
 *	0 => The key is not weak.
 *	1 => The key is weak.
 */

int	des_is_weak_key(
#ifdef __STDC__
	des_cblock *key)
#else
	key)
des_cblock	*key;
#endif
{
	register int		i;


	for (i = 0; i < NO_WEAK_KEYS; i++)
		if (CMP_8(weak_key[i],(*key)))
			return 1;
	return 0;
}
