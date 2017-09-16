#include	"des.h"
#include	"local_def.h"
#include	"key_sweak.h"
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
 * des_is_semiweak_key
 *
 *	Check for keys that produces only two different values int the
 *	internal key schedule. There are twelve such keys.
 *
 *	The key must have correct parity.
 *
 *	0 => The key is not semiweak.
 *	1 => The key is semiweak.
 */

int	des_is_semiweak_key(
#ifdef __STDC__
	des_cblock *key)
#else
	key)
des_cblock	*key;
#endif
{
	register int		i;


	for (i = 0; i < NO_SEMI_WEAK_KEYS; i++)
		if (CMP_8(semiweak_key[i],(*key)))
			return 1;
	return 0;
}
