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
 * des_no_key_schedule
 *
 *	Returns the number of different internal keys generated in a key
 *	schedule. The output is allways in the range 1 .. 16.
 */

int	des_no_key_schedule(
#ifdef __STDC__
	des_cblock *key)
#else
	key)
des_cblock	*key;
#endif
{
	register int		i, j, n;
	int			eq[16];
	des_key_schedule	ks;


	VOID des_key(key, ks); 

	for (i = 0; i < 16; i++)
		eq[i] = 0;
	for (n = 16, i = 0; i < 16; i++)
		if (!eq[i])
			for (j = i + 1; j < 16; j++)
				if (!eq[j])
					if (CMP_8(ks[i]._, ks[j]._)) {
						eq[j] = 1;
						n--;
					}

	return n;
}
