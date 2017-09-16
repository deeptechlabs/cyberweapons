#include	"des.h"
#include	"compile.h"
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
 * des_setkeyparity
 *
 *	Adjusts the parity bits in a key.
 */

int	des_set_key_parity(
#ifdef __STDC__
	des_cblock *key)
#else
	key)
des_cblock	*key;
#endif
{
	(*key)[0] = parity_tab[(*key)[0]];
	(*key)[1] = parity_tab[(*key)[1]];
	(*key)[2] = parity_tab[(*key)[2]];
	(*key)[3] = parity_tab[(*key)[3]];
	(*key)[4] = parity_tab[(*key)[4]];
	(*key)[5] = parity_tab[(*key)[5]];
	(*key)[6] = parity_tab[(*key)[6]];
	(*key)[7] = parity_tab[(*key)[7]];

	return 0;
}
