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
 * des_string_to_key
 *
 *	Generation of a key from an arbitrary null terminated string.
 *
 *	This algorithm should be modified to return the same DES key
 *	on both ASCII and non-ASCII based systems.
 */


int	des_string_to_key(
#ifdef __STDC__
	char		*str,
	des_cblock	key)
#else
	str, key)
char		*str;
des_cblock	key;
#endif
{
	des_cblock		ivec;
	des_key_schedule	schedule;
	register int unsigned	n, i;
	register unsigned char	*cp;
#ifdef DES_LSB_FIRST
	register unsigned char  c;
#endif


	cp = (unsigned char *) str;
	ZERO_8(ivec);
	for (n = i = 0; *cp; i = (i + 1) % DES_BLOCK_BYTES, cp++, n++)
		/* Shift the character "away" from the parity	*/
		/* bit. Since the key characters (mostly) are	*/
		/* in the range 1 .. 127, the shift ensures	*/
		/* usage of all character bits in the key.	*/
#ifdef DES_LSB_FIRST
		c = *cp;
		CHAR_ROTATE(c);	
		ivec[i] ^= c >> 1;
#else
		ivec[i] ^= *cp << 1;
#endif


	VOID des_set_key_parity((des_cblock *) ivec);

	VOID des_key((des_cblock *) ivec, schedule);
	
	VOID des_cbc_cksum((des_cblock *) str, (des_cblock *) key, n,
			     schedule, (des_cblock *) ivec);

	/* Correct the key parity. */
	VOID des_set_key_parity((des_cblock *) key);

	return 0;
}
