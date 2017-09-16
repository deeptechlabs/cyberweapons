#include	<sys/time.h>
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
 * des_random_cblock
 *
 *	The routine returns a random generated DES 64-bit block.
 *
 *	This method may not be the fastest, but produces a fairly random
 *	result that is not easy to predict (At least I belive this is the
 *	case).
 *
 *	This alogirthm is purely of my own construction.
 */

int	des_random_cblock(
#ifdef __STDC__
	des_cblock *cblock)
#else
	cblock)
des_cblock	*cblock;
#endif
{
	static des_cblock	cnt;
	des_cblock		seed;
	des_key_schedule	ks;
	register unsigned long	pid;
	struct timeval		time;


	pid = (unsigned long) getpid();
	VOID gettimeofday(& time, (struct timezone *) 0);

	/* "Merge" tiem and current process id. */
	time.tv_usec ^= pid;
	time.tv_sec ^= pid << 16;

	/* Make a DES 64-bit block. */
	LONG_TO_CHAR_8(seed, time.tv_usec, time.tv_sec);

	/* Make a DES key from the seed */
	VOID des_key((des_cblock *) seed, ks);

	/* Encrypt the counter with the new key */
	VOID des_dea((des_cblock *) cnt, (des_cblock *) cnt, ks, DES_ENCRYPT);

	/* Put the xor of the counter and "seed key" as the new key. */
	XOR2_8((*cblock), cnt, seed);

	return 0;
}
