/*
 *	Generate a Truly Block 64-bit Block
 *	D.P.Mitchell  83/06/28.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "crypt.h"

Block
rand_block()
{
	register i;
	Block block;
	extern long time();

	block.left  ^= 0x9662f394;
	block.right ^= 0x9f17c55f;
	key_setup(&block, 0);
	block.right = NEXT(801324423L);
	block.left = NEXT(time((long *)0));
	des(&block);
#if 0
	for (i = 0; strlen(volatile_file[i]); i++) {
		if (stat(volatile_file[i], &buf) == -1)
			continue;
		block.right ^= NEXT(buf.st_atime);
		block.left ^= NEXT(buf.st_mtime);
		des(&block);
	}
#endif
	return block;
}
