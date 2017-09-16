/*
 *	Hash User's Ascii Key into 1024 Bits with DES in CBC Mode
 *	D.P.Mitchell  83/05/24.
 */

#include "crypt.h"
#define KEY (*kstring ? (*kstring++ & 0377) : 0)

Block xkey[SUPERSIZE];

Block
key_crunch(kstring)
char *kstring;
{
	register n;
	Block hashkey;

	hashkey.right = 0x4f7b0289;
	hashkey.left  = 0x25da0a19;
	key_setup(&hashkey, 0);
	xkey[0].left  = 0;
	xkey[0].right = 0;
	for (n = 0; n < SUPERSIZE; n++) {
		xkey[n].left  ^= KEY << 0;
		xkey[n].left  ^= KEY << 8;
		xkey[n].left  ^= KEY << 16;
		xkey[n].left  ^= KEY << 24;
		xkey[n].right ^= KEY << 0;
		xkey[n].right ^= KEY << 8;
		xkey[n].right ^= KEY << 16;
		xkey[n].right ^= KEY << 24;
		des(&xkey[n]);
		if (n < SUPERSIZE - 1)
			xkey[n+1] = xkey[n];
	}
	return xkey[SUPERSIZE - 1];
}

Block
recrunch()
{
	register m, n;

	for (n = 0; n < SUPERSIZE; n++) {
		m = (n + SUPERSIZE - 1) % SUPERSIZE;
		xkey[n].left  ^= xkey[m].left;
		xkey[n].right ^= xkey[m].right;
		des(&xkey[n]);
	}
	return xkey[SUPERSIZE - 1];
}
