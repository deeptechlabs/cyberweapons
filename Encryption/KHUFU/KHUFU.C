/*
 * This is a quick hack to implement/test the Khufu encryption method described
 * in Ralph Merkle's paper.  All but the actual Khufu encryption algorithm in
 * this code are hacks... they are just for illustration.
 *
 * Copyright 1989 by Rayan Zachariassen.  Use and distribute as you see fit
 * as long as you send code/algorithm improvements or interesting results
 * back to me.
 */

#include <stdio.h>

#ifdef	sun
typedef unsigned int uint32;
typedef unsigned char ubyte;
#endif

main(argc, argv)
	int argc;
	char *argv[];
{
	register int i, n;
	uint32 a[2];
	uint32 buf[8*BUFSIZ/sizeof (uint32)];

	initialize((uint32 *)main /* 2 key-words */,
		   2 * sizeof (uint32), 5 /*seed*/);
	while ((n = read(0, (char *)buf, sizeof buf)) > 0) {
		for (i = 0; i < (n/sizeof (uint32)); i += 2 /* 64 bits */)
			if (argc == 1)
				khufu(&buf[i]);
			else
				khufuinv(&buf[i]);
		(void) write(1, (char *)buf, n);
	}
	exit(0);
}

#define	ENOUGH	16
#define	OCTETS	((ENOUGH+7)/8)

uint32 InitialSBox[256];
uint32 SBoxes[OCTETS][256];
uint32 AuxKeys[4];

khufu(datap)
	uint32	*datap;
{
	register uint32 L, R;
	register int octet;

	L = *datap++ ^ AuxKeys[0];
	R = *datap ^ AuxKeys[1];

	for (octet = OCTETS-1; octet >= 0; --octet) {
#define	ROUND(LEFT,RIGHT,ROTN) \
		RIGHT ^= SBoxes[octet][LEFT & 0xff]; \
		LEFT = (LEFT)>>(ROTN) | (LEFT)<<(32-ROTN);

		ROUND(L,R,16);
		ROUND(R,L,16);
		ROUND(L,R,8);
		ROUND(R,L,8);
		ROUND(L,R,16);
		ROUND(R,L,16);
		ROUND(L,R,24);
		ROUND(R,L,24);
	}

	*datap = R ^ AuxKeys[3];
	*--datap = L ^ AuxKeys[2];
}

khufuinv(datap)
	uint32	*datap;
{
	register uint32 L, R;
	register int octet;

	L = *datap++ ^ AuxKeys[2];
	R = *datap ^ AuxKeys[3];

	for (octet = 0; octet < OCTETS; ++octet) {
#define	ROUNDINV(LEFT,RIGHT,ROTN) \
		LEFT = (LEFT)<<(ROTN) | (LEFT)>>(32-ROTN); \
		RIGHT ^= SBoxes[octet][LEFT & 0xff]; \

		ROUNDINV(R,L,24);
		ROUNDINV(L,R,24);
		ROUNDINV(R,L,16);
		ROUNDINV(L,R,16);
		ROUNDINV(R,L,8);
		ROUNDINV(L,R,8);
		ROUNDINV(R,L,16);
		ROUNDINV(L,R,16);
	}

	*datap = R ^ AuxKeys[1];
	*--datap = L ^ AuxKeys[0];
}


#define	STATEWORDS	(64/sizeof (int))

uint32 state64[STATEWORDS];

static uint32
_getrand(i)
	register int i;
{
	static int nleft = 0;

	if (nleft == 0) {
		for (i = 0; i < STATEWORDS; i += (8/sizeof (int)))
			khufu(&state64[i]);
		nleft = STATEWORDS;
	}
	return (state64[--nleft] % (256-i)) + i;
}

initialize(key, keylength, seed)
	uint32	*key;
	int	keylength;		/* in bytes */
	int	seed;
{
	register int column, i;
	register ubyte *n1p, *n2p;
	register ubyte tmp, *SBox;
	register int octet;

	/* somehow get key diffused into state64 */
	diffuse(key, keylength, state64, sizeof state64);

	/* make the initial sbox... (this is just a quick hack for now) */
	srandom(seed);
	for (i = 0; i < 256; ++i)
		InitialSBox[i] = random();

	AuxKeys[0] = AuxKeys[1] = AuxKeys[2] = AuxKeys[3] = 0;

	for (octet = OCTETS-1; octet >= 0 ; --octet) {
		SBox = (ubyte *)&SBoxes[octet][0];
		(void) bcopy(InitialSBox, SBox, sizeof InitialSBox);
		for (column = 0; column < 4; ++column) {
			for (i = 0; i < 1024; i += 4) {
				n1p = &SBox[column + i];
				n2p = &SBox[column + ((_getrand(i>>2))<<2)];
				tmp = *n1p;
				*n1p = *n2p;
				*n2p = tmp;
			}
		}
	}

	/* now get key diffused into AuxKeys */
	diffuse(key, keylength, AuxKeys, sizeof AuxKeys);
}


diffuse(k, klen, dif, diflen)
	uint32 *k, *dif;
	int klen, diflen;
{
	/* another quick hack */
	for (; diflen >= klen ; diflen -= klen)
		(void) bcopy((char *)k, ((char *)dif)+diflen-klen, klen);
	if (diflen)
		(void) bcopy((char *)k, (char *)dif, diflen);
}


