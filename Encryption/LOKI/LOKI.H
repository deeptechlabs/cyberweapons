/*
 *  loki.h - specifies the interface to the LOKI encryption routines.
 *      This library proviloki routines to expand a key, encrypt and
 *      decrypt 64-bit data blocks.  The LOKI Data Encryption Algorithm
 *      is a block cipher which ensures that its output is a complex
 *      function of its input and the key.
 *
 *  Authors:	Lawrie Brown <Lawrie.Brown@adfa.oz.au>	Aug 1989
 *		Matthew Kwan <mkwan@cs.adfa.oz.au>	Sep 1991
 *
 *      Computer Science, UC UNSW, Australian Defence Force Academy,
 *          Canberra, ACT 2600, Australia.
 *
 *  Version:
 *      v1.0 - of loki64.o is current 7/89 lpb
 *	v2.0 - of loki64.c is current 9/91 mkwan
 *	v3.0 - now have loki89.c & loki91.c 10/92 lpb
 *
 *  Copyright 1989 by Lawrie Brown and UNSW. All rights reserved.
 *      This program may not be sold or used as inducement to buy a
 *      product without the written permission of the author.
 *
 *  Description:
 *  The routines provided by the library are:
 *
 *  lokikey(key)	    - expands a key into subkey, for use in 
 *    char  key[8];             encryption and decryption operations.
 *
 *  enloki(b)		    - main LOKI encryption routine, this routine 
 *    char  b[8];               encrypts one 64-bit block b with subkey
 *
 *  deloki(b)		    - main LOKI decryption routine, this routine 
 *    char  b[8];               decrypts one 64-bit block b with subkey
 *
 *  The 64-bit data & key blocks used in the algorithm are specified as eight
 *      unsigned chars. For the purposes of implementing the LOKI algorithm,
 *      these MUST be word aligned with bits are numbered as follows:
 *        [63..56] [55..48] 		...		[7..0]
 *      in  b[0]     b[1]  b[2]  b[3]  b[4]  b[5]  b[6]  b[7]
 */

#define LOKIBLK	8		/* No of bytes in a LOKI data-block          */
#define ROUNDS	16		/* No of LOKI rounds             	     */

typedef unsigned long	Long;   /* type specification for aligned LOKI blocks */

extern Long	lokikey[2];	/* 64-bit key used by LOKI routines          */
extern char	*loki_lib_ver;	/* String with version no. & copyright       */

#ifdef __STDC__			/* declare prototypes for library functions  */
extern void enloki(char b[LOKIBLK]);
extern void deloki(char b[LOKIBLK]);
extern void setlokikey(char key[LOKIBLK]);
#else				/* else just declare library functions extern */
extern void enloki(), deloki(), setlokikey();
#endif __STDC__
