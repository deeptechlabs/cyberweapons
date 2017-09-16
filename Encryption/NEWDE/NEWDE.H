/* newde.h -
 *
 *	Headers and defines for newde.c
 *	Graven Imagery, 1991.
 *
 * Copyright 1988,1989,1990,1991 by Richard Outerbridge
 *	(GEnie : OUTER; CIS : [71755,204])
 */

/* A useful alias on 68000-ish machines, but NOT USED HERE. */

typedef union {
	unsigned long blok[2];
	unsigned short int word[4];
	unsigned char byte[8];
	} M68K;
		
#define EN0 0	 /* MODE == encrypt (MUST be zero!) */
#define DE1 1	 /* MODE == decrypt (MUST be != 0!) */

extern void keyload(unsigned char *, int);
/*			hexkey[8]	MODE
 * Sets the internal key register according to the hexadecimal
 * key contained in the 8 bytes of hexkey, according to the KSX
 * key schedule (see Cryptologia, Vol. 10, No. 3, July 1986)
 * for encryption or decryption using NewDE according to MODE.
 */

extern void newde(unsigned char *, unsigned char *);
/*                      from[8]         to[8]
 * Encrypts/Decrypts (according to the key currently loaded in the
 * internal key register) one block of eight bytes at address 'from'
 * into the block at address 'to'.  They can be the same.
 */

extern void usekey(unsigned long *);
/*                  cookedkey[32]
 * Loads the internal key register with the data in cookedkey.
 */

extern void cpkey(unsigned long *);
/*                  cookedkey[32]
 * Copies the contents of the internal key register into the storage
 * located at &cookedkey[0].
 */

extern void makekey(char *, unsigned char *);
/*               *password, single-length key[8]
 * With a default key, this routine hashes any NULL-terminated string
 * into an eight-byte random-looking key, suitable for use with the
 * keyload() and deskey() routines.
 */

/* newde.h V5.03 rwo 9109.13 11:30 Graven Imagery
 ********************************************************************/
