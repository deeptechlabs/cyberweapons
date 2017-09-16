#ifndef _MD4_DEFINED

#define _MD4_DEFINED

/* The MD4 block size and message digest sizes, in bytes */

#define MD4_DATASIZE	64
#define MD4_DIGESTSIZE	16

/* The structure for storing MD4 info */

typedef struct {
			   LONG digest[ 4 ];			/* Message digest */
			   LONG countLo, countHi;		/* 64-bit bit count */
			   LONG data[ 16 ];				/* MD4 data buffer */
#ifdef _BIG_WORDS
			   BYTE dataBuffer[ MD4_DATASIZE ];	/* Byte buffer for data */
#endif /* _BIG_WORDS */
			   BOOLEAN done;				/* Whether final digest present */
			   } MD4_INFO;

/* Message digest functions */

void md4Initial( MD4_INFO *md4Info );
void md4Update( MD4_INFO *md4Info, BYTE *buffer, int count );
void md4Final( MD4_INFO *md4Info );

#endif /* _MD4_DEFINED */
