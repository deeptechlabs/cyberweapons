#ifndef _RIPEMD160_DEFINED

#define _RIPEMD160_DEFINED

/* The RIPEMD-160 block size and message digest sizes, in bytes */

#define RIPEMD160_DATASIZE		64
#define RIPEMD160_DIGESTSIZE	20

/* The structure for storing RIPEMD-160 info */

typedef struct {
			   LONG digest[ 5 ];			/* Message digest */
			   LONG countLo, countHi;		/* 64-bit bit count */
			   LONG data[ 16 ];				/* RIPEMD-160 data buffer */
#ifdef _BIG_WORDS
			   BYTE dataBuffer[ RIPEMD160_DATASIZE ];	/* Byte buf.for data */
#endif /* _BIG_WORDS */
			   BOOLEAN done;				/* Whether final digest present */
			   } RIPEMD160_INFO;

/* Message digest functions */

void ripemd160Initial( RIPEMD160_INFO *ripemd160Info );
void ripemd160Update( RIPEMD160_INFO *ripemd160Info, BYTE *buffer, int count );
void ripemd160Final( RIPEMD160_INFO *ripemd160Info );

#endif /* _RIPEMD160_DEFINED */
