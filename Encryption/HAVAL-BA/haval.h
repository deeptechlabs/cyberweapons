#ifndef __HAVAL_H
#define __HAVAL_H

#include <stddef.h>

#ifndef USUAL_TYPES
	#define USUAL_TYPES
	typedef unsigned char	byte;
	typedef unsigned short	word16;
	typedef unsigned long	word32;
#endif /* ?USUAL_TYPES */
	
typedef struct {
	word16 passes, hashLength;	/* HAVAL parameters */
	word32 digest[8];			/* message digest (fingerprint) */
	byte   block[128];			/* context data block */
	size_t occupied;			/* number of occupied bytes in the data block */
	word32 bitCount[2];			/* 64-bit message bit count */
	word32 temp[8];				/* temporary buffer */
} havalContext;


int havalInit (havalContext *hcp, int passes, int length);
	/* Initialize a HAVAL hashing context according to the desired	*/
	/* number of passes and hash length.  Returns:					*/
	/* 0: no error.													*/
	/* 1: hcp is NULL.												*/
	/* 2: invalid number of passes (must be 3, 4, or 5).			*/
	/* 3: invalid hash length (must be 128, 160, 192, 224, or 256).	*/
	
int havalUpdate (havalContext *hcp, const byte *dataBuffer, size_t dataLength);
	/* Updates a HAVAL hashing context with a data block dataBuffer	*/
	/* of length dataLength.  Returns:								*/
	/* 0: no error.													*/
	/* 1: hcp is NULL.												*/
	
int havalFinal (havalContext *hcp, byte *digest);
	/* Finished evaluation of a HAVAL digest, clearing the context.	*/
	/* The digest buffer must be large enough to hold the desired	*/
	/* hash length.  Returns:										*/
	/* 0: no error.													*/
	/* 1: hcp is NULL.												*/
	/* 2: digest is NULL.											*/

#endif /* __HAVAL_H */

