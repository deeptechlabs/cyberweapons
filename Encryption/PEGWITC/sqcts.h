#ifndef __SQCTS_H
#define __SQCTS_H

/*
	Ciphertext Stealing (CTS) mode support

	IMPORTANT REMARKS:
	
	1.	This is a variant of  Cipher Block Chaining which relaxes the restriction
		that the buffer length be a multiple of  SQUARE_BLOCKSIZE.  Note that the
		buffer length must still be >= SQUARE_BLOCKSIZE.
	2.	The IV is encrypted to avoid the possibility of being correlated with the
		plaintext.
*/
  
#include "square.h"

typedef struct {
	squareKeySchedule roundKeys_e, roundKeys_d;
	byte mask[SQUARE_BLOCKSIZE];
} squareCtsContext;

void squareCtsInit    (squareCtsContext *ctxCts, const squareBlock key);
void squareCtsSetIV   (squareCtsContext *ctxCts, const squareBlock iv);
void squareCtsEncrypt (squareCtsContext *ctxCts, byte *buffer, unsigned length);
void squareCtsDecrypt (squareCtsContext *ctxCts, byte *buffer, unsigned length);
void squareCtsFinal   (squareCtsContext *ctxCts);

#endif /* __SQCTS_H */
