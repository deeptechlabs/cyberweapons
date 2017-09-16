/*----------------------------*/
/* Cipher Text Stealing mode  */
/*----------------------------*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "square.h"
#include "sqcts.h"

#define D(p) ((word32 *)(p))

#define COPY_BLOCK(target, source) \
{ \
	(target)[0] = (source)[0]; \
	(target)[1] = (source)[1]; \
	(target)[2] = (source)[2]; \
	(target)[3] = (source)[3]; \
} /* COPY_BLOCK */


void squareCtsInit (squareCtsContext *ctxCts, const squareBlock key)
{
	assert (ctxCts != NULL);
	assert (key != NULL);
	memset (ctxCts, 0, sizeof (squareCtsContext));
	squareGenerateRoundKeys (key, ctxCts->roundKeys_e, ctxCts->roundKeys_d);
} /* squareCtsInit */


void squareCtsSetIV (squareCtsContext *ctxCts, const squareBlock iv)
{
	assert (ctxCts != NULL);
	if (iv != NULL) {
		memcpy (ctxCts->mask, iv, SQUARE_BLOCKSIZE);
	}
	/* Encrypt the IV so that possibility of correlation with ciphertext is avoided */
	squareEncrypt (D(ctxCts->mask), ctxCts->roundKeys_e);
} /* squareCtsSetIV */


void squareCtsEncrypt (squareCtsContext *ctxCts, byte *buffer, unsigned length)
{
	byte *mask;
	unsigned i;

	assert (ctxCts != NULL);
	assert (buffer != NULL);
	assert (length >= SQUARE_BLOCKSIZE);
	mask = ctxCts->mask;
	while (length >= SQUARE_BLOCKSIZE) {
		/* mask and encrypt the current block: */
		D(buffer)[0] ^= D(mask)[0];
		D(buffer)[1] ^= D(mask)[1];
		D(buffer)[2] ^= D(mask)[2];
		D(buffer)[3] ^= D(mask)[3];
		squareEncrypt (D(buffer), ctxCts->roundKeys_e);
		/* update the mask: */
		mask = buffer;
		/* proceed to the next block, if any: */
		buffer += SQUARE_BLOCKSIZE;
		length -= SQUARE_BLOCKSIZE;
	}
	/* save last encrypted block in context */
	COPY_BLOCK (D(ctxCts->mask), D(mask));
	if (length != 0) {
		/* "ciphertext stealing" (using ctxCts->mask as temporary buffer) */
		for (i = 0; i < length; i++) {
			ctxCts->mask[i] ^= buffer[i];
		}
		memcpy (buffer, mask, length); /* last, incomplete block */
		squareEncrypt (D(ctxCts->mask), ctxCts->roundKeys_e);
		memcpy (mask, ctxCts->mask, SQUARE_BLOCKSIZE); /* next-to-last, complete block */
		/* note that ctxCts->mask contains an encrypted block still unused as mask */
	}
	mask = NULL;
} /* squareCtsEncrypt */


void squareCtsDecrypt (squareCtsContext *ctxCts, byte *buffer, unsigned length)
{
	unsigned i;
	squareBlock temp;
 
	assert (ctxCts != NULL);
	assert (buffer != NULL);
	assert (length >= SQUARE_BLOCKSIZE);
	while (length >= 2*SQUARE_BLOCKSIZE) {
		/* save the current block for chaining: */
		COPY_BLOCK (D(temp), D(buffer));
		/* decrypt and unmask the block: */
		squareDecrypt (D(buffer), ctxCts->roundKeys_d);
		D(buffer)[0] ^= D(ctxCts->mask)[0];
		D(buffer)[1] ^= D(ctxCts->mask)[1];
		D(buffer)[2] ^= D(ctxCts->mask)[2];
		D(buffer)[3] ^= D(ctxCts->mask)[3];
		/* update the mask: */
		COPY_BLOCK (D(ctxCts->mask), D(temp));
		/* proceed to the next block, if any: */
		buffer += SQUARE_BLOCKSIZE;
		length -= SQUARE_BLOCKSIZE;
	}
	/* now SQUARE_BLOCKSIZE <= length < 2*SQUARE_BLOCKSIZE */
	/* save the current block for chaining: */
	COPY_BLOCK (D(temp), D(buffer));
	if (length > SQUARE_BLOCKSIZE) {
		/* decrypt and unmask the last, incomplete block: */
		squareDecrypt (D(buffer), ctxCts->roundKeys_d);
		for (i = 0; i < length - SQUARE_BLOCKSIZE; i++) {
			/* at this point, buffer[i + SQUARE_BLOCKSIZE]  contains */
			/* a cipherbyte C, and buffer[i] contains the XOR of the */
			/* same cipherbyte with the corresponding plainbyte P... */
			buffer[i] ^= (buffer[i + SQUARE_BLOCKSIZE] ^= buffer[i]);
			/* ... now buffer[i] contains only the cipherbyte C, and */
			/* buffer[i + SQUARE_BLOCKSIZE] contains the plainbyte P */
		}
		/* decrypt the next-to-last, complete block: */
		squareDecrypt (D(buffer), ctxCts->roundKeys_d);
	} else {
		/* decrypt the last, complete block: */
		squareDecrypt (D(buffer), ctxCts->roundKeys_d);
	}
	D(buffer)[0] ^= D(ctxCts->mask)[0];
	D(buffer)[1] ^= D(ctxCts->mask)[1];
	D(buffer)[2] ^= D(ctxCts->mask)[2];
	D(buffer)[3] ^= D(ctxCts->mask)[3];
	/* update the mask: */
	COPY_BLOCK (D(ctxCts->mask), D(temp));

#ifdef DESTROY_TEMPORARIES
	/* destroy potentially sensitive data: */
	memset (temp, 0, sizeof (temp));
	/* N.B. this cleanup is in principle unnecessary */
	/* as temp only contains encrypted (public) data */
#endif /* ?DESTROY_TEMPORARIES */
} /* squareCtsDecrypt */


void squareCtsFinal (squareCtsContext *ctxCts)
{
	assert (ctxCts != NULL);
	memset (ctxCts, 0, sizeof (squareCtsContext));
} /* squareCtsFinal */
