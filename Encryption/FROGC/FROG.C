/*

FILENAME:  frog.c

AES Submission: FROG

Principal Submitter: TecApro

Reference ANSI-C source code

Source code is documented according to the Supporting Documentation
of the AES Submission Package.

*/


#include <string.h>
#include <stdlib.h>
#include "frog.h"

/* Internal FROG functions */

void makePermutation (BYTE* permutation, BYTE lastElem) {
	/*	Receives an arbitarty byte arror of (lastElem -1) elements and
		returns a permutation with values between 0 and lastElem.
		Reference Text: section B.1.3   */

	WORD i, index = 0, k, last = lastElem;
	BYTE use[256];

	/* Initialize use array */
	for (i = 0; i <= lastElem; i++)
		use[i] = (BYTE) i;

	/* Fill permutation with non-sequencial, unique values */
	for (i = 0; i < lastElem; i++) {
		index = (index+permutation[i]) % (last+1);
		permutation[i] = use[index];

		/* Remove use[index] value from use array */
		if (index < last) {
			for (k = index; k <= last-1; k++)
				use[k] = use[k+1];
		}
		if (index > --last)
			index = 0;
	}
	permutation[lastElem] = use[0];
}

void invertPermutation (BYTE* permutation, BYTE lastElem) {
	/* Inverts a permutation array with (lastElem+1) values */
	WORD i;
	BYTE invert[256];

	for (i = 0; i <= lastElem; i++)
		invert [permutation[i]] = (BYTE) i;

	memcpy (permutation, invert, lastElem+1);
}

void makeInternalKey (BYTE direction, tInternalKey internalKey) {
	/* Processes unstructured internalKey into a valid internalKey.
	   Reference Text: section B.1.2 */

	BYTE iteration, j, i, k, l, used[BLOCK_SIZE];

	for (iteration = 0; iteration < numIter; iteration++) {
		makePermutation (internalKey[iteration].SubstPermu, 255);

		if (direction == DIR_DECRYPT)
			invertPermutation(internalKey[iteration].SubstPermu, 255);

		/* See B.1.1a */
		makePermutation(internalKey[iteration].BombPermu, BLOCK_SIZE-1);

		/* Join smaller cycles in BombPermu into one cycle
		   (See B.1.1b for rational and B.1.4 for code) */

		memset (used, 0, BLOCK_SIZE);
		j = 0;
		for (i = 0; i < BLOCK_SIZE-1; i++) {
			if (internalKey[iteration].BombPermu[j] == 0) {
				k = j;

				do {
					k = (k + 1) % BLOCK_SIZE;
				} while (used[k] != 0);

				internalKey[iteration].BombPermu[j] = k;
				l = k;

				while (internalKey[iteration].BombPermu[l] != k)
					l = internalKey[iteration].BombPermu[l];

				internalKey[iteration].BombPermu[l] = 0;
			}
			used[j] = 1;
			j = internalKey[iteration].BombPermu[j];
		}
		/* Remove references to next element within BombPermu.
		   See B.1.1c for rational and B.1.4.b for code. */
		for (i = 0; i < BLOCK_SIZE; i++) {
			if (i == BLOCK_SIZE -1)
				j = 0;
			else
				j = i + 1;
			if (internalKey[iteration].BombPermu[i] == j) {
				if (j == BLOCK_SIZE -1)
					k = 0;
				else
					k = j + 1;
				internalKey[iteration].BombPermu[i] = k;
			}
		}
	}
}

void encryptFrog (BYTE* plainText, tInternalKey internalKey) {
	/* Encrypt plainText using internalKey - (internal cycle) See B.1.1 */
	BYTE i, iteration;

	for (iteration = 0; iteration < numIter; iteration++) {
		for (i = 0; i < BLOCK_SIZE; i++) {
			plainText[i] = internalKey[iteration].SubstPermu[plainText[i] ^ internalKey[iteration].xorBu[i]];
			if (i < BLOCK_SIZE -1)
				plainText[i+1] ^= plainText[i];
			else
				plainText[0] ^= plainText[i];
			plainText[internalKey[iteration].BombPermu[i]] ^= plainText[i];
		}
	}
}

void decryptFrog (BYTE *cipherText, tInternalKey internalKey) {
	/* Decrypt cipherText using internalKey - (internal cycle) See B.1.1 */
	signed short i, iteration;

	for (iteration = numIter-1; iteration >= 0; iteration--)  {
		for (i = BLOCK_SIZE -1; i >= 0; i--) {
			cipherText[internalKey[iteration].BombPermu[i]] ^= cipherText[i];
			if (i < BLOCK_SIZE -1)
				cipherText[i+1] ^= cipherText[i];
			else
				cipherText[0] ^= cipherText[i];
			cipherText[i] = internalKey[iteration].SubstPermu[cipherText[i]] ^ internalKey[iteration].xorBu[i];
		}
	}
}

void hashKey (BYTE *binaryKey, int keyLen, tInternalKey *randomKey) {
	/* Hash binaryKey of keyLen bytes into randomKey
	   Reference Text: section B.1.2 */

	tBuffer IVbuffer;
	tInternalKey simpleKey;
	WORD internalKeyLen, i, bytesToCopy;
	BYTE* pSimpleKey = (BYTE*) simpleKey;
	BYTE* pRandomKey = (BYTE*) randomKey;
	BYTE iSeed, iKey, last, keyLen1 = keyLen - 1;
	/* Values defined from RAND Corporation's "A Million Random Digits" */
	BYTE randomSeed[251] = {
		113, 21,232, 18,113, 92, 63,157,124,193,166,197,126, 56,229,229,
			156,162, 54, 17,230, 89,189, 87,169,  0, 81,204,  8, 70,203,225,
			160, 59,167,189,100,157, 84, 11,  7,130, 29, 51, 32, 45,135,237,
			139, 33, 17,221, 24, 50, 89, 74, 21,205,191,242, 84, 53,  3,230,
			231,118, 15, 15,107,  4, 21, 34,  3,156, 57, 66, 93,255,191,  3,
			85,135,205,200,185,204, 52, 37, 35, 24, 68,185,201, 10,224,234,
			7,120,201,115,216,103, 57,255, 93,110, 42,249, 68, 14, 29, 55,
			128, 84, 37,152,221,137, 39, 11,252, 50,144, 35,178,190, 43,162,
			103,249,109,  8,235, 33,158,111,252,205,169, 54, 10, 20,221,201,
			178,224, 89,184,182, 65,201, 10, 60,  6,191,174, 79, 98, 26,160,
			252, 51, 63, 79,  6,102,123,173, 49,  3,110,233, 90,158,228,210,
			209,237, 30, 95, 28,179,204,220, 72,163, 77,166,192, 98,165, 25,
			145,162, 91,212, 41,230,110,  6,107,187,127, 38, 82, 98, 30, 67,
			225, 80,208,134, 60,250,153, 87,148, 60, 66,165, 72, 29,165, 82,
			211,207,  0,177,206, 13,  6, 14, 92,248, 60,201,132, 95, 35,215,
			118,177,121,180, 27, 83,131, 26, 39, 46, 12};

		/* Initialize SimpleKey with user supplied key material and random seed.
		   See B.1.2a */
		iSeed = iKey = 0;
		internalKeyLen = sizeof (tInternalKey);
		for (i = 0; i < internalKeyLen; i++) {
			pSimpleKey[i] = randomSeed[iSeed] ^ binaryKey[iKey];
			if (++iSeed == 251)
				iSeed = 0;
			if (++iKey == keyLen)
				iKey = 0;
		}

		/* Convert simpleKey into a valid internal key (see B.1.2b) */
		makeInternalKey (DIR_ENCRYPT, simpleKey);

		/* Initialize IV vector (see B.1.2c) */
		last = keyLen1 -1;

		if (keyLen >= BLOCK_SIZE)
			last = BLOCK_SIZE -1;

		memset (IVbuffer, 0, BLOCK_SIZE);

		for (i = 0; i <= last; i++)
			IVbuffer[i] ^= binaryKey[i];

		IVbuffer[0] ^= keyLen;

		/* Fill randomKey with the cipher texts produced successive
		   encryptions (see B.1.2.c) */
		for (i = 0; i != internalKeyLen; i += bytesToCopy) {
			encryptFrog (IVbuffer, simpleKey);
			if ((bytesToCopy = internalKeyLen - i) > BLOCK_SIZE)
				bytesToCopy = BLOCK_SIZE;
			memcpy (&pRandomKey[i], &IVbuffer, bytesToCopy);
		}
}

void shiftBitLeft (BYTE *buffer, int size) {
	/* moves an entire block of size bytes 1 bit to the left */
	int index;
	
	for (index = size - 1; index >= 0; index--) {
		buffer[index] = buffer[index] << 1;
		if (index > 0)
			buffer[index] |= (buffer[index -1] >> 7);
	}
}


BYTE hexToBinary (BYTE value) {
	/* Convert a ASCII hex digit into corresponding binary value */

	if (value >= '0' && value <= '9')
		return value - '0';
	return value - 'a' + 10;
}

void hexStringToBinary (char *hexString, BYTE *binaryData, int binaryLen) {
	/* Convert ASCII string into binary value of binaryLen bytes */
	/* hexString must be at least 2x length of binaryData */

	BYTE *pBinary;

	for (pBinary = binaryData + binaryLen-1; pBinary >= binaryData; pBinary--)
		*pBinary = (hexToBinary (*hexString++) << 4) | hexToBinary (*hexString++);
}

void binaryToHexString (BYTE *binaryArray, char *hexArray, int Size) {
	// Convert binary array into a null terminated, hex string */	
	static char hexDigits [] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	int i;
	
	for (i = Size-1; i >= 0; i--) {
		*hexArray++ = hexDigits [binaryArray[i] >> 4];
		*hexArray++ = hexDigits [binaryArray[i] & 0x0F];
	}
	*hexArray = 0;
}

/* AES Functions */

int makeKey (keyInstance *keyInst, BYTE direction, int keyLen, char *keyMaterial) {
	/* Produce a keyInstance according to NIST standard AES API */
	BYTE binaryKey [MAX_KEY_SIZE];

	keyLen /= 8; /* Internal functions lengths are in bytes, not bits */
	
	if (keyLen < MIN_KEY_SIZE || keyLen > MAX_KEY_SIZE)
		return BAD_KEY_MAT;
	
	if (direction != DIR_ENCRYPT && direction != DIR_DECRYPT)
		return BAD_KEY_DIR;
	
	hexStringToBinary (keyMaterial, binaryKey, keyLen); /* Convert ASCII string */
	keyInst->direction = direction;
	keyInst->keyLen = keyLen;

	/* Fill internal key with hashed keyMaterial */
	hashKey (binaryKey, keyLen, &keyInst->internalKey);
	/* Convert internalKey into a valid format (see B.1.2.e) */
	makeInternalKey (direction, keyInst->internalKey);
	return TRUE;
}

int blockDecrypt (cipherInstance *cipher, keyInstance *keyInst, BYTE *input,
				  int inputLen, BYTE *outBuffer) {

	/* Decrypt function according to NIST standard AES API
	   Uses the cipherInstance object and the keyInstance object to decrypt
	   one block of data in the input buffer. */

	int x;

	inputLen /= 8;  /* Internal functions use byte sizes */

	if (inputLen != BLOCK_SIZE)
		return  BAD_BLOCK_LENGTH;

	if (keyInst->direction != DIR_DECRYPT)
		return BAD_KEY_DIR;

	memcpy (outBuffer, input, BLOCK_SIZE); /* Preserve input buffer */

	/* Process input into outBuffer according to mode */

	switch (cipher->mode) {
	case MODE_CBC :
		decryptFrog (outBuffer, keyInst->internalKey);
		for (x = 0; x < BLOCK_SIZE; x++)
			outBuffer[x] ^= cipher->IV[x];
		memcpy (cipher->IV, input, BLOCK_SIZE);
		break;
	case MODE_ECB :
		decryptFrog (outBuffer, keyInst->internalKey);
		break;
	case MODE_CFB1:
	/* Receives cipher bit in most significant position of input and
	   returns plaintext bit in most significant position of outBuffer.
	   When decrypting in CFB1 mode, makeKey must be called with
		direction set to DIR_ENCRYPT! */
		encryptFrog (cipher->IV, keyInst->internalKey);
		outBuffer[BLOCK_SIZE-1] = cipher->IV[BLOCK_SIZE-1] ^ input[BLOCK_SIZE-1];
		shiftBitLeft (cipher->IV, BLOCK_SIZE);
		cipher->IV[0] |= (input[BLOCK_SIZE-1] >> 7);
	default:
		return BAD_CIPHER_MODE;
	}
	return TRUE;
}

int blockEncrypt(cipherInstance *cipher, keyInstance *keyInst, BYTE *input,
				 int inputLen, BYTE *outBuffer) {

	/* Encrypt function according to NIST standard AES API
	   Uses the cipherInstance object and the keyInstance object to encrypt
	   one block of data in the input buffer. */

	int x;

	inputLen /= 8;  /* Internal functions use byte sizes */
	
	if (inputLen != BLOCK_SIZE)
		return BAD_BLOCK_LENGTH;
	
	if (keyInst->direction != DIR_ENCRYPT)
		return BAD_KEY_DIR;
	
	memcpy (outBuffer, input, BLOCK_SIZE);  /* Preserve input buffer */

	/* Process input into outBuffer according to mode */

	switch (cipher->mode) {
	case MODE_CBC:
		for (x = 0; x < BLOCK_SIZE; x++)
			outBuffer[x] ^= cipher->IV[x];
		encryptFrog (outBuffer, keyInst->internalKey);
		memcpy (cipher->IV, outBuffer, BLOCK_SIZE);
		break;
	case MODE_ECB:
		encryptFrog (outBuffer, keyInst->internalKey);
		break;
	case MODE_CFB1:
	 /* Receives plaintext bit in most significant position of input and
		returns ciphertext bit in most significant position of outBuffer */

		encryptFrog (cipher->IV, keyInst->internalKey);

		outBuffer[BLOCK_SIZE-1] = cipher->IV[BLOCK_SIZE-1] ^ input[BLOCK_SIZE-1];
		shiftBitLeft(cipher->IV, BLOCK_SIZE);
		cipher->IV[0] = cipher->IV[0] | (outBuffer[BLOCK_SIZE-1] >> 7);
		break;
	default :
		return BAD_CIPHER_MODE;
	}
	return TRUE;
}

int cipherInit (cipherInstance *cipher, BYTE mode, char *IV) {
	/* Cipher Initialization function according to NIST standard AES API.
	   Initializes the cipher with the mode and, if present, sets the
	   Initialization Vector */

	cipher->mode = mode;
	if (IV != NULL) {
		if (strlen (IV) < MAX_IV_SIZE * 2)
			return BAD_IV_LENGTH;
		hexStringToBinary (IV, cipher->IV, MAX_IV_SIZE);
	}

	return TRUE;
}

