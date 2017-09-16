/*

	FILENAME:  tests.c
  
	AES Submission: FROG
	
	Principal Submitter: TecApro
	  
*/

#include <stdlib.h>
#include <string.h>

#include "frog.h"
#include "tests.h"

FILE *output = NULL;


/* MonteCarlo & KAT functions */

void MonteCarloTestECB (char *filename, BYTE direction) {
	cipherInstance cipher;
	keyInstance *keyInst;
	tBuffer IB, PT, CT, CTLast;
	int i, j, k, keyLen = 16, nTests, extraBytes;
	char hexIV[MAX_IV_SIZE*2 + 1], hexKeyMaterial [100]; 
	BYTE keyMaterial [MAX_KEY_SIZE], IV [BLOCK_SIZE];
	
	openFile (filename);
	if (direction == DIR_ENCRYPT)
		outputHeader (filename, "Electronic Codebook (ECB) Mode - ENCRYPTION", "Monte Carlo Test");
	else
		outputHeader (filename, "Electronic Codebook (ECB) Mode - DECRYPTION", "Monte Carlo Test");

	keyInst = (keyInstance*) malloc(sizeof( keyInstance));
	memset (IV, 0, BLOCK_SIZE);
	binaryToHexString (IV, hexIV, MAX_IV_SIZE);

	cipherInit (&cipher, MODE_ECB, hexIV);
	
	for (nTests = 2; nTests < 5; nTests++) {
		keyLen = 8 * nTests;
		
		outputInteger ("\nKEYSIZE=%i\n", keyLen*8);
		memset (keyMaterial, 0, MAX_KEY_SIZE);
		memset (IV, 0, BLOCK_SIZE);
		memset (PT, 0, BLOCK_SIZE);
		
		for (i = 0; i < 400; i++) {
			binaryToHexString (keyMaterial, hexKeyMaterial, keyLen);
			makeKey (keyInst, direction, keyLen*8, hexKeyMaterial);
			outputInteger ("\nI=%i\n", i+1);
			outputBinary ("KEY", (BYTE*) keyMaterial, keyLen);
			outputBinary ("PT", PT, BLOCK_SIZE);
			for (j = 0; j < 10000; j++) {
				memcpy (IB, PT, BLOCK_SIZE);
				if (direction == DIR_ENCRYPT)
					blockEncrypt (&cipher, keyInst, IB, BLOCK_SIZE*8, CT);
				else
					blockDecrypt (&cipher, keyInst, IB, BLOCK_SIZE*8, CT);
				memcpy (PT, CT, BLOCK_SIZE);
				if (j < 9999)
					memcpy (CTLast, CT, BLOCK_SIZE);
			}
			outputBinary ("CT", CT, BLOCK_SIZE);
			for (k = 0; k < BLOCK_SIZE; k++)
				keyMaterial[k] ^= CT[k];
			
			/* Add extra key material if required */
			if (keyLen > 16) {
				for (extraBytes = 0, k = BLOCK_SIZE; k < keyLen; k++, extraBytes++)
					keyMaterial[k] ^= CTLast[extraBytes];
			}
			
			memcpy (PT, CT, BLOCK_SIZE);
		}
	}
	outputString ("==========\n");
	closeFile ();
	free (keyInst);
}

void MonteCarloTestCBCEncrypt (char *filename) {
	cipherInstance cipher;
	keyInstance keyInst;
	int keyLen = 16, i, j, k, nTests, extraBytes;
	tBuffer IB, PT, CT, CTLast, CV;
	BYTE keyMaterial [MAX_KEY_SIZE], IV [BLOCK_SIZE];
	char hexIV[MAX_IV_SIZE*2 + 1], hexKeyMaterial [100];
	
	openFile (filename);
	outputHeader (filename, "Cipher Block Chaining (CBC) Mode - ENCRYPTION", "Monte Carlo Test");
	
	memset (keyMaterial, 0, MAX_KEY_SIZE);
	memset (IV, 0, BLOCK_SIZE);
	binaryToHexString (IV, hexIV, MAX_IV_SIZE);
	memset (PT, 0, BLOCK_SIZE);

	binaryToHexString (IV, hexIV, MAX_IV_SIZE);
	cipherInit (&cipher, MODE_ECB, hexIV);

	for (nTests = 2; nTests < 5; nTests++) {
		keyLen = 8 * nTests;
		
		outputInteger ("\nKEYSIZE=%i\n", keyLen*8);
		memset (keyMaterial, 0, MAX_KEY_SIZE);
		memset (IV, 0, BLOCK_SIZE);
		memcpy (CV, IV, BLOCK_SIZE);
		memset (PT, 0, BLOCK_SIZE);
		
		for (i = 0; i < 400; i++) {
			binaryToHexString (keyMaterial, hexKeyMaterial, keyLen);
			makeKey (&keyInst, DIR_ENCRYPT, keyLen*8, hexKeyMaterial);
			
			/* Output i, KEY & PT */
			outputInteger ("\nI=%i\n",i+1);
			outputBinary ("KEY", (BYTE*) keyMaterial, keyLen);
			outputBinary ("CV", CV, BLOCK_SIZE);
			outputBinary ("PT", PT, BLOCK_SIZE);
			
			for (j = 0; j < 10000; j++) {
				for (k = 0; k < BLOCK_SIZE; k++)
					IB[k] = PT[k] ^ CV[k];
				
				blockEncrypt (&cipher, &keyInst, IB, BLOCK_SIZE*8, CT);
				
				if (j==0)
					memcpy (PT, CV, BLOCK_SIZE);
				else
					memcpy (PT, CTLast, BLOCK_SIZE);
				
				memcpy (CV, CT, BLOCK_SIZE);
				if (j < 9999)
					memcpy (CTLast, CT, BLOCK_SIZE);
			}
			outputBinary ("CT", CT, BLOCK_SIZE);
			for (k = 0; k < BLOCK_SIZE; k++)
				keyMaterial[k] ^= CT[k];
			/* Add extra key material if required */
			if (keyLen > 16) {
				for (extraBytes = 0, k = BLOCK_SIZE; k < keyLen; k++, extraBytes++)
					keyMaterial[k] ^= CTLast[extraBytes];
			}
			memcpy (PT, CTLast, BLOCK_SIZE);
			memcpy (CV, CT, BLOCK_SIZE);
		}
	}
	outputString ("==========\n");
	closeFile ();
}

void MonteCarloTestCBCDecrypt (char *filename) {
	cipherInstance cipher;
	keyInstance keyInst;
	int keyLen = 16, i, j, k, nTests, extraBytes;
	tBuffer IB, PT, CT, OB, PTLast, CV;
	BYTE keyMaterial [MAX_KEY_SIZE], IV [BLOCK_SIZE];
	char hexKeyMaterial [100], hexIV[MAX_IV_SIZE*2 + 1];
	
	openFile (filename);
	outputHeader (filename, "Cipher Block Chaining (CBC) Mode - DECRYPTION", "Monte Carlo Test");
	
	memset (IV, 0, BLOCK_SIZE);
	binaryToHexString (IV, hexIV, MAX_IV_SIZE);
	
	cipherInit (&cipher, MODE_ECB, hexIV);
	for (nTests = 2; nTests < 5; nTests++) {
		keyLen = 8 * nTests;
		
		outputInteger ("\nKEYSIZE=%i\n", keyLen*8);
		memset (keyMaterial, 0, MAX_KEY_SIZE);
		memset (IV, 0, BLOCK_SIZE);
		memcpy (CV, IV, BLOCK_SIZE);
		memset (CT, 0, BLOCK_SIZE);
		
		for (i = 0; i < 400; i++) {
			binaryToHexString (keyMaterial, hexKeyMaterial, keyLen);
			makeKey (&keyInst, DIR_DECRYPT, keyLen*8, hexKeyMaterial);
			
			/* Output i, KEY & PT */
			outputInteger ("\nI=%i\n",i+1);
			outputBinary ("KEY", (BYTE*) keyMaterial, keyLen);
			outputBinary ("CV", CV, BLOCK_SIZE);
			outputBinary ("CT", CT, BLOCK_SIZE);
			
			for (j = 0; j < 10000; j++) {
				memcpy (IB, CT, BLOCK_SIZE);
				
				blockDecrypt (&cipher, &keyInst, IB, BLOCK_SIZE*8, OB);
				
				for (k = 0; k < BLOCK_SIZE; k++)
					PT[k] = OB[k] ^ CV[k];
				
				memcpy (CV, CT, BLOCK_SIZE);
				if (j < 9999)
					memcpy (CT, PT, BLOCK_SIZE);
				
				if (j < 9999)
					memcpy (PTLast, PT, BLOCK_SIZE);
			}
			outputBinary ("PT", PT, BLOCK_SIZE);
			for (k = 0; k < BLOCK_SIZE; k++)
				keyMaterial[k] ^= PT[k];
			/* Add extra key material if required */
			if (keyLen > 16) {
				for (extraBytes = 0, k = BLOCK_SIZE; k < keyLen; k++, extraBytes++)
					keyMaterial[k] ^= PTLast[extraBytes];
			}
			memcpy (CV, CT, BLOCK_SIZE);
			memcpy (CT, PT, BLOCK_SIZE);
		}
	}
	outputString ("==========\n");
	closeFile ();
}

void VariableKeyKAT (char *filename) {
	cipherInstance cipherInst;
	keyInstance *EncryptKeyInst;
	int i, nTests, keyLen = 16;
	
	BYTE PT [BLOCK_SIZE], CT [BLOCK_SIZE], keyMaterial [MAX_KEY_SIZE], IV [BLOCK_SIZE];
	BYTE *pShiftBitMarker;
	char hexKeyMaterial [100], hexIV[MAX_IV_SIZE*2 + 1];
	
	
	openFile (filename);
	outputHeader (filename, "Electronic Codebook (ECB) Mode", "Variable Key Known Answer Tests");
	
	EncryptKeyInst = (keyInstance*) malloc(sizeof( keyInstance));
	
	memset (IV, 0, BLOCK_SIZE);
	binaryToHexString (IV, hexIV, MAX_IV_SIZE);
	
	cipherInit (&cipherInst, MODE_ECB, hexIV);
	
	for (nTests = 2; nTests < 5; nTests++) {
		keyLen = 8 * nTests;
		memset (keyMaterial, 0, MAX_KEY_SIZE);
		memset (PT, 0, BLOCK_SIZE);
		pShiftBitMarker = (BYTE*) keyMaterial + keyLen-1;
		*pShiftBitMarker = 0x80;
		
		outputInteger ("\nKEYSIZE=%i\n\n", keyLen*8);
		outputBinary ("PT", PT, BLOCK_SIZE);
		
		for (i = 0; i < keyLen * 8; i++) {
			binaryToHexString (keyMaterial, hexKeyMaterial, keyLen);
			makeKey (EncryptKeyInst, DIR_ENCRYPT, keyLen*8, hexKeyMaterial);
			memset (PT, 0, BLOCK_SIZE);
			
			blockEncrypt (&cipherInst, EncryptKeyInst, PT, BLOCK_SIZE*8, CT);
			/* Output i, KEY & PT */
			outputInteger ("\nI=%i\n",i+1);
			outputBinary ("KEY", (BYTE*) keyMaterial, keyLen);
			outputBinary ("CT", CT, BLOCK_SIZE);
			
			/* Shift bit across keyLen bytes */
			if ((*pShiftBitMarker = (*pShiftBitMarker >> 1)) == 0) {
				if (pShiftBitMarker > keyMaterial) {
					pShiftBitMarker--;
					*pShiftBitMarker = 0x80;
				}
			}
			
		}
	}
	outputString ("==========\n");
	closeFile ();
	free (EncryptKeyInst);
}


void VariableTextKAT (char *filename) {
	cipherInstance cipherInst;
	keyInstance *EncryptKeyInst;
	int i, nTests, keyLen = 16;
	
	BYTE PT [BLOCK_SIZE], CT [BLOCK_SIZE], keyMaterial [MAX_KEY_SIZE], IV [BLOCK_SIZE];
	BYTE *pShiftBitMarker;
	char hexKeyMaterial [100], hexIV[MAX_IV_SIZE*2 + 1];
	
	
	openFile (filename);
	outputHeader (filename, "Electronic Codebook (ECB) Mode", "Variable Text Known Answer Tests");
	
	EncryptKeyInst = (keyInstance*) malloc(sizeof( keyInstance));

	memset (IV, 0, BLOCK_SIZE);
	binaryToHexString (IV, hexIV, MAX_IV_SIZE);

	cipherInit (&cipherInst, MODE_ECB, hexIV);
	
	for (nTests = 2; nTests < 5; nTests++) {
		keyLen = 8 * nTests;
		memset (keyMaterial, 0, keyLen);
		memset (PT, 0, BLOCK_SIZE);
		pShiftBitMarker = (BYTE*) PT + BLOCK_SIZE - 1;
		*pShiftBitMarker = 0x80;
		
		outputInteger ("\nKEYSIZE=%i\n\n", keyLen*8);
		outputBinary ("KEY", (BYTE*) keyMaterial, keyLen);
		
		for (i = 0; i < BLOCK_SIZE * 8; i++) {
			memset (keyMaterial, 0, keyLen);
			binaryToHexString (keyMaterial, hexKeyMaterial, keyLen);
			makeKey (EncryptKeyInst, DIR_ENCRYPT, keyLen*8, hexKeyMaterial);
			
			blockEncrypt (&cipherInst, EncryptKeyInst, PT, BLOCK_SIZE*8, CT);
			
			/*  Output i, KEY & PT */
			outputInteger ("\nI=%i\n",i+1);
			outputBinary ("PT", PT, BLOCK_SIZE);
			outputBinary ("CT", CT, BLOCK_SIZE);
			
			/* Shift bit across keyLen bytes */
			if ((*pShiftBitMarker = (*pShiftBitMarker >> 1)) == 0) {
				if (pShiftBitMarker > PT) {
					pShiftBitMarker--;
					*pShiftBitMarker = 0x80;
				}
			}
		}
	}
	outputString ("==========\n");
	closeFile ();
	free (EncryptKeyInst);
}

void openFile (char *filename) {
	if ((output = fopen (filename, "w+")) == NULL)
		output = stdout;
}

void closeFile () {
	fclose (output);
}

void outputLineFeed () {
	fputs ("\n", output);
	puts ("\n");
}

void outputInteger (char *format, int i) {
	fprintf (output, format, i);
	printf (format, i);
}

void outputBinary (char *Item, BYTE *value, int Size) {
	char outputBuffer [65];
	binaryToHexString (value, outputBuffer, Size);
	fprintf (output, "%s=%s\n", Item, outputBuffer);
	printf ("%s=%s\n", Item, outputBuffer);
}

void outputString (char *Item) {
	fprintf (output, "%s", Item);
	printf ("%s", Item);
}

void outputHeader (char *filename, char *title, char *title2) {
	fputs ("\n", output);
	fputs("=========================\n", output);
	fputs("\n", output);
	fprintf (output, "FILENAME:  %s\n\n", filename);
	fprintf (output, "%s\n", title);
	fprintf (output, "%s\n\n", title2);
	fputs ("Algorithm Name: FROG", output);
	fputs ("\n", output);
	fputs ("Principal Submitter: TecApro", output);
	fputs ("\n\n", output);
	fputs ("==========\n", output);
	fputs ("\n", output);
}
