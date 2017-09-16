/*

FILENAME:  frog.h

AES Submission: FROG

Principal Submitter: TecApro

*/


#ifndef _frog_h_
#define _frog_h_

#include "aes.h"

void binaryToHexString (BYTE *binaryArray, char *hexArray, int Size);
void decryptFrog (BYTE *cipherText, tInternalKey key);
void encryptFrog (BYTE *plainText, tInternalKey key);
void hashKey (BYTE *binaryKey, int keyLen, tInternalKey *randomKey);
void hexStringToBinary (char *hexString, BYTE *binaryData, int binaryLen);
BYTE hexToBinary (BYTE value);
void invertPermutation (BYTE *permutation, BYTE lastElem);
void makeInternalKey (BYTE direction, tInternalKey key);
void makePermutation (BYTE *permutation, BYTE lastElem);
void shiftBitLeft (BYTE *buffer, int size);

#endif
