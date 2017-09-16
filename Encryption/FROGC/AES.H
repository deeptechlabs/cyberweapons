/*  aes.h  */

/*  AES Cipher header file for ANSI C Submissions
      Lawrence E. Bassham III
      Computer Security Division
      National Institute of Standards and Technology

      April 15, 1998

    This sample is to assist implementers developing to the Cryptographic 
API Profile for AES Candidate Algorithm Submissions.  Please consult this 
document as a cross-reference.

    ANY CHANGES, WHERE APPROPRIATE, TO INFORMATION PROVIDED IN THIS FILE
MUST BE DOCUMENTED.  CHANGES ARE ONLY APPROPRIATE WHERE SPECIFIED WITH
THE STRING "CHANGE POSSIBLE".  FUNCTION CALLS AND THEIR PARAMETERS CANNOT 
BE CHANGED.  STRUCTURES CAN BE ALTERED TO ALLOW IMPLEMENTERS TO INCLUDE 
IMPLEMENTATION SPECIFIC INFORMATION.
*/

/*  Includes:
	Standard include files
*/

#include <stdio.h>

/*  Defines:
	Add any additional defines you need
*/

#define     DIR_ENCRYPT     0    /*  Are we encrpyting?  */
#define     DIR_DECRYPT     1    /*  Are we decrpyting?  */
#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode? */
#define     TRUE            1
#define     FALSE           0

/*  Error Codes - CHANGE POSSIBLE: inclusion of additional error codes  */
#define     BAD_KEY_DIR        -1  /*  Key direction is invalid, e.g.,
					unknown value */
#define     BAD_KEY_MAT        -2  /*  Key material not of correct 
					length */
#define     BAD_KEY_INSTANCE   -3  /*  Key passed is not valid  */
#define     BAD_CIPHER_MODE    -4  /*  Params struct passed to 
					cipherInit invalid */
#define     BAD_CIPHER_STATE   -5  /*  Cipher in wrong state (e.g., not 
					initialized) */
#define     BAD_BLOCK_LENGTH	-6 /* Block length must be 16 bytes */
#define	    BAD_IV_LENGTH	-7 /* Hex IV length must be 32 bytes */

/*  CHANGE POSSIBLE:  inclusion of algorithm specific defines  */
/*  See Reference Text: section B.6.C */

#define     MAX_KEY_SIZE       125  /* Maximum size (in bytes) of binary key */
#define     MIN_KEY_SIZE         5  /* Minimum size (in bytes) of binary key */
#define     BLOCK_SIZE	        16  /* Plain Text size (in bytes) */
#define	    MAX_IV_SIZE		16  /* Maximum IV size (in bytes) */

/*  Typedefs:

	Typedef'ed data storage elements.  Add any algorithm specific 
parameters at the bottom of the structs as appropriate.
*/

typedef    unsigned char      BYTE;
typedef    unsigned short int WORD;

#define numIter 8

typedef BYTE tBuffer[BLOCK_SIZE];
typedef BYTE tBinaryKey[MAX_KEY_SIZE];

typedef struct _tIterKey {
  BYTE xorBu[BLOCK_SIZE];
  BYTE SubstPermu[256];
  BYTE BombPermu[BLOCK_SIZE];
} tIterKey;

typedef tIterKey tInternalKey[numIter];


/*  The structure for key information */
typedef struct {
      BYTE  direction;	/*  Key used for encrypting or decrypting? */
      int   keyLen;	/*  Length of the key  */
      char  keyMaterial[MAX_KEY_SIZE+1];  /*  Raw key data in ASCII,
                                    e.g., user input or KAT values */
      /*  The following parameters are algorithm dependent, replace or
      		add as necessary  */
	  tInternalKey internalKey;
      } keyInstance;

/*  The structure for cipher information */
typedef struct {
      BYTE  mode;            /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
	  BYTE  IV[MAX_IV_SIZE]; /* A possible Initialization Vector for
      					ciphering */
      /*  Add any algorithm specific parameters needed here  */
      } cipherInstance;


/*  Function protoypes  */


int makeKey(keyInstance *key, BYTE direction, int keyLen,
			char *keyMaterial);


int cipherInit(cipherInstance *cipher, BYTE mode, char *IV);

int blockEncrypt(cipherInstance *cipher, keyInstance *key, BYTE *input, 
			int inputLen, BYTE *outBuffer);

int blockDecrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
			int inputLen, BYTE *outBuffer);
