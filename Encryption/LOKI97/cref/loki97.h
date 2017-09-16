/* 
 * loki97.h - header file for the LOKI97 AES candidate block cipher.<p>
 *
 * LOKI97 was written by Lawrie Brown (ADFA), Josef Pieprzyk, and Jennifer
 * Seberry (UOW) in 1997.<p>
 *
 * <b>Copyright</b> 1998 by <a href="mailto:Lawrie.Brown@adfa.oz.au">
 * Lawrie Brown</a> & ITRACE (UNSW).
 *
 * based on aes.h - AES Cipher header file for ANSI C Submissions
 */

/* Includes: Standard include files */
#include <stdio.h>
#include <string.h>

/* Defines: AES */

#define     DIR_ENCRYPT     0    /*  Are we encrypting?  */
#define     DIR_DECRYPT     1    /*  Are we decrypting?  */
#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode? */
#define     TRUE            1
#define     FALSE           0


/* Error Codes */
#define     BAD_KEY_DIR        -1  /*  Key direction is invalid, e.g.,
					unknown value */
#define     BAD_KEY_MAT        -2  /*  Key material not of correct 
					length */
#define     BAD_KEY_INSTANCE   -3  /*  Key passed is not valid  */
#define     BAD_CIPHER_MODE    -4  /*  Params struct passed to 
					cipherInit invalid */
#define     BAD_CIPHER_STATE   -5  /*  Cipher in wrong state (e.g., not 
					initialized) */
#define     BAD_CIPHER_INPUT   -6  /*  Cipher input not BLOCK_SIZE multiple */


/* Algorithm Specific Defines  */
#define     MAX_KEY_SIZE	64  /* # of ASCII char's needed to
					represent a key */
#define     MAX_IV_SIZE		16  /* # bytes needed to represent an IV  */

/* Number of bytes in a data-block. */
#define	    BLOCK_SIZE		16

/* Number of rounds for the algorithm. */
#define     ROUNDS		16

/* Number of subkeys used by the algorithm. */
#define     NUM_SUBKEYS		3*ROUNDS

/* Typedefs: */

typedef    unsigned char    BYTE;			/* unsigned byte */

typedef    struct { unsigned long l,r; } ULONG64;	/* 64bit unsigned int */


/*  The structure for key information */
typedef struct {
      BYTE  direction;	/*  Key used for encrypting or decrypting? */
      int   keyLen;	/*  Length of the key  */
      char  keyMaterial[MAX_KEY_SIZE+1];  /*  Raw key data in ASCII,
                                    e.g., user input or KAT values */
      /*  The following parameters are algorithm dependent */
      ULONG64	SK[NUM_SUBKEYS];	/* LOKI97 subkeys for this key */
      } keyInstance;

/*  The structure for cipher information */
typedef struct {
      BYTE  mode;            /* MODE_ECB, MODE_CBC, or MODE_CFB1 */
      BYTE  IV[MAX_IV_SIZE]; /* A possible Initialization Vector for 
      					ciphering */
      /*  Add any algorithm specific parameters needed here  */
      ULONG64	IVL, IVR;	/* IV packed into 64-bit L & R halves */
      int   blockSize;    	/* Sample: Handles non-128 bit block sizes
      					(if available) */
      } cipherInstance;


/*  Function protoypes  */
int makeKey(keyInstance *key, BYTE direction, int keyLen,
			char *keyMaterial);

int cipherInit(cipherInstance *cipher, BYTE mode, char *IV);

int blockEncrypt(cipherInstance *cipher, keyInstance *key, BYTE *input, 
			int inputLen, BYTE *outBuffer);

int blockDecrypt(cipherInstance *cipher, keyInstance *key, BYTE *input,
			int inputLen, BYTE *outBuffer);

int self_test();
