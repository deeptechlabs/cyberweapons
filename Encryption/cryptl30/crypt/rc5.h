#ifndef _RC5_DEFINED

#define _RC5_DEFINED

/* The RC5 blocksize */

#define RC5_BLOCKSIZE		8

/* The default and maximum (sane) number of RC5 rounds */

#define RC5_DEFAULT_ROUNDS	12
#define RC5_MAX_ROUNDS		32

/* The maximum RC5 expanded key size: 256 bytes.  Note that sizeof( LONG )
   may not equal 4, so the total size may in fact be more than 256 bytes,
   however the total information content is only 256 bytes */

#define RC5_EXPANDED_KEYSIZE_LONG	64
#define RC5_EXPANDED_KEYSIZE		( RC5_EXPANDED_KEYSIZE_LONG * sizeof( LONG ) )

/* A structure to hold the RC5 key */

typedef struct {
	LONG S[ RC5_EXPANDED_KEYSIZE_LONG ];	/* S-box */
	int noRounds;							/* Number of rounds */
	} RC5_KEY;

/* Prototypes for functions in RC5.C */

void rc5encrypt( RC5_KEY *key, BYTE *data );
void rc5decrypt( RC5_KEY *key, BYTE *data );
void rc5keyInit( RC5_KEY *key, const BYTE *userKey, const int userKeyLength );

#endif /* _RC5_DEFINED */
