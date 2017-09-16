/****************************************************************************
*									    *
*			    MDC.H - MDC interface header		    *
*									    *
*	Written by Peter Gutmann, pgut1@cs.aukuni.ac.nz, September 1992	    *
*		    You can use this code in any way you want,		    *
*	although it'd be nice if you kept my name + contact address on it   *
*									    *
****************************************************************************/

#include "md5.h"

/* The block size (in bytes) */

#define BLOCKSIZE   16

/* The default IV value used to seed the cipher in initKey().  Changing this
   for each file precludes the use of precomputed encrypted data for very
   fast checking against known plaintext */

#define DEFAULT_IV	( ( BYTE * ) "\0\0\0\0\0\0\0\0" )

#define IV_SIZE		8

/* Define for simple block encryption */

void MD5Transform( LONG *digest, LONG *data );

#ifdef LITTLE_ENDIAN
  #define mdcTransform(iv)  longReverse( ( LONG * ) iv, BLOCKSIZE ); \
			    MD5Transform( ( LONG * ) iv, ( LONG * ) auxKey ); \
			    longReverse( ( LONG * ) iv, BLOCKSIZE )
#else
  #define mdcTransform(iv)  MD5Transform( ( LONG * ) iv, ( LONG * ) auxKey )
#endif /* LITTLE_ENDIAN */

/* Prototypes for functions in MDC.C */

void initKey( BYTE *key, int keyLength, const BYTE *iv );
void encryptCFB( BYTE *buffer, int length );
void decryptCFB( BYTE *buffer, int length );
BYTE *getIV( void );
BYTE *getIV( void );
