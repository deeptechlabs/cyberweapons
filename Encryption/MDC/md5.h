#ifndef _MD5_DEFINED

#define _MD5_DEFINED

/* Some useful defines which always end up in my code */

typedef unsigned char	BYTE;
typedef unsigned short	WORD;
typedef unsigned long	LONG;

typedef char		BOOLEAN;

#define TRUE	1
#define FALSE	0

#define ERROR	-1
#define OK	0

/****************************************************************************
*									    *
*	    RSA Data Security, Inc. MD5 Message-Digest Algorithm	    *
*  Created 2/17/90 RLR, revised 12/27/90 SRD,AJ,BSK,JT Reference C version  *
*   Revised (for MD5) RLR 4/27/91: G modified to have y&~z instead of y&z,  *
* FF, GG, HH modified to add in last register done, access pattern: round 2 *
*   works mod 5, round 3 works mod 3, distinct additive constant for each   *
*		    step round 4 added, working mod 7			    *
*									    *
****************************************************************************/

/* The size of an MD5 data block and the number of rounds in the MD5 transformation */

#define MD5_BLOCKSIZE	64
#define MD5_ROUNDS	64

/* Data structure for MD5 computation */

typedef struct {
	       LONG i[ 2 ];	    /* Number of bits handled mod 2^64 */
	       LONG buf[ 4 ];	    /* Scratch buffer */
	       BYTE in[ MD5_BLOCKSIZE ];    /* Input buffer */
	       BYTE digest[ 16 ];   /* Actual digest after MD5Final() call */
	       } MD5_CTX;

/* Message digest functions */

void MD5SetConst( BYTE *buffer );
void MD5Init( MD5_CTX *mdContext );
void MD5Update( MD5_CTX *mdContext, BYTE *buffer, unsigned int noBytes );
void MD5Final( MD5_CTX *mdContext );

#endif /* _MD5_DEFINED */\End\Of\Shar\
#endif /* _MD5_DEFINED */\End\Of\Shar\
