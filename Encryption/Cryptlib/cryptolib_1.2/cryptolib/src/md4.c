/*
 ***********************************************************************
 ** md4.c -- the source code for MD4 routines                         **
 ** RSA Data Security, Inc. MD4 Message-Digest Algorithm              **
 ** Created: 2/17/90 RLR                                              **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                   **
 ** Revised: 5/92 Michael Reiter, Optimized                           **
 ***********************************************************************
 */            

/*
 ***********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.  **
 **                                                                   **
 ** License to copy and use this software is granted provided that    **
 ** it is identified as the "RSA Data Security, Inc. MD4 Message-     **
 ** Digest Algorithm" in all material mentioning or referencing this  **
 ** software or this function.                                        **
 **                                                                   **
 ** License is also granted to make and use derivative works          **
 ** provided that such works are identified as "derived from the RSA  **
 ** Data Security, Inc. MD4 Message-Digest Algorithm" in all          **
 ** material mentioning or referencing the derived work.              **
 **                                                                   **
 ** RSA Data Security, Inc. makes no representations concerning       **
 ** either the merchantability of this software or the suitability    **
 ** of this software for any particular purpose.  It is provided "as  **
 ** is" without express or implied warranty of any kind.              **
 **                                                                   **
 ** These notices must be retained in any copies of any part of this  **
 ** documentation and/or software.                                    **
 ***********************************************************************
 */

#include "libcrypt.h"

typedef unsigned long UINT4;
/*
 ***********************************************************************
 **  Message-digest routines:                                         **
 **  To form the message digest for a message M                       **
 **    (1) Initialize a context buffer mdContext using MD4Init        **
 **    (2) Call MD4Update on mdContext and M                          **
 **    (3) Call MD4Final on mdContext                                 **
 **  The message digest is now in mdContext->digest[0...15]           **
 ***********************************************************************
 */

/* forward declaration */
static void MD4Transform P((UINT4 *, UINT4 *));

static unsigned char MD4PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD4 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG and HH are MD4 transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s) \
{(a) += F ((b), (c), (d)) + (x); \
	 (a) = ROTATE_LEFT ((a), (s));}
#define GG(a, b, c, d, x, s) \
{(a) += G ((b), (c), (d)) + (x) + (UINT4)0x5A827999; \
	 (a) = ROTATE_LEFT ((a), (s));}
#define HH(a, b, c, d, x, s) \
{(a) += H ((b), (c), (d)) + (x) + (UINT4)0x6ED9EBA1; \
	 (a) = ROTATE_LEFT ((a), (s));}

/* The routine MD4Init initializes the message-digest context
   mdContext. All fields are set to zero.
   */
#ifdef K_AND_R
_TYPE( void ) MD4Init (mdContext)
  MD4_CTX *mdContext;
#else
_TYPE( void ) MD4Init (MD4_CTX *mdContext)
#endif
{
	mdContext->i[0] = mdContext->i[1] = (UINT4)0;
	
	/* Load magic initialization constants.
	 */
	mdContext->buf[0] = (UINT4)0x67452301;
	mdContext->buf[1] = (UINT4)0xefcdab89;
	mdContext->buf[2] = (UINT4)0x98badcfe;
	mdContext->buf[3] = (UINT4)0x10325476;
}

/* The routine MD4Update updates the message-digest context to
   account for the presence of each of the characters inBuf[0..inLen-1]
   in the message whose digest is being computed.
   */
#ifdef K_AND_R
_TYPE( void ) MD4Update (mdContext, inBuf, inLen)
  MD4_CTX *mdContext;
  unsigned char *inBuf;
  unsigned int inLen;
#else
_TYPE( void ) MD4Update (MD4_CTX *mdContext,
			 unsigned char *inBuf,
			 unsigned int inLen)
#endif
{
	register UINT4 *in = mdContext->in;
	register int mod4 = 0,
	div4 = 0;
	int i;
	register int mdi = 0;
	
	if (!(inLen > 0))
		return;
	
	/* compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);
	
	/* update number of bits */
	if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
		mdContext->i[1]++;
	mdContext->i[0] += ((UINT4)inLen << 3);
	mdContext->i[1] += ((UINT4)inLen >> 29);
	
	mod4 = mdi & 3;
	div4 = mdi >> 2;
	
	/* Completely fill in any partially filled integer in the "in" buffer
	 */
	if ((i = mod4 ? 4 - mod4 : 0) != 0) {
		while (i-- && inLen) {
			--inLen;
			in[div4] |= ((UINT4) *inBuf++) << (mod4++ << 3);
		}
		
		if (mod4 == 4)
			if (++div4 == 16) {
				MD4Transform (mdContext->buf, in);
				div4 = 0;
			}
	}
	
	/* Fill in integers from the input
	 */
	for (i = 0; (unsigned)i < ((UINT4) inLen >> 2); ++i) {
		in[div4] = (UINT4) *inBuf++;
		in[div4] |= ((UINT4) *inBuf++) << 8;
		in[div4] |= ((UINT4) *inBuf++) << 16;
		in[div4] |= ((UINT4) *inBuf++) << 24;
		
		if (++div4 == 16) {
			MD4Transform (mdContext->buf, in);
			div4 = 0;
		}
	}
	
	/* Partially fill in an integer with any leftover input bytes
	 */
	if ((mod4 = (inLen & 3)) != 0) {
		in[div4] = 0;
		for (i = 0; i < mod4; ++i)
			in[div4] |= ((UINT4) *inBuf++) << (i << 3);
	}
}

/* The routine MD4Final terminates the message-digest computation and
   ends with the desired message digest in mdContext->digest[0...15].
   */
#ifdef K_AND_R
_TYPE( void ) MD4Final (mdContext)
  MD4_CTX *mdContext;
#else
_TYPE( void ) MD4Final (MD4_CTX *mdContext)
#endif
{
	UINT4 t1, t2;
	int mdi;
	unsigned int i, ii;
	unsigned int padLen;
	
	/* save number of bits */
	t1 = mdContext->i[0];
	t2 = mdContext->i[1];
	
	/* compute number of bytes mod 64 */
	mdi = (int)((mdContext->i[0] >> 3) & 0x3F);
	
	/* pad out to 56 mod 64 */
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
	MD4Update (mdContext, MD4PADDING, padLen);
	
	/* append length in bits and transform */
	mdContext->in[14] = t1;
	mdContext->in[15] = t2;
	
	MD4Transform (mdContext->buf, mdContext->in);
	
	/* store buffer in digest */
	for (i = 0, ii = 0; i < 4; i++, ii += 4) {
		mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
		mdContext->digest[ii+1] =
			(unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
		mdContext->digest[ii+2] =
			(unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
		mdContext->digest[ii+3] =
			(unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
	}
}

/* Basic MD4 step. Transforms buf based on in.
 */
static void MD4Transform (buf, in)
  UINT4 *buf;
  UINT4 *in;
{
	register UINT4 a = buf[0],
	b = buf[1],
	c = buf[2],
	d = buf[3];
	
	/* Round 1 */
	FF (a, b, c, d, in[ 0],  3);
	FF (d, a, b, c, in[ 1],  7);
	FF (c, d, a, b, in[ 2], 11);
	FF (b, c, d, a, in[ 3], 19);
	FF (a, b, c, d, in[ 4],  3);
	FF (d, a, b, c, in[ 5],  7);
	FF (c, d, a, b, in[ 6], 11);
	FF (b, c, d, a, in[ 7], 19);
	FF (a, b, c, d, in[ 8],  3);
	FF (d, a, b, c, in[ 9],  7);
	FF (c, d, a, b, in[10], 11);
	FF (b, c, d, a, in[11], 19);
	FF (a, b, c, d, in[12],  3);
	FF (d, a, b, c, in[13],  7);
	FF (c, d, a, b, in[14], 11);
	FF (b, c, d, a, in[15], 19);
	
	/* Round 2 */
	GG (a, b, c, d, in[ 0],  3);
	GG (d, a, b, c, in[ 4],  5);
	GG (c, d, a, b, in[ 8],  9);
	GG (b, c, d, a, in[12], 13);
	GG (a, b, c, d, in[ 1],  3);
	GG (d, a, b, c, in[ 5],  5);
	GG (c, d, a, b, in[ 9],  9);
	GG (b, c, d, a, in[13], 13);
	GG (a, b, c, d, in[ 2],  3);
	GG (d, a, b, c, in[ 6],  5);
	GG (c, d, a, b, in[10],  9);
	GG (b, c, d, a, in[14], 13);
	GG (a, b, c, d, in[ 3],  3);
	GG (d, a, b, c, in[ 7],  5);
	GG (c, d, a, b, in[11],  9);
	GG (b, c, d, a, in[15], 13);
	
	/* Round 3 */
	HH (a, b, c, d, in[ 0],  3);
	HH (d, a, b, c, in[ 8],  9);
	HH (c, d, a, b, in[ 4], 11);
	HH (b, c, d, a, in[12], 15);
	HH (a, b, c, d, in[ 2],  3);
	HH (d, a, b, c, in[10],  9);
	HH (c, d, a, b, in[ 6], 11);
	HH (b, c, d, a, in[14], 15);
	HH (a, b, c, d, in[ 1],  3);
	HH (d, a, b, c, in[ 9],  9);
	HH (c, d, a, b, in[ 5], 11);
	HH (b, c, d, a, in[13], 15);
	HH (a, b, c, d, in[ 3],  3);
	HH (d, a, b, c, in[11],  9);
	HH (c, d, a, b, in[ 7], 11);
	HH (b, c, d, a, in[15], 15);
	
	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*
 ***********************************************************************
 ** End of md4.c                                                      **
 ******************************** (cut) ********************************
 */

