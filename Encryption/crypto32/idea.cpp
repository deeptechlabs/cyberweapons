// idea.cpp - modified by Wei Dai from:
// Copyright 1992 by Colin Plumb.  Distributed with permission.

/*      idea.c - C source code for IDEA block cipher.
 *      IDEA (International Data Encryption Algorithm), formerly known as
 *      IPES (Improved Proposed Encryption Standard).
 *      Algorithm developed by Xuejia Lai and James L. Massey, of ETH Zurich.
 *      This implementation modified and derived from original C code
 *      developed by Xuejia Lai.
 *      Zero-based indexing added, names changed from IPES to IDEA.
 *
 *  Optimized for speed 21 Oct 92 by Colin Plumb.
 *
 *      The IDEA(tm) block cipher is covered by a patent held by ETH and a
 *      Swiss company called Ascom-Tech AG.  The Swiss patent number is
 *      PCT/CH91/00117.  International patents are pending. IDEA(tm) is a
 *      trademark of Ascom-Tech AG.  There is no license fee required for
 *      noncommercial use.  Commercial users may obtain licensing details
 *      from Dieter Profos, Ascom Tech AG, Solothurn Lab, Postfach 151, 4502
 *      Solothurn, Switzerland, Tel +41 65 242885, Fax +41 65 235761.
 *
 *      The IDEA block cipher uses a 64-bit block size, and a 128-bit key
 *      size.  It breaks the 64-bit cipher block into four 16-bit words
 *      because all of the primitive inner operations are done with 16-bit
 *      arithmetic.  It likewise breaks the 128-bit cipher key into eight
 *      16-bit words.
 *
 *      For further information on the IDEA cipher, see these papers:
 *      1) Xuejia Lai, "Detailed Description and a Software Implementation of
 *         the IPES Cipher", Institute for Signal and Information
 *         Processing, ETH-Zentrum, Zurich, Switzerland, 1991
 *      2) Xuejia Lai, James L. Massey, Sean Murphy, "Markov Ciphers and
 *         Differential Cryptanalysis", Advances in Cryptology- EUROCRYPT'91
 *
 *      This code assumes that each pair of 8-bit bytes comprising a 16-bit
 *      word in the key and in the cipher block are externally represented
 *      with the Most Significant Byte (MSB) first, regardless of the
 *      internal native byte order of the target CPU.
 */

#include "pch.h"
#include "idea.h"

NAMESPACE_BEGIN(CryptoPP)

static const int IDEA_KEYLEN=(6*IDEA::ROUNDS+4);  // key schedule length in # of word16s

#define low16(x) ((x)&0xffff)	// compiler should be able to optimize this away if word is 16 bits
#define high16(x) ((x)>>16)

// should use an inline function but macros are still faster in MSVC 4.0
#define DirectMUL(a,b)					\
{										\
	assert(b <= 0xffff);				\
										\
	word32 p=(word32)low16(a)*b;		\
										\
	if (p)								\
	{									\
		p = low16(p) - high16(p);		\
		a = (word)p - (word)high16(p);	\
	}									\
	else								\
		a = 1-a-b;						\
}

#ifdef IDEA_LARGECACHE
bool IDEA::tablesBuilt = false;
word16 IDEA::log[0x10000];
word16 IDEA::antilog[0x10000];

void IDEA::BuildLogTables()
{
	if (tablesBuilt)
		return;
	else
	{
		tablesBuilt = true;

		word x=1;
		word32 i;

		for (i=0; i<0x10000; i++)
		{
			antilog[i] = (word16)x;
			DirectMUL(x, 3);
		}

		for (i=0; i<0x10000; i++)
			log[antilog[i]] = (word16)i;
	}
}

void IDEA::LookupKeyLogs()
{
   word* Z=key;
   int r=ROUNDS;
   do
   {
	   Z[0] = log[Z[0]];
	   Z[3] = log[Z[3]];
	   Z[4] = log[Z[4]];
	   Z[5] = log[Z[5]];
	   Z+=6;
   } while (--r);
   Z[0] = log[Z[0]];
   Z[3] = log[Z[3]];
}

inline void IDEA::LookupMUL(word &a, word b)
{
	a = antilog[low16(log[low16(a)]+b)];
}
#endif // IDEA_LARGECACHE

IDEA::IDEA (const byte * userKey, CipherDir direction)
	: key(IDEA_KEYLEN)
{
#ifdef IDEA_LARGECACHE
	BuildLogTables();
#endif

	EnKey(userKey);

	if (direction==DECRYPTION)
		DeKey();

#ifdef IDEA_LARGECACHE
	LookupKeyLogs();
#endif
}

void IDEA::EnKey (const byte *userKey)
{
   int i, j;
   word *Z=key;

   for (j=0;j<8;j++)
	   Z[j] = (userKey[2*j]<<8) + userKey[2*j+1];
   for (i=0;j<IDEA_KEYLEN;j++)
   {
	  i++;
	  Z[i+7]=low16((Z[i&7] << 9) | (Z[i+1 & 7] >> 7));
	  Z+=i&8;
	  i&=7;
   }
}

static word inv(word x)
{
	word y=x;
	for (unsigned i=0; i<15; i++)
	{
		DirectMUL(y,low16(y));
		DirectMUL(y,x);
	}
	return low16(y);
}

void IDEA::DeKey()
{
   word *Z=key;
   int j;
   word t1,t2,t3;
   SecBlock<word> tempKey(IDEA_KEYLEN);
   word *p=tempKey+IDEA_KEYLEN;
   t1=inv(*Z++);
   t2=low16(0-*Z++);
   t3=low16(0-*Z++);
   *--p=inv(*Z++);
   *--p=t3;
   *--p=t2;
   *--p=t1;
   for (j=1;j<ROUNDS;j++)
   {
	  t1=*Z++;
	  *--p=*Z++;
	  *--p=t1;
	  t1=inv(*Z++);
	  t2=low16(0-*Z++);
	  t3=low16(0-*Z++);
	  *--p=inv(*Z++);
	  *--p=t2;
	  *--p=t3;
	  *--p=t1;
   }
   t1=*Z++;
   *--p=*Z++;
   *--p=t1;
   t1=inv(*Z++);
   t2=low16(0-*Z++);
   t3=low16(0-*Z++);
   *--p=inv(*Z++);
   *--p=t3;
   *--p=t2;
   *--p=t1;
   /*copy and destroy temp copy*/
   memcpy(key, tempKey, IDEA_KEYLEN*sizeof(word));
}

#ifdef IDEA_LARGECACHE
#define MUL(a,b) LookupMUL(a,b)
#else
#define MUL(a,b) DirectMUL(a,b)
#endif

void IDEA::ProcessBlock(const byte *in, byte *out) const
{
   word x1,x2,x3,x4,t1,t2;
#ifdef IS_LITTLE_ENDIAN
   x1=byteReverse(((word16 *)in)[0]);
   x2=byteReverse(((word16 *)in)[1]);
   x3=byteReverse(((word16 *)in)[2]);
   x4=byteReverse(((word16 *)in)[3]);
#else
   x1=((word16 *)in)[0];
   x2=((word16 *)in)[1];
   x3=((word16 *)in)[2];
   x4=((word16 *)in)[3];
#endif

   const word* Z=key;
   int r=ROUNDS;
   do
   {
	  MUL(x1,Z[0]);
	  x2+=Z[1];
	  x3+=Z[2];
	  MUL(x4,Z[3]);
	  t2=x1^x3;
	  MUL(t2,Z[4]);
	  t1=t2+(x2^x4);
	  MUL(t1,Z[5]);
	  Z+=6;
	  t2+=t1;
	  x1^=t1;
	  x4^=t2;
	  t2^=x2;
	  x2=x3^t1;
	  x3=t2;
   } while (--r);
   MUL(x1,Z[0]);
   x3+=Z[1];
   x2+=Z[2];
   MUL(x4,Z[3]);

   PutBlockBigEndian<word16>(out, x1, x3, x2, x4);
}

NAMESPACE_END
