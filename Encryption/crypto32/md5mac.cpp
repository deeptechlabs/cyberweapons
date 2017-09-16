// md5mac.cpp - modified by Wei Dai from Eric Young's md5_dgst.c
// Copyright 1995 by Eric Young.  Distributed with permission.

#include "pch.h"
#include "md5mac.h"

NAMESPACE_BEGIN(CryptoPP)

const word32 MD5MAC::T[12] =
	{ 0xac45ef97,0xcd430f29,0x551b7e45,0x3411801c,
	  0x96ce77b1,0x7c8e722e,0x0aab5a5f,0x18be4336,
	  0x21b4219d,0x4db987bc,0xbd279da2,0xc3d75bc7 };

MD5MAC::MD5MAC(const byte *userKey)
	: IteratedHash<word32>(DATASIZE, DIGESTSIZE),
	  key(12)
{
	const word32 zeros[4] = {0,0,0,0};

	for (unsigned i=0, j; i<3; i++)
	{
		key[4*i+0] = 0x67452301L;
		key[4*i+1] = 0xefcdab89L;
		key[4*i+2] = 0x98badcfeL;
		key[4*i+3] = 0x10325476L;

		memcpy(data, userKey, KEYLENGTH);
		CorrectEndianess(data, data, KEYLENGTH);
		for (j=0; j<3; j++)
			memcpy(data+4+4*j, T+((i+j)%3)*4, 16);
		Transform(key+4*i, data, zeros);

		for (j=0; j<3; j++)
			memcpy(data+4*j, T+((i+j)%3)*4, 16);
		memcpy(data+12, userKey, KEYLENGTH);
		CorrectEndianess(data+12, data+12, KEYLENGTH);
		Transform(key+4*i, data, zeros);
	}

	Init();
}

void MD5MAC::Init()
{
	countLo = countHi = 0;

	digest[0] = key[0];
	digest[1] = key[1];
	digest[2] = key[2];
	digest[3] = key[3];
}

void MD5MAC::CorrectEndianess(word32 *out, const word32 *in, unsigned int byteCount)
{
#ifndef IS_LITTLE_ENDIAN
	byteReverse(out, in, byteCount);
#else
	if (in!=out)
		memcpy(out, in, byteCount);
#endif
}

void MD5MAC::HashBlock(const word32 *input)
{
#ifdef IS_LITTLE_ENDIAN
	Transform(digest, input, key+4);
#else
	byteReverse(data.ptr, input, (unsigned int)DATASIZE);
	Transform(digest, data, key+4);
#endif
}

void MD5MAC::Final (byte *hash)
{
	PadLastBlock(56);
	CorrectEndianess(data, data, 56);

	data[14] = countLo;
	data[15] = countHi;

	Transform(digest, data, key+4);

	unsigned i;
	for (i=0; i<4; i++)
		data[i] = key[8+i];
	for (i=0; i<12; i++)
		data[i+4] = T[i] ^ key[8+i%4];
	Transform(digest, data, key+4);

	CorrectEndianess(digest, digest, DIGESTSIZE);
	memcpy(hash, digest, DIGESTSIZE);

	Init();		// reinit for next use
}

void MD5MAC::Transform (word32 *digest, const word32 *X, const word32 *key)
{
// #define	F(x,y,z)	((x & y)  |  (~x & z))
#define F(x,y,z)    (z ^ (x & (y^z)))
// #define	G(x,y,z)	((x & z)  |  (y & ~z))
#define G(x,y,z)    (y ^ (z & (x^y)))
#define	H(x,y,z)	(x ^ y ^ z)
#define	I(x,y,z)	(y  ^  (x | ~z))

#define R0(a,b,c,d,k,s,t) { \
	a+=(k+t+ F((b),(c),(d)) + key[0]); \
	a = rotlFixed(word32(a), (unsigned int)(s)); \
	a+=b; };\

#define R1(a,b,c,d,k,s,t) { \
	a+=(k+t+ G((b),(c),(d)) + key[1]); \
	a = rotlFixed(word32(a), (unsigned int)(s)); \
	a+=b; };

#define R2(a,b,c,d,k,s,t) { \
	a+=(k+t+ H((b),(c),(d)) + key[2]); \
	a = rotlFixed(word32(a), (unsigned int)(s)); \
	a+=b; };

#define R3(a,b,c,d,k,s,t) { \
	a+=(k+t+ I((b),(c),(d)) + key[3]); \
	a = rotlFixed(word32(a), (unsigned int)(s)); \
	a+=b; };

	register unsigned long A,B,C,D;

	A=digest[0];
	B=digest[1];
	C=digest[2];
	D=digest[3];

	/* Round 0 */
	R0(A,B,C,D,X[ 0], 7,0xd76aa478);
	R0(D,A,B,C,X[ 1],12,0xe8c7b756);
	R0(C,D,A,B,X[ 2],17,0x242070db);
	R0(B,C,D,A,X[ 3],22,0xc1bdceee);
	R0(A,B,C,D,X[ 4], 7,0xf57c0faf);
	R0(D,A,B,C,X[ 5],12,0x4787c62a);
	R0(C,D,A,B,X[ 6],17,0xa8304613);
	R0(B,C,D,A,X[ 7],22,0xfd469501);
	R0(A,B,C,D,X[ 8], 7,0x698098d8);
	R0(D,A,B,C,X[ 9],12,0x8b44f7af);
	R0(C,D,A,B,X[10],17,0xffff5bb1);
	R0(B,C,D,A,X[11],22,0x895cd7be);
	R0(A,B,C,D,X[12], 7,0x6b901122);
	R0(D,A,B,C,X[13],12,0xfd987193);
	R0(C,D,A,B,X[14],17,0xa679438e);
	R0(B,C,D,A,X[15],22,0x49b40821);
	/* Round 1 */
	R1(A,B,C,D,X[ 1], 5,0xf61e2562);
	R1(D,A,B,C,X[ 6], 9,0xc040b340);
	R1(C,D,A,B,X[11],14,0x265e5a51);
	R1(B,C,D,A,X[ 0],20,0xe9b6c7aa);
	R1(A,B,C,D,X[ 5], 5,0xd62f105d);
	R1(D,A,B,C,X[10], 9,0x02441453);
	R1(C,D,A,B,X[15],14,0xd8a1e681);
	R1(B,C,D,A,X[ 4],20,0xe7d3fbc8);
	R1(A,B,C,D,X[ 9], 5,0x21e1cde6);
	R1(D,A,B,C,X[14], 9,0xc33707d6);
	R1(C,D,A,B,X[ 3],14,0xf4d50d87);
	R1(B,C,D,A,X[ 8],20,0x455a14ed);
	R1(A,B,C,D,X[13], 5,0xa9e3e905);
	R1(D,A,B,C,X[ 2], 9,0xfcefa3f8);
	R1(C,D,A,B,X[ 7],14,0x676f02d9);
	R1(B,C,D,A,X[12],20,0x8d2a4c8a);
	/* Round 2 */
	R2(A,B,C,D,X[ 5], 4,0xfffa3942);
	R2(D,A,B,C,X[ 8],11,0x8771f681);
	R2(C,D,A,B,X[11],16,0x6d9d6122);
	R2(B,C,D,A,X[14],23,0xfde5380c);
	R2(A,B,C,D,X[ 1], 4,0xa4beea44);
	R2(D,A,B,C,X[ 4],11,0x4bdecfa9);
	R2(C,D,A,B,X[ 7],16,0xf6bb4b60);
	R2(B,C,D,A,X[10],23,0xbebfbc70);
	R2(A,B,C,D,X[13], 4,0x289b7ec6);
	R2(D,A,B,C,X[ 0],11,0xeaa127fa);
	R2(C,D,A,B,X[ 3],16,0xd4ef3085);
	R2(B,C,D,A,X[ 6],23,0x04881d05);
	R2(A,B,C,D,X[ 9], 4,0xd9d4d039);
	R2(D,A,B,C,X[12],11,0xe6db99e5);
	R2(C,D,A,B,X[15],16,0x1fa27cf8);
	R2(B,C,D,A,X[ 2],23,0xc4ac5665);
	/* Round 3 */
	R3(A,B,C,D,X[ 0], 6,0xf4292244);
	R3(D,A,B,C,X[ 7],10,0x432aff97);
	R3(C,D,A,B,X[14],15,0xab9423a7);
	R3(B,C,D,A,X[ 5],21,0xfc93a039);
	R3(A,B,C,D,X[12], 6,0x655b59c3);
	R3(D,A,B,C,X[ 3],10,0x8f0ccc92);
	R3(C,D,A,B,X[10],15,0xffeff47d);
	R3(B,C,D,A,X[ 1],21,0x85845dd1);
	R3(A,B,C,D,X[ 8], 6,0x6fa87e4f);
	R3(D,A,B,C,X[15],10,0xfe2ce6e0);
	R3(C,D,A,B,X[ 6],15,0xa3014314);
	R3(B,C,D,A,X[13],21,0x4e0811a1);
	R3(A,B,C,D,X[ 4], 6,0xf7537e82);
	R3(D,A,B,C,X[11],10,0xbd3af235);
	R3(C,D,A,B,X[ 2],15,0x2ad7d2bb);
	R3(B,C,D,A,X[ 9],21,0xeb86d391);

	digest[0]+=A;
	digest[1]+=B;
	digest[2]+=C;
	digest[3]+=D;
}

NAMESPACE_END
