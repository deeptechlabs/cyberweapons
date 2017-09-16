// mars.cpp - modified by Sean Woods from Brian Gladman's mars6.c for Crypto++

/* This is an independent implementation of the MARS encryption         */
/* algorithm designed by a team at IBM as a candidate for the US        */
/* NIST Advanced Encryption Standard (AES) effort. The algorithm        */
/* is subject to Patent action by IBM, who intend to offer royalty      */
/* free use if a Patent is granted.                                     */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but       */
/* I hereby give permission for its free direct or derivative use       */
/* subject to acknowledgment of its origin and compliance with any      */
/* constraints that IBM place on the use of the MARS algorithm.         */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 4th October 1998      */

#include "pch.h"
#include "mars.h"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN
static word32 gen_mask(word32 x)
{
	word32	m;

	m = (~x ^ (x >> 1)) & 0x7fffffff;
	m &= (m >> 1) & (m >> 2); m &= (m >> 3) & (m >> 6); 
	
	if(!m)
		return 0;
	
	m <<= 1; m |= (m << 1); m |= (m << 2); m |= (m << 4);
	m |= (m << 1) & ~x & 0x80000000;

	return m & 0xfffffffc;
};
NAMESPACE_END

MARS::MARS(const byte *userKey, unsigned int keylen)
	: EK(40)
{
	assert(keylen == KeyLength(keylen));

	const unsigned int c=(keylen - 1)/4 + 1;
	SecBlock<word32> k(c);

	GetUserKeyLittleEndian(k.ptr, c, userKey, keylen);

	SecBlock<word32> VK(47);
	word32 j, m, w, *t = VK + 7;
	int i;

	for (i = 0; i < 7; i++)
		t[i-7] = Sbox[i];

	for(i = 0; i < 39; ++i)
		t[i] = rotlFixed(t[i - 7] ^ t[i - 2], 3) ^ k[i % c] ^ i;

	t[39] = keylen / 4;

	for(j = 0; j < 7; ++j)
	{
		for(i = 1; i < 40; ++i)
			t[i] = rotlFixed(t[i] + Sbox[t[i - 1] & 511], 9);

		t[0] = rotlFixed(t[0] + Sbox[t[39] & 511], 9);
	}

	for(i = 0; i < 40; ++i)
		EK[(7*i) % 40] = t[i];

	for(i = 5; i < 37; i += 2)
	{
		w = EK[i] | 3; 

		if(m = gen_mask(w))
			w ^= (rotlMod(Sbox[265 + (EK[i] & 3)], EK[i + 3]) & m);

		EK[i] = w;
	}
}

#define f_mix(a,b,c,d)					\
		r = rotrFixed(a, 8); 				\
		b ^= Sbox[a & 255];				\
		b += Sbox[(r & 255) + 256];		\
		r = rotrFixed(a, 16);				\
		a  = rotrFixed(a, 24);				\
		c += Sbox[r & 255];				\
		d ^= Sbox[(a & 255) + 256]

#define b_mix(a,b,c,d)					\
		r = rotlFixed(a, 8); 				\
		b ^= Sbox[(a & 255) + 256];		\
		c -= Sbox[r & 255];				\
		r = rotlFixed(a, 16);				\
		a  = rotlFixed(a, 24);				\
		d -= Sbox[(r & 255) + 256];		\
		d ^= Sbox[a & 255]

#define f_ktr(a,b,c,d,i)	\
	m = a + EK[i];			\
	a = rotlFixed(a, 13);		\
	r = a * EK[i + 1];		\
	l = Sbox[m & 511]; 		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	c += rotlMod(m, r);		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	d ^= r; 				\
	b += rotlMod(l, r)

#define r_ktr(a,b,c,d,i)	\
	r = a * EK[i + 1];		\
	a = rotrFixed(a, 13);		\
	m = a + EK[i];			\
	l = Sbox[m & 511]; 		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	c -= rotlMod(m, r);		\
	r = rotlFixed(r, 5); 		\
	l ^= r; 				\
	d ^= r; 				\
	b -= rotlMod(l, r)

void MARSEncryption::ProcessBlock(const byte *inBlock, byte *outBlock) const
{
	word32 a, b, c, d, l, m, r;
	
	GetBlockLittleEndian(inBlock,a,b,c,d);

	a += EK[0];
	b += EK[1];
	c += EK[2];
	d += EK[3];

	int i;
	for (i = 0; i < 2; i++) {
		f_mix(a,b,c,d);
		a += d;
		f_mix(b,c,d,a);
		b += c;
		f_mix(c,d,a,b);
		f_mix(d,a,b,c);
	}

	f_ktr(a,b,c,d, 4); f_ktr(b,c,d,a, 6); f_ktr(c,d,a,b, 8); f_ktr(d,a,b,c,10); 
	f_ktr(a,b,c,d,12); f_ktr(b,c,d,a,14); f_ktr(c,d,a,b,16); f_ktr(d,a,b,c,18); 
	f_ktr(a,d,c,b,20); f_ktr(b,a,d,c,22); f_ktr(c,b,a,d,24); f_ktr(d,c,b,a,26); 
	f_ktr(a,d,c,b,28); f_ktr(b,a,d,c,30); f_ktr(c,b,a,d,32); f_ktr(d,c,b,a,34); 

	for (i = 0; i < 2; i++) {
		b_mix(a,b,c,d);
		b_mix(b,c,d,a);
		c -= b;
		b_mix(c,d,a,b);
		d -= a;
		b_mix(d,a,b,c);
	}

	a -= EK[36];
	b -= EK[37];
	c -= EK[38];
	d -= EK[39];

	PutBlockLittleEndian(outBlock,a,b,c,d);
}

void MARSDecryption::ProcessBlock(const byte *inBlock, byte *outBlock) const
{
	word32 a, b, c, d, l, m, r;

	GetBlockLittleEndian(inBlock,d,c,b,a);
	
	d += EK[36];
	c += EK[37];
	b += EK[38];
	a += EK[39];

	int i;
	for (i = 0; i < 2; i++) {
		f_mix(a,b,c,d);
		a += d;
		f_mix(b,c,d,a);
		b += c;
		f_mix(c,d,a,b);
		f_mix(d,a,b,c);
	}

	r_ktr(a,b,c,d,34); r_ktr(b,c,d,a,32); r_ktr(c,d,a,b,30); r_ktr(d,a,b,c,28);
	r_ktr(a,b,c,d,26); r_ktr(b,c,d,a,24); r_ktr(c,d,a,b,22); r_ktr(d,a,b,c,20);
	r_ktr(a,d,c,b,18); r_ktr(b,a,d,c,16); r_ktr(c,b,a,d,14); r_ktr(d,c,b,a,12);
	r_ktr(a,d,c,b,10); r_ktr(b,a,d,c, 8); r_ktr(c,b,a,d, 6); r_ktr(d,c,b,a, 4);

	for (i = 0; i < 2; i++) {
		b_mix(a,b,c,d);
		b_mix(b,c,d,a);
		c -= b;
		b_mix(c,d,a,b);
		d -= a;
		b_mix(d,a,b,c);
	}

	d -= EK[0];
	c -= EK[1];
	b -= EK[2];
	a -= EK[3];

	PutBlockLittleEndian(outBlock,d,c,b,a);
}

NAMESPACE_END
