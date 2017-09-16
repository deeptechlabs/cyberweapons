// seal.cpp - written and placed in the public domain by Wei Dai
// updated to SEAL 3.0 by Leonard Janke

#include "pch.h"
#include "seal.h"
#include "sha.h"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN
	struct Gamma
	{
		Gamma(const byte *key);
		word32 Apply(word32 i);

		SecBlock<word32> H, Z, D;
		word32 lastIndex;
	};

	Gamma::Gamma(const byte *key)
		: lastIndex(0xffffffff), H(5), Z(5), D(16)
	{
		GetUserKeyBigEndian(H.ptr, 5, key, 20);
		memset(D, 0, 64);
	}

	word32 Gamma::Apply(word32 i)
	{
		word32 shaIndex = i/5;
		if (shaIndex != lastIndex)
		{
			memcpy(Z, H, 20);
			D[0] = shaIndex;
			SHA::Transform(Z, D);
			lastIndex = shaIndex;
		}
		return Z[i%5];
	}
NAMESPACE_END

SEAL::SEAL(const byte *key, word32 counter, unsigned int L)
	: L(L), R(4*L/8192), S(256), T(512), 
	startCount(counter), counter(counter), position(0), buffer(L/8)
{
	assert(L%8192 == 0);

	Gamma gamma(key);
	unsigned int i;

	for (i=0; i<512; i++)
		T[i] = gamma.Apply(i);

	for (i=0; i<256; i++)
		S[i] = gamma.Apply(0x1000+i);

	for (i=0; i<4*(L/8192); i++)
		R[i] = gamma.Apply(0x2000+i);

	Generate(counter, buffer);
}

byte SEAL::GetByte()
{
	if (position == L/8)
		IncrementCounter();
	return buffer[position++];
}

void SEAL::ProcessString(byte *outString, const byte *inString, unsigned int length)
{
	while (length >= L/8-position)
	{
		xorbuf(outString, inString, buffer+position, L/8-position);
		length -= L/8-position;
		inString += L/8-position;
		outString += L/8-position;
		IncrementCounter();
	}

	xorbuf(outString, inString, buffer+position, length);
	position += length;
}

void SEAL::Seek(unsigned long seekPosition)
{
	counter = startCount + seekPosition/(L/8);
	position = seekPosition%(L/8);
	Generate(counter, buffer);
}

void SEAL::IncrementCounter()
{
	counter++;
	position = 0;
	Generate(counter, buffer);
}

void SEAL::Generate(word32 in, byte *out) const
{
	word32 a, b, c, d, n1, n2, n3, n4;
	unsigned int p, q;
	word32 *wout = (word32 *)out;

	for (unsigned int l=0; l<L/8192; l++)
	{
		a = in ^ R[4*l];
		b = rotrFixed(in, 8U) ^ R[4*l+1];
		c = rotrFixed(in, 16U) ^ R[4*l+2];
		d = rotrFixed(in, 24U) ^ R[4*l+3];

#define Ttab(x) *(word32 *)((byte *)T.ptr+x)
	
		for (unsigned int j=0; j<2; j++)
		{
			p = a & 0x7fc;
			b += Ttab(p);
			a = rotrFixed(a, 9U);
	
			p = b & 0x7fc;
			c += Ttab(p);
			b = rotrFixed(b, 9U);
	
			p = c & 0x7fc;
			d += Ttab(p);
			c = rotrFixed(c, 9U);
	
			p = d & 0x7fc;
			a += Ttab(p);
			d = rotrFixed(d, 9U);
		}

		n1 = d; n2 = b; n3 = a; n4 = c;
	
		p = a & 0x7fc;
		b += Ttab(p);
		a = rotrFixed(a, 9U);
	
		p = b & 0x7fc;
		c += Ttab(p);
		b = rotrFixed(b, 9U);
	
		p = c & 0x7fc;
		d += Ttab(p);
		c = rotrFixed(c, 9U);
	
		p = d & 0x7fc;
		a += Ttab(p);
		d = rotrFixed(d, 9U);
		
		// generate 8192 bits
		for (unsigned int i=0; i<64; i++)
		{
			p = a & 0x7fc;
			a = rotrFixed(a, 9U);
			b += Ttab(p);
			b ^= a;
	
			q = b & 0x7fc;
			b = rotrFixed(b, 9U);
			c ^= Ttab(q);
			c += b;
	
			p = (p+c) & 0x7fc;
			c = rotrFixed(c, 9U);
			d += Ttab(p);
			d ^= c;
	
			q = (q+d) & 0x7fc;
			d = rotrFixed(d, 9U);
			a ^= Ttab(q);
			a += d;
	
			p = (p+a) & 0x7fc;
			b ^= Ttab(p);
			a = rotrFixed(a, 9U);
	
			q = (q+b) & 0x7fc;
			c += Ttab(q);
			b = rotrFixed(b, 9U);
	
			p = (p+c) & 0x7fc;
			d ^= Ttab(p);
			c = rotrFixed(c, 9U);
	
			q = (q+d) & 0x7fc;
			d = rotrFixed(d, 9U);
			a += Ttab(q);

#ifdef IS_LITTLE_ENDIAN
			wout[0] = byteReverse(b + S[4*i+0]);
			wout[1] = byteReverse(c ^ S[4*i+1]);
			wout[2] = byteReverse(d + S[4*i+2]);
			wout[3] = byteReverse(a ^ S[4*i+3]);
#else
			wout[0] = b + S[4*i+0];
			wout[1] = c ^ S[4*i+1];
			wout[2] = d + S[4*i+2];
			wout[3] = a ^ S[4*i+3];
#endif
			wout += 4;
	
			if (i & 1)
			{
				a += n3;
				b += n4;
				c ^= n3;
				d ^= n4;
			}
			else
			{
				a += n1;
				b += n2;        
				c ^= n1;
				d ^= n2;
			}
		}
	}

	a = b = c = d = n1 = n2 = n3 = n4 = 0;
	p = q = 0;
}

NAMESPACE_END
