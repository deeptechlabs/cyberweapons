// gf2n.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "gf2n.h"
#include "algebra.h"
#include "words.h"

#include <iostream>

#include "algebra.cpp"

NAMESPACE_BEGIN(CryptoPP)

PolynomialMod2::PolynomialMod2()
{
}

PolynomialMod2::PolynomialMod2(word value, unsigned int bitLength)
	: reg(bitsToWords(bitLength))
{
	assert(reg.size>0);

	reg[0] = value;
	SetWords(reg+1, 0, reg.size-1);
}

PolynomialMod2::PolynomialMod2(const PolynomialMod2& t)
	: reg(t.reg.size)
{
	CopyWords(reg, t.reg, reg.size);
}

void PolynomialMod2::Randomize(RandomNumberGenerator &rng, unsigned int nbits)
{
	const unsigned int nbytes = nbits/8 + 1;
	SecByteBlock buf(nbytes);
	rng.GetBlock(buf, nbytes);
	buf[0] = (byte)Crop(buf[0], nbits % 8);
	Decode(buf, nbytes);
}

PolynomialMod2 PolynomialMod2::AllOnes(unsigned int bitLength)
{
	PolynomialMod2 result((word)0, bitLength);
	SetWords(result.reg, ~(word)0, result.reg.size);
	if (bitLength%WORD_BITS)
		result.reg[result.reg.size-1] = (word)Crop(result.reg[result.reg.size-1], bitLength%WORD_BITS);
	return result;
}

void PolynomialMod2::SetBit(unsigned int n, int value)
{
	if (value)
	{
		reg.CleanGrow(n/WORD_BITS + 1);
		reg[n/WORD_BITS] |= (word(1) << (n%WORD_BITS));
	}
	else
	{
		if (n/WORD_BITS < reg.size)
			reg[n/WORD_BITS] &= ~(word(1) << (n%WORD_BITS));
	}
}

byte PolynomialMod2::GetByte(unsigned int n) const
{
	if (n/WORD_SIZE >= reg.size)
		return 0;
	else
		return byte(reg[n/WORD_SIZE] >> ((n%WORD_SIZE)*8));
}

void PolynomialMod2::SetByte(unsigned int n, byte value)
{
	reg.CleanGrow(bytesToWords(n+1));
	reg[n/WORD_SIZE] &= ~(word(0xff) << 8*(n%WORD_SIZE));
	reg[n/WORD_SIZE] |= (word(value) << 8*(n%WORD_SIZE));
}

PolynomialMod2 PolynomialMod2::Monomial(unsigned i) 
{
	PolynomialMod2 r((word)0, i+1); 
	r.SetBit(i); 
	return r;
}

PolynomialMod2 PolynomialMod2::Trinomial(unsigned t0, unsigned t1, unsigned t2) 
{
	PolynomialMod2 r((word)0, t0+1);
	r.SetBit(t0);
	r.SetBit(t1);
	r.SetBit(t2);
	return r;
}

const PolynomialMod2 &PolynomialMod2::Zero()
{
	static const PolynomialMod2 zero;
	return zero;
}

const PolynomialMod2 &PolynomialMod2::One()
{
	static const PolynomialMod2 one = 1;
	return one;
}

void PolynomialMod2::Decode(const byte *input, unsigned int inputLen)
{
	reg.CleanNew(bytesToWords(inputLen));

	for (unsigned int i=0; i<inputLen; i++)
		reg[i/WORD_SIZE] |= input[inputLen-1-i] << (i%WORD_SIZE)*8;
}

unsigned int PolynomialMod2::Encode(byte *output, unsigned int outputLen) const
{
	unsigned int byteCount = STDMIN(outputLen, reg.size*WORD_SIZE);

	for (unsigned int i=0; i<byteCount; i++)
		output[outputLen-1-i] = byte(reg[i/WORD_SIZE] >> (i%WORD_SIZE)*8);

	memset(output, 0, outputLen-byteCount);
	return outputLen;
}

unsigned int PolynomialMod2::WordCount() const
{
	return CountWords(reg, reg.size);
}

unsigned int PolynomialMod2::ByteCount() const
{
	unsigned wordCount = WordCount();
	if (wordCount)
		return (wordCount-1)*WORD_SIZE + BytePrecision(reg[wordCount-1]);
	else
		return 0;
}

unsigned int PolynomialMod2::BitCount() const
{
	unsigned wordCount = WordCount();
	if (wordCount)
		return (wordCount-1)*WORD_BITS + BitPrecision(reg[wordCount-1]);
	else
		return 0;
}

unsigned int PolynomialMod2::Parity() const
{
	unsigned i;
	word temp=0;
	for (i=0; i<reg.size; i++)
		temp ^= reg[i];
	return CryptoPP::Parity(temp);
}

PolynomialMod2& PolynomialMod2::operator=(const PolynomialMod2& t)
{
	reg.CopyFrom(t.reg);
	return *this;
}

PolynomialMod2& PolynomialMod2::operator^=(const PolynomialMod2& t)
{
	reg.CleanGrow(t.reg.size);
	XorWords(reg, t.reg, t.reg.size);
	return *this;
}

PolynomialMod2 operator^(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	if (b.reg.size >= a.reg.size)
	{
		PolynomialMod2 result((word)0, b.reg.size*WORD_BITS);
		XorWords(result.reg, a.reg, b.reg, a.reg.size);
		CopyWords(result.reg+a.reg.size, b.reg+a.reg.size, b.reg.size-a.reg.size);
		return result;
	}
	else
	{
		PolynomialMod2 result((word)0, a.reg.size*WORD_BITS);
		XorWords(result.reg, a.reg, b.reg, b.reg.size);
		CopyWords(result.reg+b.reg.size, a.reg+b.reg.size, a.reg.size-b.reg.size);
		return result;
	}
}

PolynomialMod2 operator&(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	PolynomialMod2 result((word)0, WORD_BITS*STDMIN(a.reg.size, b.reg.size));
	AndWords(result.reg, a.reg, b.reg, result.reg.size);
	return result;
}

PolynomialMod2 operator*(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	PolynomialMod2 result((word)0, a.BitCount() + b.BitCount());

	for (int i=b.Degree(); i>=0; i--)
	{
		result <<= 1;
		if (b[i])
			XorWords(result.reg, a.reg, a.reg.size);
	}
	return result;
}

PolynomialMod2 PolynomialMod2::Squared() const
{
	static const word map[16] = {0, 1, 4, 5, 16, 17, 20, 21, 64, 65, 68, 69, 80, 81, 84, 85};

	PolynomialMod2 result((word)0, 2*reg.size*WORD_BITS);

	for (unsigned i=0; i<reg.size; i++)
	{
		unsigned j;

		for (j=0; j<WORD_BITS; j+=8)
			result.reg[2*i] |= map[(reg[i] >> (j/2)) % 16] << j;

		for (j=0; j<WORD_BITS; j+=8)
			result.reg[2*i+1] |= map[(reg[i] >> (j/2 + WORD_BITS/2)) % 16] << j;
	}

	return result;
}

void PolynomialMod2::Divide(PolynomialMod2 &remainder, PolynomialMod2 &quotient,
				   const PolynomialMod2 &dividend, const PolynomialMod2 &divisor)
{
	if (!divisor)
		throw PolynomialMod2::DivideByZero();

	int degree = divisor.Degree();
	remainder.reg.CleanNew(bitsToWords(degree+1));
	if (dividend.BitCount() >= divisor.BitCount())
		quotient.reg.CleanNew(bitsToWords(dividend.BitCount() - divisor.BitCount() + 1));
	else
		quotient.reg.CleanNew(0);

	for (int i=dividend.Degree(); i>=0; i--)
	{
		remainder <<= 1;
		remainder.reg[0] |= dividend[i];
		if (remainder[degree])
		{
			remainder -= divisor;
			quotient.SetBit(i);
		}
	}
}

PolynomialMod2 operator/(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	PolynomialMod2 remainder, quotient;
	PolynomialMod2::Divide(remainder, quotient, a, b);
	return quotient;
}

PolynomialMod2 operator%(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	PolynomialMod2 remainder, quotient;
	PolynomialMod2::Divide(remainder, quotient, a, b);
	return remainder;
}

PolynomialMod2& PolynomialMod2::operator<<=(unsigned int n)
{
	if (!reg.size)
		return *this;

	int i;
	word u;
	word carry=0;
	word *r=reg;

	if (n==1)	// special case code for most frequent case
	{
		i = reg.size;
		while (i--)
		{
			u = *r;
			*r = (u << 1) | carry;
			carry = u >> (WORD_BITS-1);
			r++;
		}

		if (carry)
		{
			reg.Grow(reg.size+1);
			reg[reg.size-1] = carry;
		}

		return *this;
	}

	int shiftWords = n / WORD_BITS;
	int shiftBits = n % WORD_BITS;

	if (shiftBits)
	{
		i = reg.size;
		while (i--)
		{
			u = *r;
			*r = (u << shiftBits) | carry;
			carry = u >> (WORD_BITS-shiftBits);
			r++;
		}
	}

	if (carry)
	{
		reg.Grow(reg.size+shiftWords+1);
		reg[reg.size-1] = carry;
	}
	else
		reg.Grow(reg.size+shiftWords);

	if (shiftWords)
	{
		for (i = reg.size-1; i>=shiftWords; i--)
			reg[i] = reg[i-shiftWords];
		for (; i>=0; i--)
			reg[i] = 0;
	}

	return *this;
}

PolynomialMod2& PolynomialMod2::operator>>=(unsigned int n)
{
	if (!reg.size)
		return *this;

	int shiftWords = n / WORD_BITS;
	int shiftBits = n % WORD_BITS;

	unsigned i;
	word u;
	word carry=0;
	word *r=reg+reg.size-1;

	if (shiftBits)
	{
		i = reg.size;
		while (i--)
		{
			u = *r;
			*r = (u >> shiftBits) | carry;
			carry = u << (WORD_BITS-shiftBits);
			r--;
		}
	}

	if (shiftWords)
	{
		for (i=0; i<reg.size-shiftWords; i++)
			reg[i] = reg[i+shiftWords];
		for (; i<reg.size; i++)
			reg[i] = 0;
	}

	return *this;
}

PolynomialMod2 PolynomialMod2::operator<<(unsigned int n) const
{
	PolynomialMod2 result(*this);
	return result<<=n;
}

PolynomialMod2 PolynomialMod2::operator>>(unsigned int n) const
{
	PolynomialMod2 result(*this);
	return result>>=n;
}

bool PolynomialMod2::operator!() const
{
	for (unsigned i=0; i<reg.size; i++)
		if (reg[i]) return false;
	return true;
}

bool operator==(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	unsigned i, smallerSize = STDMIN(a.reg.size, b.reg.size);

	for (i=0; i<smallerSize; i++)
		if (a.reg[i] != b.reg[i]) return false;

	for (i=smallerSize; i<a.reg.size; i++)
		if (a.reg[i] != 0) return false;

	for (i=smallerSize; i<b.reg.size; i++)
		if (b.reg[i] != 0) return false;

	return true;
}

std::ostream& operator<<(std::ostream& out, const PolynomialMod2 &a)
{
	// Get relevant conversion specifications from ostream.
	long f = out.flags() & std::ios::basefield;	// Get base digits.
	int bits, block;
	char suffix;
	switch(f)
	{
	case std::ios::oct :
		bits = 3;
		block = 4;
		suffix = 'o';
		break;
	case std::ios::hex :
		bits = 4;
		block = 2;
		suffix = 'h';
		break;
	default :
		bits = 1;
		block = 8;
		suffix = 'b';
	}

	if (!a)
		return out << '0' << suffix;

	SecBlock<char> s(a.BitCount()/bits+1);
	unsigned i;
	const char vec[]="0123456789ABCDEF";

	for (i=0; i*bits < a.BitCount(); i++)
	{
		int digit=0;
		for (int j=0; j<bits; j++)
			digit |= a[i*bits+j] << j;
		s[i]=vec[digit];
	}

	while (i--)
	{
		out << s[i];
		if (i && (i%block)==0)
			out << ',';
	}

	return out << suffix;
}

PolynomialMod2 PolynomialMod2::Gcd(const PolynomialMod2 &a, const PolynomialMod2 &b)
{
	return EuclideanDomainOf<PolynomialMod2>().Gcd(a, b);
}

bool PolynomialMod2::IsIrreducible() const
{
	signed int d = Degree();
	if (d <= 0)
		return false;

	PolynomialMod2 t(2), u(t);
	for (int i=1; i<=d/2; i++)
	{
		u = u.Squared()%(*this);
		if (!Gcd(u+t, *this).IsUnit())
			return false;
	}
	return true;
}

// ********************************************************

GF2NP::GF2NP(const PolynomialMod2 &modulus)
	: QuotientRing<EuclideanDomainOf<PolynomialMod2> >(EuclideanDomainOf<PolynomialMod2>(), modulus), m(modulus.Degree()) 
{
}

// ********************************************************

GF2NT::GF2NT(unsigned int t0, unsigned int t1, unsigned int t2)
	: GF2NP(PolynomialMod2::Trinomial(t0, t1, t2))
	, t0(t0), t1(t1)
	, result((word)0, m)
{
	assert(t0 > t1 && t1 > t2 && t2==0);
}

const GF2NT::Element& GF2NT::MultiplicativeInverse(const Element &a) const
{
	SecWordBlock T(m_modulus.reg.size * 4);
	word *b = T;
	word *c = T+m_modulus.reg.size;
	word *f = T+2*m_modulus.reg.size;
	word *g = T+3*m_modulus.reg.size;
	unsigned int bcLen=1, fgLen=m_modulus.reg.size;
	unsigned int k=0;

	SetWords(T, 0, 3*m_modulus.reg.size);
	b[0]=1;
	assert(a.reg.size <= m_modulus.reg.size);
	CopyWords(f, a.reg, a.reg.size);
	CopyWords(g, m_modulus.reg, m_modulus.reg.size);

	while (1)
	{
		word t=f[0];
		while (!t)
		{
			ShiftWordsRightByWords(f, fgLen, 1);
			if (c[bcLen-1])
				bcLen++;
			assert(bcLen <= m_modulus.reg.size);
			ShiftWordsLeftByWords(c, bcLen, 1);
			k+=WORD_BITS;
			t=f[0];
		}

		unsigned int i=0;
		while (t%2 == 0)
		{
			t>>=1;
			i++;
		}
		k+=i;

		if (t==1 && CountWords(f, fgLen)==1)
			break;

		if (i==1)
		{
			ShiftWordsRightByBits(f, fgLen, 1);
			t=ShiftWordsLeftByBits(c, bcLen, 1);
		}
		else
		{
			ShiftWordsRightByBits(f, fgLen, i);
			t=ShiftWordsLeftByBits(c, bcLen, i);
		}
		if (t)
		{
			c[bcLen] = t;
			bcLen++;
			assert(bcLen <= m_modulus.reg.size);
		}

		if (f[fgLen-1]==0 && g[fgLen-1]==0)
			fgLen--;

		if (f[fgLen-1] < g[fgLen-1])
		{
			std::swap(f, g);
			std::swap(b, c);
		}

		XorWords(f, g, fgLen);
		XorWords(b, c, bcLen);
	}

	while (k >= WORD_BITS)
	{
		word temp = b[0];
		// right shift b
		for (unsigned i=0; i+1<bitsToWords(m); i++)
			b[i] = b[i+1];
		b[bitsToWords(m)-1] = 0;

		if (t1 < WORD_BITS)
			for (unsigned int j=0; j<WORD_BITS-t1; j++)
				temp ^= ((temp >> j) & 1) << (t1 + j);
		else
			b[t1/WORD_BITS-1] ^= temp << t1%WORD_BITS;

		if (t1 % WORD_BITS)
			b[t1/WORD_BITS] ^= temp >> (WORD_BITS - t1%WORD_BITS);

		if (t0%WORD_BITS)
		{
			b[t0/WORD_BITS-1] ^= temp << t0%WORD_BITS;
			b[t0/WORD_BITS] ^= temp >> (WORD_BITS - t0%WORD_BITS);
		}
		else
			b[t0/WORD_BITS-1] ^= temp;

		k -= WORD_BITS;
	}

	if (k)
	{
		word temp = b[0] << (WORD_BITS - k);
		ShiftWordsRightByBits(b, bitsToWords(m), k);

		if (t1 < WORD_BITS)
			for (unsigned int j=0; j<WORD_BITS-t1; j++)
				temp ^= ((temp >> j) & 1) << (t1 + j);
		else
			b[t1/WORD_BITS-1] ^= temp << t1%WORD_BITS;

		if (t1 % WORD_BITS)
			b[t1/WORD_BITS] ^= temp >> (WORD_BITS - t1%WORD_BITS);

		if (t0%WORD_BITS)
		{
			b[t0/WORD_BITS-1] ^= temp << t0%WORD_BITS;
			b[t0/WORD_BITS] ^= temp >> (WORD_BITS - t0%WORD_BITS);
		}
		else
			b[t0/WORD_BITS-1] ^= temp;
	}

	CopyWords(result.reg.ptr, b, result.reg.size);
	return result;
}

const GF2NT::Element& GF2NT::Multiply(const Element &a, const Element &b) const
{
	unsigned int aSize = STDMIN(a.reg.size, result.reg.size);
	Element r((word)0, m);

	for (int i=m-1; i>=0; i--)
	{
		if (r[m-1])
		{
			ShiftWordsLeftByBits(r.reg.ptr, r.reg.size, 1);
			XorWords(r.reg.ptr, m_modulus.reg, r.reg.size);
		}
		else
			ShiftWordsLeftByBits(r.reg.ptr, r.reg.size, 1);

		if (b[i])
			XorWords(r.reg.ptr, a.reg, aSize);
	}

	if (m%WORD_BITS)
		r.reg.ptr[r.reg.size-1] = (word)Crop(r.reg[r.reg.size-1], m%WORD_BITS);

	CopyWords(result.reg.ptr, r.reg.ptr, result.reg.size);
	return result;
}

const GF2NT::Element& GF2NT::Reduced(const Element &a) const
{
	SecWordBlock b(a.reg);

	unsigned i;
	for (i=b.size-1; i>=bitsToWords(t0); i--)
	{
		word temp = b[i];

		if (t0%WORD_BITS)
		{
			b[i-t0/WORD_BITS] ^= temp >> t0%WORD_BITS;
			b[i-t0/WORD_BITS-1] ^= temp << (WORD_BITS - t0%WORD_BITS);
		}
		else
			b[i-t0/WORD_BITS] ^= temp;

		if ((t0-t1)%WORD_BITS)
		{
			b[i-(t0-t1)/WORD_BITS] ^= temp >> (t0-t1)%WORD_BITS;
			b[i-(t0-t1)/WORD_BITS-1] ^= temp << (WORD_BITS - (t0-t1)%WORD_BITS);
		}
		else
			b[i-(t0-t1)/WORD_BITS] ^= temp;
	}

	if (i==bitsToWords(t0)-1 && t0%WORD_BITS)
	{
		word mask = ((word)1<<(t0%WORD_BITS))-1;
		word temp = b[i] & ~mask;
		b[i] &= mask;

		b[i-t0/WORD_BITS] ^= temp >> t0%WORD_BITS;

		if ((t0-t1)%WORD_BITS)
		{
			b[i-(t0-t1)/WORD_BITS] ^= temp >> (t0-t1)%WORD_BITS;
			if ((t0-t1)%WORD_BITS > t0%WORD_BITS)
				b[i-(t0-t1)/WORD_BITS-1] ^= temp << (WORD_BITS - (t0-t1)%WORD_BITS);
			else
				assert(temp==0);
		}
		else
			b[i-(t0-t1)/WORD_BITS] ^= temp;
	}

	SetWords(result.reg.ptr, 0, result.reg.size);
	CopyWords(result.reg.ptr, b, STDMIN(b.size, result.reg.size));
	return result;
}

NAMESPACE_END
