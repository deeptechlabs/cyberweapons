// secshare.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "secshare.h"
#include "queue.h"
#include "algebra.h"
#include "gf2_32.h"
#include "polynomi.h"

#include "algebra.cpp"
#include "polynomi.cpp"

ANONYMOUS_NAMESPACE_BEGIN
class Field : public CryptoPP::GF2_32
{
public:
	Field() : CryptoPP::GF2_32(0xB1D89917) {}

	Element Divide(Element a, Element b) const
	{
		static Element invTable[256];
		Element bInv;

		if (b<256 && invTable[b])
			bInv = invTable[b];
		else
			bInv = invTable[b] = MultiplicativeInverse(b);

		return Multiply(a, bInv);
	}
};

typedef CryptoPP::PolynomialOverFixedRing<Field, 0> Polynomial;
typedef CryptoPP::RingOfPolynomialsOver<Field> PolynomialRing;

static const Field field;
static const PolynomialRing polynomialRing(field);
NAMESPACE_END

template<> const Field Polynomial::fixedRing(field);

NAMESPACE_BEGIN(CryptoPP)

ShareFork::ShareFork(RandomNumberGenerator &rng, word32 m, word32 n, BufferedTransformation *const *outports)
	: Fork(n, outports), m_rng(rng), m_threshold(m), m_count(0)
{
	for (unsigned int i=0; i<NumberOfPorts(); i++)
	{
		AccessPort(i).PutLong(m_threshold);
		AccessPort(i).PutLong(i+1);
	}
}

void ShareFork::Put(byte inByte)
{
	m_buffer = (m_buffer<<8) | inByte;
	if (++m_count == 4)
	{
		Share(m_buffer);
		m_count = 0;
		m_buffer = 0;
	}
}

void ShareFork::Put(const byte *inString, unsigned int length)
{
	while (length--)
		Put(*inString++);
}

void ShareFork::Share(word32 message)
{
	Polynomial::RandomizationParameter param(m_threshold, 0);
	Polynomial poly(m_rng, param);
	poly.SetCoefficient(0, message);

	for (unsigned int i=0; i<NumberOfPorts(); i++)
		AccessPort(i).PutLong(poly.EvaluateAt(i+1));
}

void ShareFork::InputFinished()
{
	byte filler = 4-m_count;
	assert(filler > 0 && filler <= 4);

	for (byte i = 0; i<filler; i++)
		Put(filler);

	assert(m_count == 0);
}

// ****************************************************************

ShareJoin::ShareJoin(unsigned int n, BufferedTransformation *outQ)
	: Join(n, outQ), m_x(n), m_indexRead(false), m_firstOutput(true)
{
	assert(n>0);
}

void ShareJoin::NotifyInput(unsigned int /* interfaceId */, unsigned int /* length */)
{
	unsigned long n = AccessPort(0).MaxRetrieveable();

	for (unsigned int i=1; n && i<NumberOfPorts(); i++)
		n = STDMIN(n, AccessPort(i).MaxRetrieveable());

	if (!m_indexRead && n>=8)
	{
		ReadIndex();
		n -= 8;
	}

	if (m_indexRead)
		Assemble(n);
}

void ShareJoin::ReadIndex()
{
	for (unsigned int i=0; i<NumberOfPorts(); i++)
	{
		AccessPort(i).GetLong(m_threshold);
		AccessPort(i).GetLong(m_x[i]);
	}

	m_indexRead = true;
}

void ShareJoin::NotifyClose(unsigned int id)
{
	if (InterfacesOpen() == 1)
	{
		byte filler = m_buffer & 0xff;
		for (unsigned int i=3; i && i>=filler; --i)
			AttachedTransformation()->Put(byte(m_buffer>>(8*i)));
	}

	Join::NotifyClose(id);
}

void ShareJoin::Assemble(unsigned long n)
{
	SecBlock<word32> y(NumberOfPorts());

	while (n>=4)
	{
		for (unsigned int i=0; i<NumberOfPorts(); i++)
			AccessPort(i).GetLong(y[i]);

		Output(polynomialRing.InterpolateAt(0, m_x, y, NumberOfPorts()));
		n -= 4;
	}
}

void ShareJoin::Output(word32 message)
{
	if (m_firstOutput)
		m_firstOutput = false;
	else
		AttachedTransformation()->PutLong(m_buffer);

	m_buffer = message;
}

// ************************************************************

DisperseFork::DisperseFork(unsigned int m, unsigned int n, BufferedTransformation *const *outports)
	: ShareFork(*(RandomNumberGenerator *)0, m, n, outports),
	  m_poly(m), m_polyCount(0)
{
}

void DisperseFork::Share(word32 message)
{
	m_poly[m_polyCount++] = message;

	if (m_polyCount==m_threshold)
	{
		Polynomial poly(m_poly.Begin(), m_poly.End());

		for (unsigned int i=0; i<NumberOfPorts(); i++)
			AccessPort(i).PutLong(poly.EvaluateAt(i+1));

		m_polyCount = 0;
	}
}

void DisperseFork::InputFinished()
{
	ShareFork::InputFinished();

	word32 filler = m_threshold - m_polyCount;
	for (word32 i=0; i<filler; i++)
		Share(filler);
}

DisperseJoin::DisperseJoin(unsigned int n, BufferedTransformation *outQ)
	: ShareJoin(n, outQ), m_firstPolyOutput(true)
{
}

void DisperseJoin::Assemble(unsigned long n)
{
	while (n>=4)
	{
		SecBlock<word32> y(NumberOfPorts());
		unsigned int i;

		for (i=0; i<NumberOfPorts(); i++)
			AccessPort(i).GetLong(y[i]);

		Polynomial poly(polynomialRing.Interpolate(m_x, y, NumberOfPorts()));

		if (m_firstPolyOutput)
		{
			m_polyBuffer.Grow(m_threshold);
			m_firstPolyOutput = false;
		}
		else
		{
			for (i=0; i<m_threshold; i++)
				Output(m_polyBuffer[i]);
		}

		for (i=0; i<m_threshold; i++)
			m_polyBuffer[i] = poly[i];

		n -= 4;
	}
}

void DisperseJoin::NotifyClose(unsigned int id)
{
	if (InterfacesOpen() == 1)
	{
		word32 filler = m_polyBuffer[m_threshold-1];
		for (word32 i=0; i+filler < m_threshold; ++i)
			Output(m_polyBuffer[i]);
	}

	ShareJoin::NotifyClose(id);
}

NAMESPACE_END
