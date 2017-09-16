// algebra.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "algebra.h"
#include "integer.h"

#include <vector>

NAMESPACE_BEGIN(CryptoPP)

template <class T> const T& AbstractGroup<T>::Double(const Element &a) const
{
	return Add(a, a);
}

template <class T> const T& AbstractGroup<T>::Subtract(const Element &a, const Element &b) const
{
	return Add(a, Inverse(b));
}

template <class T> T& AbstractGroup<T>::Accumulate(Element &a, const Element &b) const
{
	return a = Add(a, b);
}

template <class T> T& AbstractGroup<T>::Reduce(Element &a, const Element &b) const
{
	return a = Subtract(a, b);
}

template <class T> const T& AbstractRing<T>::Square(const Element &a) const
{
	return Multiply(a, a);
}

template <class T> const T& AbstractRing<T>::Divide(const Element &a, const Element &b) const
{
	return Multiply(a, MultiplicativeInverse(b));
}

template <class T> const T& AbstractEuclideanDomain<T>::Mod(const Element &a, const Element &b) const
{
	Element q;
	DivisionAlgorithm(result, q, a, b);
	return result;
}

template <class T> const T& AbstractEuclideanDomain<T>::Gcd(const Element &a, const Element &b) const
{
	Element g[3]={b, a};
	unsigned int i0=0, i1=1, i2=2;

	while (!Equal(g[i1], Zero()))
	{
		g[i2] = Mod(g[i0], g[i1]);
		unsigned int t = i0; i0 = i1; i1 = i2; i2 = t;
	}

	return result = g[i0];
}

template <class T> const QuotientRing<T>::Element& QuotientRing<T>::MultiplicativeInverse(const Element &a) const
{
	Element g[3]={m_modulus, a};
#ifdef __BCPLUSPLUS__
    // BC++50 workaround          
	Element v[3];
    v[0]=m_domain.Zero();
    v[1]=m_domain.One();
#else
	Element v[3]={m_domain.Zero(), m_domain.One()};
#endif
	Element y;
	unsigned int i0=0, i1=1, i2=2;

	while (!Equal(g[i1], Zero()))
	{
		// y = g[i0] / g[i1];
		// g[i2] = g[i0] % g[i1];
		m_domain.DivisionAlgorithm(g[i2], y, g[i0], g[i1]);
		// v[i2] = v[i0] - (v[i1] * y);
		v[i2] = m_domain.Subtract(v[i0], m_domain.Multiply(v[i1], y));
		unsigned int t = i0; i0 = i1; i1 = i2; i2 = t;
	}

	return m_domain.IsUnit(g[i0]) ? m_domain.Divide(v[i0], g[i0]) : m_domain.Zero();
}

template <class T> T AbstractGroup<T>::ScalarMultiply(const Element &base, const Integer &exponent) const
{
	Element result;
	SimultaneousMultiplication(&result, *this, base, &exponent, &exponent+1);
	return result;
}

template <class T> T AbstractGroup<T>::CascadeScalarMultiply(const Element &x, const Integer &e1, const Element &y, const Integer &e2) const
{
	const unsigned expLen = STDMAX(e1.BitCount(), e2.BitCount());
	if (expLen==0)
		return Zero();

	const unsigned w = (expLen <= 46 ? 1 : (expLen <= 260 ? 2 : 3));
	const unsigned tableSize = 1<<w;
	std::vector<Element> powerTable(tableSize << w);

	powerTable[1] = x;
	powerTable[tableSize] = y;
	if (w==1)
		powerTable[3] = Add(x,y);
	else
	{
		powerTable[2] = Double(x);
		powerTable[2*tableSize] = Double(y);

		unsigned i, j;

		for (i=3; i<tableSize; i+=2)
			powerTable[i] = Add(powerTable[i-2], powerTable[2]);
		for (i=1; i<tableSize; i+=2)
			for (j=i+tableSize; j<(tableSize<<w); j+=tableSize)
				powerTable[j] = Add(powerTable[j-tableSize], y);

		for (i=3*tableSize; i<(tableSize<<w); i+=2*tableSize)
			powerTable[i] = Add(powerTable[i-2*tableSize], powerTable[2*tableSize]);
		for (i=tableSize; i<(tableSize<<w); i+=2*tableSize)
			for (j=i+2; j<i+tableSize; j+=2)
				powerTable[j] = Add(powerTable[j-1], x);
	}

	Element result;
	unsigned power1 = 0, power2 = 0, prevPosition = expLen-1;
	bool firstTime = true;

	for (int i = expLen-1; i>=0; i--)
	{
		power1 = 2*power1 + e1.GetBit(i);
		power2 = 2*power2 + e2.GetBit(i);

		if (i==0 || 2*power1 >= tableSize || 2*power2 >= tableSize)
		{
			unsigned squaresBefore = prevPosition-i;
			unsigned squaresAfter = 0;
			prevPosition = i;
			while ((power1 || power2) && power1%2 == 0 && power2%2==0)
			{
				power1 /= 2;
				power2 /= 2;
				squaresBefore--;
				squaresAfter++;
			}
			if (firstTime)
			{
				result = powerTable[(power2<<w) + power1];
				firstTime = false;
			}
			else
			{
				while (squaresBefore--)
					result = Double(result);
				if (power1 || power2)
					Accumulate(result, powerTable[(power2<<w) + power1]);
			}
			while (squaresAfter--)
				result = Double(result);
			power1 = power2 = 0;
		}
	}
	return result;
}

template <class Element, class Iterator> Element GeneralCascadeMultiplication(const AbstractGroup<Element> &group, Iterator begin, Iterator end)
{
	if (end-begin == 1)
		return group.ScalarMultiply((*begin).second, (*begin).first);
	else if (end-begin == 2)
		return group.CascadeScalarMultiply((*begin).second, (*begin).first, (*(begin+1)).second, (*(begin+1)).first);
	else
	{
		Integer q, r;
		Iterator last = end;
		--last;

		std::make_heap(begin, end);
		std::pop_heap(begin, end);

		while (!!(*begin).first)
		{
			// (*last).first is largest exponent, (*begin).first is next largest
			Integer::Divide(r, q, (*last).first, (*begin).first);

			if (q == Integer::One())
				group.Accumulate((*begin).second, (*last).second);	// avoid overhead of GeneralizedMultiplication()
			else
				group.Accumulate((*begin).second, group.ScalarMultiply((*last).second, q));

			(*last).first = r;

			std::push_heap(begin, end);
			std::pop_heap(begin, end);
		}

		return group.ScalarMultiply((*last).second, (*last).first);
	}
}

template <class Element>
struct WindowSlider
{
	bool FindFirstWindow(const AbstractGroup<Element> &group, const Integer &expIn)
	{
		exp = &expIn;
		expLen = expIn.BitCount();
		windowSize = expLen <= 17 ? 1 : (expLen <= 24 ? 2 : (expLen <= 70 ? 3 : (expLen <= 197 ? 4 : (expLen <= 539 ? 5 : (expLen <= 1434 ? 6 : 7)))));
		buckets.resize(1<<(windowSize-1), group.Zero());
		windowEnd = 0;
		return FindNextWindow();
	}
	bool FindNextWindow()
	{
		windowBegin = windowEnd;
		if (windowBegin >= expLen)
			return false;
		const Integer &e = *exp;
		while (!e.GetBit(windowBegin))
			windowBegin++;
		windowEnd = windowBegin+windowSize;
		nextBucket = 0;
		for (unsigned int i=windowBegin+1; i<windowEnd; i++)
			nextBucket |= e.GetBit(i) << (i-windowBegin-1);
		assert(nextBucket < buckets.size());
		return true;
	}

	std::vector<Element> buckets;
	const Integer *exp;
	unsigned int expLen, windowSize, windowBegin, windowEnd, nextBucket;
};

template <class Element, class Iterator, class ConstIterator>
void SimultaneousMultiplication(Iterator result, const AbstractGroup<Element> &group, const Element &base, ConstIterator expBegin, ConstIterator expEnd)
{
	unsigned int expCount = std::distance(expBegin, expEnd);

	std::vector<WindowSlider<Element> > exponents(expCount);
	unsigned int i;

	bool notDone = false;
	for (i=0; i<expCount; i++)
	{
		assert(expBegin->NotNegative());
		notDone = exponents[i].FindFirstWindow(group, *expBegin++) || notDone;
	}

	unsigned int expBitPosition = 0;
	Element g = base;
	while (notDone)
	{
		notDone = false;
		for (i=0; i<expCount; i++)
		{
			if (expBitPosition < exponents[i].expLen && expBitPosition == exponents[i].windowBegin)
			{
				Element &bucket = exponents[i].buckets[exponents[i].nextBucket];
				group.Accumulate(bucket, g);
				exponents[i].FindNextWindow();
			}
			notDone = notDone || exponents[i].windowBegin < exponents[i].expLen;
		}

		if (notDone)
		{
			g = group.Double(g);
			expBitPosition++;
		}
	}

	for (i=0; i<expCount; i++)
	{
		Element &r = *result++;
		std::vector<Element> &buckets = exponents[i].buckets;
		r = buckets[buckets.size()-1];
		if (buckets.size() > 1)
		{
			for (int j = buckets.size()-2; j >= 1; j--)
			{
				group.Accumulate(buckets[j], buckets[j+1]);
				group.Accumulate(r, buckets[j]);
			}
			group.Accumulate(buckets[0], buckets[1]);
			r = group.Add(group.Double(r), buckets[0]);
		}
	}
}

template <class T> T AbstractRing<T>::Exponentiate(const Element &base, const Integer &exponent) const
{
	Element result;
	SimultaneousMultiplication(&result, MultiplicativeGroup(), base, &exponent, &exponent+1);
	return result;
}

template <class T> T AbstractRing<T>::CascadeExponentiate(const Element &x, const Integer &e1, const Element &y, const Integer &e2) const
{
	return MultiplicativeGroup().CascadeScalarMultiply(x, e1, y, e2);
}

template <class Element, class Iterator> Element GeneralCascadeExponentiation(const AbstractRing<Element> &ring, Iterator begin, Iterator end)
{
	return GeneralCascadeMultiplication<Element>(ring.MultiplicativeGroup(), begin, end);
}

template <class Element, class Iterator, class ConstIterator>
void SimultaneousExponentiation(Iterator result, const AbstractRing<Element> &ring, const Element &base, ConstIterator expBegin, ConstIterator expEnd)
{
	SimultaneousMultiplication<Element>(result, ring.MultiplicativeGroup(), base, expBegin, expEnd);
}

NAMESPACE_END
