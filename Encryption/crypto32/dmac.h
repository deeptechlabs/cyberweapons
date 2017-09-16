#ifndef CRYPTOPP_DMAC_H
#define CRYPTOPP_DMAC_H

#include "cbcmac.h"

NAMESPACE_BEGIN(CryptoPP)

/// DMAC

/** Based on "CBC MAC for Real-Time Data Sources" by Erez Petrank
	and Charles Rackoff. T should be an encryption class.
*/
template <class T> class DMAC : public MessageAuthenticationCode
{
public:
	enum {KEYLENGTH=T::KEYLENGTH, DIGESTSIZE=T::BLOCKSIZE};

	DMAC(const byte *key, unsigned int keylength = KEYLENGTH);

	void Update(const byte *input, unsigned int length);
	void Final(byte *mac);
	unsigned int DigestSize() const {return DIGESTSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return T::KeyLength(keylength);}

private:
	byte *GenerateSubKeys(const byte *key, unsigned int keylength);

	unsigned int subkeylength;
	SecByteBlock subkeys;
	CBC_MAC<T> mac1;
	T f2;
	unsigned int counter;
};

template <class T>
DMAC<T>::DMAC(const byte *key, unsigned int keylength)
	: subkeylength(T::KeyLength(T::BLOCKSIZE))
	, subkeys(2*STDMAX((unsigned int)T::BLOCKSIZE, subkeylength))
	, mac1(GenerateSubKeys(key, keylength), subkeylength)
	, f2(subkeys+subkeys.size/2, subkeylength)
	, counter(0)
{
	subkeys.Resize(0);
}

template <class T>
void DMAC<T>::Update(const byte *input, unsigned int length)
{
	mac1.Update(input, length);
	counter = (counter + length) % T::BLOCKSIZE;
}

template <class T>
void DMAC<T>::Final(byte *mac)
{
	byte pad[T::BLOCKSIZE];
	byte padByte = byte(T::BLOCKSIZE-counter);
	memset(pad, padByte, padByte);
	mac1.Update(pad, padByte);
	mac1.Final(mac);
	f2.ProcessBlock(mac);
}

template <class T>
byte *DMAC<T>::GenerateSubKeys(const byte *key, unsigned int keylength)
{
	T cipher(key, keylength);
	memset(subkeys, 0, subkeys.size);
	cipher.ProcessBlock(subkeys);
	subkeys[subkeys.size/2 + T::BLOCKSIZE - 1] = 1;
	cipher.ProcessBlock(subkeys+subkeys.size/2);
	return subkeys;
}

NAMESPACE_END

#endif
