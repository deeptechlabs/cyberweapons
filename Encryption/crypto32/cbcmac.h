#ifndef CRYPTOPP_CBCMAC_H
#define CRYPTOPP_CBCMAC_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

/// CBC-MAC

/** Compatible with FIPS 113. T should be an encryption class.
	Secure only for fixed length messages. For variable length
	messages use DMAC.
*/
template <class T> class CBC_MAC : public MessageAuthenticationCode
{
public:
	enum {KEYLENGTH=T::KEYLENGTH, DIGESTSIZE=T::BLOCKSIZE};

	CBC_MAC(const byte *key, unsigned int keylength = KEYLENGTH);

	void Update(const byte *input, unsigned int length);
	void Final(byte *mac);
	unsigned int DigestSize() const {return DIGESTSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return T::KeyLength(keylength);}

private:
	void ProcessBuf();
	T cipher;
	SecByteBlock reg;
	unsigned int counter;
};

template <class T>
CBC_MAC<T>::CBC_MAC(const byte *key, unsigned int keylength)
	: cipher(key, keylength)
	, reg(T::BLOCKSIZE)
	, counter(0)
{
	memset(reg, 0, T::BLOCKSIZE);
}

template <class T>
void CBC_MAC<T>::Update(const byte *input, unsigned int length)
{
	while (counter && length)
	{
		reg[counter++] ^= *input++;
		if (counter == T::BLOCKSIZE)
			ProcessBuf();
		length--;
	}

	while (length >= T::BLOCKSIZE)
	{
		xorbuf(reg, input, T::BLOCKSIZE);
		ProcessBuf();
		input += T::BLOCKSIZE;
		length -= T::BLOCKSIZE;
	}

	while (length--)
	{
		reg[counter++] ^= *input++;
		if (counter == T::BLOCKSIZE)
			ProcessBuf();
	}
}

template <class T>
void CBC_MAC<T>::Final(byte *mac)
{
	if (counter)
		ProcessBuf();
	memcpy(mac, reg, T::BLOCKSIZE);
}

template <class T>
void CBC_MAC<T>::ProcessBuf()
{
	cipher.ProcessBlock(reg);
	counter = 0;
}

NAMESPACE_END

#endif
