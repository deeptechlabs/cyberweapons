// hmac.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_HMAC_H
#define CRYPTOPP_HMAC_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

// HMAC(K, text) = H(K XOR opad, H(K XOR ipad, text))

template <class T> class HMAC : public MessageAuthenticationCode
{
public:
	// put enums here for Metrowerks 4
	enum {KEYLENGTH=16, MAX_KEYLENGTH=T::DATASIZE, DIGESTSIZE=T::DIGESTSIZE, DATASIZE=T::DATASIZE};

	HMAC(const byte *userKey, unsigned int keylength=KEYLENGTH);
	void Update(const byte *input, unsigned int length);
	void Final(byte *mac);
	unsigned int DigestSize() const {return DIGESTSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return STDMIN(keylength, (unsigned int)MAX_KEYLENGTH);}

private:
	enum {IPAD=0x36, OPAD=0x5c};

	void Init();

	SecByteBlock k_ipad, k_opad;
	T hash;
};

template <class T>
HMAC<T>::HMAC(const byte *userKey, unsigned int keylength)
	: k_ipad(MAX_KEYLENGTH), k_opad(MAX_KEYLENGTH)
{
	assert(keylength == KeyLength(keylength));

	memset(k_ipad, IPAD, MAX_KEYLENGTH);
	xorbuf(k_ipad, userKey, keylength);

	memset(k_opad, OPAD, MAX_KEYLENGTH);
	xorbuf(k_opad, userKey, keylength);

	Init();
}

template <class T>
void HMAC<T>::Init()
{
	hash.Update(k_ipad, MAX_KEYLENGTH);
}

template <class T>
void HMAC<T>::Update(const byte *input, unsigned int length)
{
	hash.Update(input, length);
}

template <class T>
void HMAC<T>::Final(byte *mac)
{
	hash.Final(mac);

	hash.Update(k_opad, MAX_KEYLENGTH);
	hash.Update(mac, DIGESTSIZE);
	hash.Final(mac);
	Init();
}

NAMESPACE_END

#endif
