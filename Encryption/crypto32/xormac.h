// xormac.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_XORMAC_H
#define CRYPTOPP_XORMAC_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T> class XMACC : public IteratedHash<typename T::HashWordType>, public MessageAuthenticationCode
{
public:
	typedef typename T::HashWordType HashWordType;

	// If you need to generate MACs with XMACC (instead of just verifying them),
	// you must save the counter before destroying an XMACC object
	// and reinitialize it the next time you create an XMACC with the same key.
	// Start counter at 0 when using a key for the first time.

	XMACC(const byte *userKey, word32 counter=0xffffffff);

	word32 CurrentCounter() const {return counter;}

	void Final(byte *mac);
	bool Verify(const byte *mac);
	unsigned int DigestSize() const {return DIGESTSIZE;}

	enum {KEYLENGTH=T::DIGESTSIZE-4, DIGESTSIZE = 4+T::DIGESTSIZE, DATASIZE = T::DATASIZE};

private:
	void Init();
	void HashBlock(const HashWordType *input);
	static void WriteWord32(byte *output, word32 value);
	static void XorDigest(HashWordType *digest, const HashWordType *buffer);

	SecByteBlock key;
	SecBlock<HashWordType> buffer;
	word32 counter, index;
};

template <class T> XMACC<T>::XMACC(const byte *userKey, word32 counter)
	: IteratedHash<T::HashWordType>(DATASIZE, T::DIGESTSIZE)
	, key(KEYLENGTH)
	, buffer(T::DIGESTSIZE/sizeof(HashWordType))
	, counter(counter)
{
	memcpy(key, userKey, KEYLENGTH);
	Init();
}

template <class T> void XMACC<T>::Init()
{
	countLo = countHi = 0;
	index = 0x80000000;
	memset(digest, 0, T::DIGESTSIZE);
}

template <class T> inline void XMACC<T>::WriteWord32(byte *output, word32 value)
{
	output[0] = byte(value >> 24);
	output[1] = byte(value >> 16);
	output[2] = byte(value >> 8);
	output[3] = byte(value);
}

template <class T> inline void XMACC<T>::XorDigest(HashWordType *digest, const HashWordType *buffer)
{
	for (unsigned i=0; i<(T::DIGESTSIZE/sizeof(HashWordType)); i++)
		digest[i] ^= buffer[i];
}

template <class T> void XMACC<T>::HashBlock(const HashWordType *input)
{
	memcpy(buffer, key, KEYLENGTH);
	WriteWord32((byte *)buffer.ptr+KEYLENGTH, ++index);
	T::CorrectEndianess(buffer, buffer, T::DIGESTSIZE);
	T::CorrectEndianess(data, input, DATASIZE);
	T::Transform(buffer, data);
	XorDigest(digest, buffer);
}

template <class T> void XMACC<T>::Final(byte *mac)
{
	assert(counter != 0xffffffff);

	PadLastBlock(DATASIZE-8);
	WriteWord32((byte *)data.ptr+DATASIZE-8, countHi);
	WriteWord32((byte *)data.ptr+DATASIZE-4, countLo);
	HashBlock(data);

	memcpy(buffer, key, KEYLENGTH);
	WriteWord32((byte *)buffer.ptr+KEYLENGTH, 0);
	memset(data, 0, DATASIZE-4);
	WriteWord32((byte *)data.ptr+DATASIZE-4, ++counter);
	T::CorrectEndianess(buffer, buffer, T::DIGESTSIZE);
	T::CorrectEndianess(data, data, DATASIZE);
	T::Transform(buffer, data);
	XorDigest(digest, buffer);

	WriteWord32(mac, counter);
	T::CorrectEndianess(digest, digest, T::DIGESTSIZE);
	memcpy(mac+4, digest, T::DIGESTSIZE);

	Init();		// reinit for next use
}

template <class T> bool XMACC<T>::Verify(const byte *mac)
{
	PadLastBlock(DATASIZE-8);
	WriteWord32((byte *)data.ptr+DATASIZE-8, countHi);
	WriteWord32((byte *)data.ptr+DATASIZE-4, countLo);
	HashBlock(data);

	memcpy(buffer, key, KEYLENGTH);
	WriteWord32((byte *)buffer.ptr+KEYLENGTH, 0);
	memset(data, 0, DATASIZE-4);
	memcpy((byte *)data.ptr+DATASIZE-4, mac, 4);
	T::CorrectEndianess(buffer, buffer, T::DIGESTSIZE);
	T::CorrectEndianess(data, data, DATASIZE);
	T::Transform(buffer, data);
	XorDigest(digest, buffer);

	T::CorrectEndianess(digest, digest, T::DIGESTSIZE);
	bool macValid = (memcmp(mac+4, digest, T::DIGESTSIZE) == 0);
	Init();		// reinit for next use
	return macValid;
}

NAMESPACE_END

#endif
