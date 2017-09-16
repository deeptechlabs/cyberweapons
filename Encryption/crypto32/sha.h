#ifndef CRYPTOPP_SHA_H
#define CRYPTOPP_SHA_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

/// implements the SHA-1 standard
class SHA : public IteratedHash<word32>
{
public:
	SHA();
	void Final(byte *hash);
	unsigned int DigestSize() const {return DIGESTSIZE;};

	static void CorrectEndianess(word32 *out, const word32 *in, unsigned int byteCount)
	{
#ifdef IS_LITTLE_ENDIAN
		byteReverse(out, in, byteCount);
#else
		if (in!=out)
			memcpy(out, in, byteCount);
#endif
	}

	static void Transform(word32 *digest, const word32 *data );

	enum {DIGESTSIZE = 20, DATASIZE = 64};

private:
	void Init();
	void HashBlock(const word32 *input);
};

NAMESPACE_END

#endif
