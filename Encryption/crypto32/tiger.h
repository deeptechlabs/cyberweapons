#ifndef CRYPTOPP_TIGER_H
#define CRYPTOPP_TIGER_H

#include "config.h"

#ifdef WORD64_AVAILABLE

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

class Tiger : public IteratedHash<word64>
{
public:
	enum {DIGESTSIZE = 24, DATASIZE = 64};

	// digestSize can be 16, 20, or 24
	Tiger(unsigned int digestSize=DIGESTSIZE);
	void Final(byte *hash);
	unsigned int DigestSize() const {return digestSize;}

	static void CorrectEndianess(word64 *out, const word64 *in, unsigned int byteCount)
	{
#ifndef IS_LITTLE_ENDIAN
		byteReverse(out, in, byteCount);
#else
		if (in!=out)
			memcpy(out, in, byteCount);
#endif
	}

	static void Transform (word64 *buf, const word64 *in);

private:
	void Init();
	void HashBlock(const word64 *input);

	static const word64 table[4*256];
	const unsigned int digestSize;
};

NAMESPACE_END

#endif
#endif
