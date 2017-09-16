#ifndef CRYPTOPP_MD5MAC_H
#define CRYPTOPP_MD5MAC_H

#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

class MD5MAC : public IteratedHash<word32>, public MessageAuthenticationCode
{
public:
	MD5MAC(const byte *userKey);
	void Final(byte *mac);
	unsigned int DigestSize() const {return DIGESTSIZE;}

	enum {KEYLENGTH=16, DIGESTSIZE = 16, DATASIZE = 64};

private:
	void Init();
	void HashBlock(const word32 *input);
	static void CorrectEndianess(word32 *out, const word32 *in, unsigned int byteCount);
	static void Transform (word32 *buf, const word32 *in, const word32 *key);

	static const word32 T[12];
	SecBlock<word32> key;
};

NAMESPACE_END

#endif
