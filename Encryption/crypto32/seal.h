#ifndef CRYPTOPP_SEAL_H
#define CRYPTOPP_SEAL_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class SEAL : public RandomNumberGenerator,
			 public RandomAccessStreamCipher
{
public:
	// If you plan to encrypt more than one message with a key,
	// you must call NextCount() after each message, save the count,
	// and initialize SEAL with it for the next message.
	SEAL(const byte *key, word32 counter = 0, unsigned int L = 32*1024);

	word32 NextCount() const {return counter+1;}

	byte GetByte();
	byte ProcessByte(byte input)
		{return (input ^ SEAL::GetByte());}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length)
		{SEAL::ProcessString(inoutString, inoutString, length);}

	void Seek(unsigned long position);

	enum {KEYLENGTH=20};

protected:
	void Generate(word32 in, byte *out) const;
	void IncrementCounter();

private:
	const unsigned int L;
	SecBlock<word32> R, S, T;

	const word32 startCount;
	word32 counter;
	unsigned int position;
	SecByteBlock buffer;
};

NAMESPACE_END

#endif
