#ifndef CRYPTOPP_WAKE_H
#define CRYPTOPP_WAKE_H

#include "cryptlib.h"
#include "misc.h"
#include "filters.h"

NAMESPACE_BEGIN(CryptoPP)

class WAKE
{
protected:
	inline word32 M(word32 x, word32 y);
	inline word32 enc(word32 V);
	inline word32 dec(word32 V);
	void genkey(word32 k0, word32 k1, word32 k2, word32 k3);

	word32 t[257];
	word32 r3, r4, r5, r6;
};

class WAKEEncryption : public Filter, protected WAKE
{
public:
	// key length is 32 bytes
	WAKEEncryption(const byte *key, BufferedTransformation *outQueue = NULL);

	void Put(byte inByte)
	{
		if (inbufSize==INBUFMAX)
			ProcessInbuf();
		inbuf[inbufSize++] = inByte;
	}

	void Put(const byte *inString, unsigned int length);
	void InputFinished();

protected:
	virtual void ProcessInbuf();
	enum {INBUFMAX=256};
	SecByteBlock inbuf;
	unsigned int inbufSize;
};

class WAKEDecryption : public WAKEEncryption
{
public:
	// key length is 32 bytes
	WAKEDecryption(const byte *key, BufferedTransformation *outQueue = NULL)
		: WAKEEncryption(key, outQueue) {lastBlock=false;}

	void InputFinished();

protected:
	virtual void ProcessInbuf();
	bool lastBlock;
};

NAMESPACE_END

#endif
