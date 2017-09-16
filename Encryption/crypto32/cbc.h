#ifndef CRYPTOPP_CBC_H
#define CRYPTOPP_CBC_H

#include "filters.h"
#include "modes.h"

NAMESPACE_BEGIN(CryptoPP)

/// CBC mode encryptor with padding

/** Compatible with RFC 2040.
*/
class CBCPaddedEncryptor : protected CipherMode, public FilterWithBufferedInput
{
public:
	CBCPaddedEncryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

protected:
	void NextPut(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);
};

class CBCPaddedDecryptor : protected CipherMode, public FilterWithBufferedInput
{
public:
	CBCPaddedDecryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

protected:
	void NextPut(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);
};

/// CBC mode encryptor with ciphertext stealing

/** Compatible with RFC 2040.
	Ciphertext stealing requires at least cipher.BlockSize()+1 bytes of plaintext.
	Shorter plaintext will be padded with '\0's.
*/
class CBC_CTS_Encryptor : protected CipherMode, public FilterWithBufferedInput
{
public:
	CBC_CTS_Encryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

protected:
	void FirstPut(const byte *inString);
	void NextPut(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);
};

class CBC_CTS_Decryptor : protected CipherMode, public FilterWithBufferedInput
{
public:
	CBC_CTS_Decryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

protected:
	void NextPut(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);
};

NAMESPACE_END

#endif
