#ifndef CRYPTOPP_DEFAULT_H
#define CRYPTOPP_DEFAULT_H

#include "sha.h"
#include "hmac.h"
#include "des.h"
#include "filters.h"

NAMESPACE_BEGIN(CryptoPP)

typedef DES_EDE2_Encryption Default_ECB_Encryption;
typedef DES_EDE2_Decryption Default_ECB_Decryption;
typedef SHA DefaultHashModule;
typedef HMAC<DefaultHashModule> DefaultMAC;

class DefaultEncryptor : public Filter
{
public:
	DefaultEncryptor(const char *passphrase, BufferedTransformation *outQueue = NULL);

	void Detach(BufferedTransformation *newOut = NULL);
	BufferedTransformation *AttachedTransformation();

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);

private:
	member_ptr<Default_ECB_Encryption> m_cipher;
};

class DefaultDecryptor : public FilterWithBufferedInput
{
public:
	DefaultDecryptor(const char *passphrase, BufferedTransformation *outQueue = NULL);

	void Detach(BufferedTransformation *newOut = NULL);
	BufferedTransformation *AttachedTransformation();

	// MAC_GOOD and MAC_BAD are not used in this class but are defined for DefaultDecryptorWithMAC
	enum State {WAITING_FOR_KEYCHECK, KEY_GOOD, KEY_BAD, MAC_GOOD, MAC_BAD};
	State CurrentState() const {return m_state;}

protected:
	void FirstPut(const byte *inString);
	void NextPut(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);

	State m_state;

private:
	void CheckKey(const byte *salt, const byte *keyCheck);
	SecBlock<char> m_passphrase;
	member_ptr<Default_ECB_Decryption> m_cipher;
};

class DefaultEncryptorWithMAC : public DefaultEncryptor
{
public:
	DefaultEncryptorWithMAC(const char *passphrase, BufferedTransformation *outQueue = NULL);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	void InputFinished();

private:
	member_ptr<DefaultMAC> m_mac;
};

class DefaultDecryptorWithMAC : public DefaultDecryptor
{
public:
	DefaultDecryptorWithMAC(const char *passphrase, BufferedTransformation *outQueue = NULL);

	void Detach(BufferedTransformation *newOut = NULL);
	BufferedTransformation *AttachedTransformation();
};

NAMESPACE_END

#endif
