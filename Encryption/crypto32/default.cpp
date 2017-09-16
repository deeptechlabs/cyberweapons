// default.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "default.h"
#include "cbc.h"
#include "queue.h"
#include <time.h>
#include <memory>

NAMESPACE_BEGIN(CryptoPP)

static const unsigned int MASH_ITERATIONS = 200;
static const unsigned int SALTLENGTH = 8;
static const unsigned int BLOCKSIZE = Default_ECB_Encryption::BLOCKSIZE;
static const unsigned int KEYLENGTH = Default_ECB_Encryption::KEYLENGTH;

// The purpose of this function Mash() is to take an arbitrary length input
// string and *deterministicly* produce an arbitrary length output string such
// that (1) it looks random, (2) no information about the input is
// deducible from it, and (3) it contains as much entropy as it can hold, or
// the amount of entropy in the input string, whichever is smaller.

void Mash(const byte *in, word16 inLen, byte *out, word16 outLen, int iterations)
{
	unsigned int bufSize = (outLen-1+DefaultHashModule::DIGESTSIZE-((outLen-1)%DefaultHashModule::DIGESTSIZE));

	// ASSERT: bufSize == (the smallest multiple of DIGESTSIZE that is >= outLen)

	byte b[2];
	SecByteBlock buf(bufSize);
	SecByteBlock outBuf(bufSize);
	DefaultHashModule hash;

	unsigned int i;
	for(i=0; i<outLen; i+=DefaultHashModule::DIGESTSIZE)
	{
		b[0] = (byte) i >> 8;
		b[1] = (byte) i;
		hash.Update(b, 2);
		hash.Update(in, inLen);
		hash.Final(outBuf+i);
	}

	while (iterations-- > 1)
	{
		memcpy(buf, outBuf, bufSize);
		for (i=0; i<bufSize; i+=DefaultHashModule::DIGESTSIZE)
		{
			b[0] = (byte) i >> 8;
			b[1] = (byte) i;
			hash.Update(b, 2);
			hash.Update(buf, bufSize);
			hash.Final(outBuf+i);
		}
	}

	memcpy(out, outBuf, outLen);
}

static void GenerateKeyIV(const char *passphrase, const byte *salt, unsigned int saltLength, byte *key, byte *IV)
{
	unsigned int passphraseLength = strlen(passphrase);
	SecByteBlock temp(passphraseLength+saltLength);
	memcpy(temp, passphrase, passphraseLength);
	memcpy(temp+passphraseLength, salt, saltLength);
	SecByteBlock keyIV(KEYLENGTH+BLOCKSIZE);
	Mash(temp, passphraseLength + saltLength, keyIV, KEYLENGTH+BLOCKSIZE, MASH_ITERATIONS);
	memcpy(key, keyIV, KEYLENGTH);
	memcpy(IV, keyIV+KEYLENGTH, BLOCKSIZE);
}

// ********************************************************

DefaultEncryptor::DefaultEncryptor(const char *passphrase, BufferedTransformation *outQ)
	: Filter(outQ)
{
	assert(SALTLENGTH <= DefaultHashModule::DIGESTSIZE);
	assert(BLOCKSIZE <= DefaultHashModule::DIGESTSIZE);

	SecByteBlock salt(DefaultHashModule::DIGESTSIZE), keyCheck(DefaultHashModule::DIGESTSIZE);
	DefaultHashModule hash;

	// use hash(passphrase | time | clock) as salt
	hash.Update((byte *)passphrase, strlen(passphrase));
	time_t t=time(0);
	hash.Update((byte *)&t, sizeof(t));
	clock_t c=clock();
	hash.Update((byte *)&c, sizeof(c));
	hash.Final(salt);

	// use hash(passphrase | salt) as key check
	hash.Update((byte *)passphrase, strlen(passphrase));
	hash.Update(salt, SALTLENGTH);
	hash.Final(keyCheck);

	Filter::AttachedTransformation()->Put(salt, SALTLENGTH);

	// mash passphrase and salt together into key and IV
	SecByteBlock key(KEYLENGTH);
	SecByteBlock IV(BLOCKSIZE);
	GenerateKeyIV(passphrase, salt, SALTLENGTH, key, IV);

	m_cipher.reset(new Default_ECB_Encryption(key));
	Insert(new CBCPaddedEncryptor(*m_cipher, IV));

	Filter::AttachedTransformation()->Put(keyCheck, BLOCKSIZE);
}

void DefaultEncryptor::Detach(BufferedTransformation *newOut)
{
	Filter::AttachedTransformation()->Detach(newOut);
}

BufferedTransformation *DefaultEncryptor::AttachedTransformation()
{
	return Filter::AttachedTransformation()->AttachedTransformation();
}

void DefaultEncryptor::Put(byte inByte)
{
	Filter::AttachedTransformation()->Put(inByte);
}

void DefaultEncryptor::Put(const byte *inString, unsigned int length)
{
	Filter::AttachedTransformation()->Put(inString, length);
}

// ********************************************************

DefaultDecryptor::DefaultDecryptor(const char *p, BufferedTransformation *outQ)
	: FilterWithBufferedInput(SALTLENGTH+BLOCKSIZE, 1, 0, outQ)
	, m_state(WAITING_FOR_KEYCHECK)
	, m_passphrase(p, strlen(p)+1)
{
}

void DefaultDecryptor::Detach(BufferedTransformation *newOut)
{
	if (WAITING_FOR_KEYCHECK)
		Detach(newOut);
	else
		Filter::AttachedTransformation()->Detach(newOut);
}

BufferedTransformation *DefaultDecryptor::AttachedTransformation()
{
	if (WAITING_FOR_KEYCHECK)
		return Filter::AttachedTransformation();
	else
		return Filter::AttachedTransformation()->AttachedTransformation();
}

void DefaultDecryptor::FirstPut(const byte *inString)
{
	CheckKey(inString, inString+SALTLENGTH);
}

void DefaultDecryptor::NextPut(const byte *inString, unsigned int length)
{
	Filter::AttachedTransformation()->Put(inString, length);
}

void DefaultDecryptor::LastPut(const byte *inString, unsigned int length)
{
}

void DefaultDecryptor::CheckKey(const byte *salt, const byte *keyCheck)
{
	SecByteBlock check(STDMAX((unsigned int)2*BLOCKSIZE, (unsigned int)DefaultHashModule::DIGESTSIZE));

	DefaultHashModule hash;
	hash.Update((byte *)m_passphrase.ptr, strlen(m_passphrase));
	hash.Update(salt, SALTLENGTH);
	hash.Final(check);

	SecByteBlock key(KEYLENGTH);
	SecByteBlock IV(BLOCKSIZE);
	GenerateKeyIV(m_passphrase, salt, SALTLENGTH, key, IV);

	m_cipher.reset(new Default_ECB_Decryption(key));
	std::auto_ptr<CBCPaddedDecryptor> decryptor(new CBCPaddedDecryptor(*m_cipher, IV));

	decryptor->Put(keyCheck, BLOCKSIZE);
	decryptor->ForceNextPut();
	decryptor->Get(check+BLOCKSIZE, BLOCKSIZE);

	Insert(decryptor.release());

	if (memcmp(check, check+BLOCKSIZE, BLOCKSIZE))
		m_state = KEY_BAD;
	else
		m_state = KEY_GOOD;
}

// ********************************************************

static DefaultMAC * NewDefaultEncryptorMAC(const char *passphrase)
{
	unsigned int macKeyLength = DefaultMAC::KeyLength(16);
	SecByteBlock macKey(macKeyLength);
	// since the MAC is encrypted there is no reason to mash the passphrase for many iterations
	Mash((const byte *)passphrase, strlen(passphrase), macKey, macKeyLength, 1);
	return new DefaultMAC(macKey, macKeyLength);
}

DefaultEncryptorWithMAC::DefaultEncryptorWithMAC(const char *passphrase, BufferedTransformation *outQueue)
	: DefaultEncryptor(passphrase, outQueue), m_mac(NewDefaultEncryptorMAC(passphrase))
{
}

void DefaultEncryptorWithMAC::Put(byte inByte)
{
	m_mac->Update(&inByte, 1);
	DefaultEncryptor::Put(inByte);
}

void DefaultEncryptorWithMAC::Put(const byte *inString, unsigned int length)
{
	m_mac->Update(inString, length);
	DefaultEncryptor::Put(inString, length);
}

void DefaultEncryptorWithMAC::InputFinished()
{
	SecByteBlock macValue(m_mac->DigestSize());
	m_mac->Final(macValue);
	DefaultEncryptor::Put(macValue, macValue.size);
	DefaultEncryptor::InputFinished();
}

// ********************************************************

class DefaultDecryptorMAC_Checker : public FilterWithBufferedInput
{
public:
	DefaultDecryptorMAC_Checker(const char *passphrase, DefaultDecryptorWithMAC::State &state, BufferedTransformation *outQ)
		: FilterWithBufferedInput(0, 1, DefaultMAC::DIGESTSIZE, outQ)
		, m_mac(NewDefaultEncryptorMAC(passphrase)), m_state(state)
	{
	}

	void NextPut(const byte *inString, unsigned int length)
	{
		m_mac->Update(inString, length);
		AttachedTransformation()->Put(inString, length);
	}

	void LastPut(const byte *inString, unsigned int length)
	{
		if (m_state == DefaultDecryptorWithMAC::KEY_GOOD)
		{
			if (length >= m_mac->DigestSize() && m_mac->Verify(inString))
				m_state = DefaultDecryptorWithMAC::MAC_GOOD;
			else
				m_state = DefaultDecryptorWithMAC::MAC_BAD;
		}
	}

	member_ptr<DefaultMAC> m_mac;
	DefaultDecryptorWithMAC::State &m_state;
};

DefaultDecryptorWithMAC::DefaultDecryptorWithMAC(const char *passphrase, BufferedTransformation *outQueue)
	: DefaultDecryptor(passphrase, new DefaultDecryptorMAC_Checker(passphrase, m_state, outQueue))
{
}

void DefaultDecryptorWithMAC::Detach(BufferedTransformation *newOut)
{
	DefaultDecryptor::AttachedTransformation()->Detach(newOut);
}

BufferedTransformation *DefaultDecryptorWithMAC::AttachedTransformation()
{
	return DefaultDecryptor::AttachedTransformation()->AttachedTransformation();
}

NAMESPACE_END
