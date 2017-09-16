// validat1.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#include "files.h"
#include "hex.h"
#include "cbc.h"
#include "cbcmac.h"
#include "dmac.h"
#include "idea.h"
#include "des.h"
#include "rc2.h"
#include "arc4.h"
#include "rc5.h"
#include "blowfish.h"
#include "diamond.h"
#include "wake.h"
#include "3way.h"
#include "safer.h"
#include "gost.h"
#include "shark.h"
#include "cast.h"
#include "square.h"
#include "seal.h"
#include "rc6.h"
#include "mars.h"
#include "rijndael.h"
#include "twofish.h"
#include "serpent.h"
#include "rng.h"

#include <stdlib.h>
#include <memory>
#include <iostream>
#include <iomanip>

#include "validate.h"

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

bool ValidateAll()
{
	bool pass=TestSettings();

	pass=CRC32Validate() && pass;
	pass=MD2Validate() && pass;
	pass=MD5Validate() && pass;
	pass=SHAValidate() && pass;
	pass=HAVALValidate() && pass;
	pass=TigerValidate() && pass;
	pass=RIPEMDValidate() && pass;

	pass=MD5MACValidate() && pass;
	pass=HMACValidate() && pass;
	pass=XMACCValidate() && pass;

	pass=DESValidate() && pass;
	pass=CipherModesValidate() && pass;
	pass=IDEAValidate() && pass;
	pass=SAFERValidate() && pass;
	pass=RC2Validate() && pass;
	pass=ARC4Validate() && pass;
	pass=RC5Validate() && pass;
	pass=BlowfishValidate() && pass;
	pass=Diamond2Validate() && pass;
	pass=ThreeWayValidate() && pass;
	pass=GOSTValidate() && pass;
	pass=SHARKValidate() && pass;
	pass=SHARK2Validate() && pass;
	pass=CASTValidate() && pass;
	pass=SquareValidate() && pass;
	pass=SEALValidate() && pass;
	pass=RC6Validate() && pass;
	pass=MARSValidate() && pass;
	pass=RijndaelValidate() && pass;
	pass=TwofishValidate() && pass;
	pass=SerpentValidate() && pass;

	pass=BBSValidate() && pass;
	pass=DHValidate() && pass;
	pass=MQVValidate() && pass;
	pass=RSAValidate() && pass;
	pass=ElGamalValidate() && pass;
	pass=NRValidate() && pass;
	pass=DSAValidate() && pass;
	pass=LUCValidate() && pass;
	pass=LUCDIFValidate() && pass;
	pass=LUCELGValidate() && pass;
	pass=RabinValidate() && pass;
	pass=RWValidate() && pass;
	pass=BlumGoldwasserValidate() && pass;
	pass=ECPValidate() && pass;
	pass=EC2NValidate() && pass;
	pass=ECDSAValidate() && pass;

	if (pass)
		cout << "\nAll tests passed!\n";
	else
		cout << "\nOops!  Not all tests passed.\n";

	return pass;
}

bool TestSettings()
{
	bool pass = true;

	cout << "\nTesting Settings...\n\n";

	if (*(word32 *)"\x01\x02\x03\x04" == 0x04030201L)
	{
#ifdef IS_LITTLE_ENDIAN
		cout << "passed:  ";
#else
		cout << "FAILED:  ";
		pass = false;
#endif
		cout << "Your machine is little endian.\n";
	}
	else if (*(word32 *)"\x01\x02\x03\x04" == 0x01020304L)
	{
#ifndef IS_LITTLE_ENDIAN
		cout << "passed:  ";
#else
		cout << "FAILED:  ";
		pass = false;
#endif
		cout << "Your machine is big endian.\n";
	}
	else
	{
		cout << "FAILED:  Your machine is neither big endian nor little endian.\n";
		pass = false;
	}

	if (sizeof(byte) == 1)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(byte) == " << sizeof(byte) << endl;

	if (sizeof(word16) == 2)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word16) == " << sizeof(word16) << endl;

	if (sizeof(word32) == 4)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word32) == " << sizeof(word32) << endl;

#ifdef WORD64_AVAILABLE
	if (sizeof(word64) == 8)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word64) == " << sizeof(word64) << endl;
#else
	if (sizeof(dword) >= 8)
	{
		cout << "FAILED:  sizeof(dword) >= 8, but WORD64_AVAILABLE not defined" << endl;
		pass = false;
	}
	else
		cout << "passed:  word64 not available" << endl;
#endif

	if (sizeof(dword) == 2*sizeof(word))
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "sizeof(word) == " << sizeof(word) << ", sizeof(dword) == " << sizeof(dword) << endl;

	dword test = (dword(1)<<WORD_BITS) + 2;
	if (HIGH_WORD(test) == 1 && LOW_WORD(test) == 2)
		cout << "passed:  ";
	else
	{
		cout << "FAILED:  ";
		pass = false;
	}
	cout << "HIGH_WORD() and LOW_WORD() macros\n";

	if (!pass)
	{
		cout << "Some critical setting in config.h is in error.  Please fix it and recompile." << endl;
		abort();
	}
	return pass;
}

// VC50 workaround
typedef auto_ptr<BlockTransformation> apbt;

class CipherFactory
{
public:
	virtual unsigned int BlockSize() const =0;
	virtual unsigned int KeyLength() const =0;

	virtual apbt NewEncryption(const byte *key) const =0;
	virtual apbt NewDecryption(const byte *key) const =0;
};

template <class E, class D> class FixedRoundsCipherFactory : public CipherFactory
{
public:
	FixedRoundsCipherFactory(unsigned int keylen=0) : m_keylen(keylen?keylen:E::KEYLENGTH)
		{assert(E::KeyLength(m_keylen)==m_keylen && D::KeyLength(m_keylen)==m_keylen);}
	unsigned int BlockSize() const {return E::BLOCKSIZE;}
	unsigned int KeyLength() const {return m_keylen;}

	apbt NewEncryption(const byte *key) const
		{return apbt(new E(key, m_keylen));}
	apbt NewDecryption(const byte *key) const
		{return apbt(new D(key, m_keylen));}

	unsigned int m_keylen;
};

template <class E, class D> class VariableRoundsCipherFactory : public CipherFactory
{
public:
	VariableRoundsCipherFactory(unsigned int keylen=0, unsigned int rounds=0) : m_keylen(keylen?keylen:E::KEYLENGTH), m_rounds(rounds?rounds:E::ROUNDS)
		{assert(E::KeyLength(m_keylen)==m_keylen && D::KeyLength(m_keylen)==m_keylen);}
	unsigned int BlockSize() const {return E::BLOCKSIZE;}
	unsigned int KeyLength() const {return m_keylen;}

	apbt NewEncryption(const byte *key) const
		{return apbt(new E(key, m_keylen, m_rounds));}
	apbt NewDecryption(const byte *key) const
		{return apbt(new D(key, m_keylen, m_rounds));}

	unsigned int m_keylen, m_rounds;
};

bool BlockTransformationTest(const CipherFactory &cg, BufferedTransformation &valdata, unsigned int tuples = 0xffff)
{
	HexEncoder output(new FileSink(cout));
	SecByteBlock plain(cg.BlockSize()), cipher(cg.BlockSize()), out(cg.BlockSize()), outplain(cg.BlockSize());
	SecByteBlock key(cg.KeyLength());
	bool pass=true, fail;

	while (valdata.MaxRetrieveable() && tuples--)
	{
		valdata.Get(key, cg.KeyLength());
		valdata.Get(plain, cg.BlockSize());
		valdata.Get(cipher, cg.BlockSize());

		apbt trans = cg.NewEncryption(key);
		trans->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, cg.BlockSize()) != 0;

		trans = (apbt&) cg.NewDecryption(key);
		trans->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, cg.BlockSize());

		pass = pass && !fail;

		cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, cg.KeyLength());
		cout << "   ";
		output.Put(outplain, cg.BlockSize());
		cout << "   ";
		output.Put(out, cg.BlockSize());
		cout << endl;
	}
	return pass;
}

class FilterTester : public Sink
{
public:
	FilterTester(const byte *validOutput, unsigned int outputLen)
		: validOutput(validOutput), outputLen(outputLen), counter(0), fail(false) {}
	void Put(byte inByte)
	{
		if (counter >= outputLen || validOutput[counter] != inByte)
			fail = true;
		counter++;
	}
	void Put(const byte *inString, unsigned int len)
	{
		while (len--)
			Put(*inString++);
	}
	void InputFinished()
	{
		if (counter != outputLen)
			fail = true;
	}
	unsigned int Get(byte &outByte)
	{
		outByte = !fail;
		return 1;
	}

	const byte *validOutput;
	unsigned int outputLen, counter;
	bool fail;
};

bool TestFilter(BufferedTransformation &bt, const byte *in, unsigned int inLen, const byte *out, unsigned int outLen)
{
	bt.Attach(new FilterTester(out, outLen));
	LC_RNG rng(8595);
	while (inLen)
	{
		unsigned int randomLen = rng.GetLong(0, inLen);
		bt.Put(in, randomLen);
		in += randomLen;
		inLen -= randomLen;
	}
	bt.Close();
	byte result = 0;
	bt.Get(result);
	return result == 1;
}

bool DESValidate()
{
	cout << "\nDES validation suite running...\n\n";

	FileSource valdata("descert.dat", true, new HexDecoder);
	bool pass = BlockTransformationTest(FixedRoundsCipherFactory<DESEncryption, DESDecryption>(), valdata);

	cout << "\nTesting EDE2, EDE3, and XEX3 variants...\n\n";

	FileSource valdata1("3desval.dat", true, new HexDecoder);
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE2_Encryption, DES_EDE2_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_EDE3_Encryption, DES_EDE3_Decryption>(), valdata1, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<DES_XEX3_Encryption, DES_XEX3_Decryption>(), valdata1, 1) && pass;

	return pass;
}

bool CipherModesValidate()
{
	cout << "\nTesting DES modes...\n\n";
	const byte key[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	const byte iv[] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
	const byte plain[] = {	// "Now is the time for all " without tailing 0
		0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
		0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
		0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20};
	DESEncryption desE(key);
	DESDecryption desD(key);
	bool pass=true, fail;

	{
		// generated with Crypto++, matches FIPS 81
		// but has extra 8 bytes as result of padding
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, 
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F, 
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6, 
			0x62, 0xC1, 0x6A, 0x27, 0xE4, 0xFC, 0xF2, 0x77};

		CBCPaddedEncryptor cbcE(desE, iv);
		fail = !TestFilter(cbcE, plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with padding" << endl;
		
		CBCPaddedDecryptor cbcD(desD, iv);
		fail = !TestFilter(cbcD, encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with padding" << endl;
	}
	{
		// generated with Crypto++, matches FIPS 81
		// but with last two blocks swapped as result of CTS
		const byte encrypted[] = {
			0xE5, 0xC7, 0xCD, 0xDE, 0x87, 0x2B, 0xF2, 0x7C, 
			0x68, 0x37, 0x88, 0x49, 0x9A, 0x7C, 0x05, 0xF6, 
			0x43, 0xE9, 0x34, 0x00, 0x8C, 0x38, 0x9C, 0x0F};

		CBC_CTS_Encryptor cbcE(desE, iv);
		fail = !TestFilter(cbcE, plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC encryption with ciphertext stealing (CTS)" << endl;
		
		CBC_CTS_Decryptor cbcD(desD, iv);
		fail = !TestFilter(cbcD, encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC decryption with ciphertext stealing (CTS)" << endl;
	}
	{
		const byte encrypted[] = {	// from FIPS 81
			0xF3,0x09,0x62,0x49,0xC7,0xF4,0x6E,0x51,
			0xA6,0x9E,0x83,0x9B,0x1A,0x92,0xF7,0x84,
			0x03,0x46,0x71,0x33,0x89,0x8E,0xA6,0x22};

		CFBEncryption cfbE(desE, iv);
		fail = !TestFilter(StreamCipherFilter(cfbE), plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB encryption" << endl;

		CFBDecryption cfbD(desE, iv);
		fail = !TestFilter(StreamCipherFilter(cfbD), encrypted, sizeof(encrypted), plain, sizeof(plain));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CFB decryption" << endl;
	}
	{
		const byte encrypted[] = {	// from Eric Young's libdes
			0xf3,0x09,0x62,0x49,0xc7,0xf4,0x6e,0x51,
			0x35,0xf2,0x4a,0x24,0x2e,0xeb,0x3d,0x3f,
			0x3d,0x6d,0x5b,0xe3,0x25,0x5a,0xf8,0xc3};

		OFB ofb(desE, iv);
		fail = !TestFilter(StreamCipherFilter(ofb), plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "OFB" << endl;
	}
	{
		const byte encrypted[] = {	// generated with Crypto++
			0xF3, 0x09, 0x62, 0x49, 0xC7, 0xF4, 0x6E, 0x51, 
			0x16, 0x3A, 0x8C, 0xA0, 0xFF, 0xC9, 0x4C, 0x27, 
			0xFA, 0x2F, 0x80, 0xF4, 0x80, 0xB8, 0x6F, 0x75};

		CounterMode cm(desE, iv);
		fail = !TestFilter(StreamCipherFilter(cm), plain, sizeof(plain), encrypted, sizeof(encrypted));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "Counter Mode" << endl;
	}
	{
		const byte plain[] = {	// "7654321 Now is the time for "
			0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20, 
			0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74, 
			0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 
			0x66, 0x6f, 0x72, 0x20};
		const byte mac1[] = {	// from FIPS 113
			0xf1, 0xd3, 0x0f, 0x68, 0x49, 0x31, 0x2c, 0xa4};
		const byte mac2[] = {	// generated with Crypto++
			0x35, 0x80, 0xC5, 0xC4, 0x6B, 0x81, 0x24, 0xE2};

		CBC_MAC<DESEncryption> cbcmac(key);
		fail = !TestFilter(HashFilter(cbcmac), plain, sizeof(plain), mac1, sizeof(mac1));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "CBC MAC" << endl;

		DMAC<DESEncryption> dmac(key);
		fail = !TestFilter(HashFilter(dmac), plain, sizeof(plain), mac2, sizeof(mac2));
		pass = pass && !fail;
		cout << (fail ? "FAILED   " : "passed   ") << "DMAC" << endl;
	}

	return pass;
}

bool IDEAValidate()
{
	cout << "\nIDEA validation suite running...\n\n";

	FileSource valdata("ideaval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<IDEAEncryption, IDEADecryption>(), valdata);
}

bool SAFERValidate()
{
	cout << "\nSAFER validation suite running...\n\n";

	FileSource valdata("saferval.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_K64_Encryption, SAFER_K64_Decryption>(), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_K128_Encryption, SAFER_K128_Decryption>(16,12), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_SK64_Encryption, SAFER_SK64_Decryption>(8,6), valdata, 4) && pass;
	pass = BlockTransformationTest(VariableRoundsCipherFactory<SAFER_SK128_Encryption, SAFER_SK128_Decryption>(), valdata, 4) && pass;
	return pass;
}

bool RC2Validate()
{
	cout << "\nRC2 validation suite running...\n\n";

	FileSource valdata("rc2val.dat", true, new HexDecoder);
	HexEncoder output(new FileSink(cout));
	SecByteBlock plain(RC2Encryption::BLOCKSIZE), cipher(RC2Encryption::BLOCKSIZE), out(RC2Encryption::BLOCKSIZE), outplain(RC2Encryption::BLOCKSIZE);
	SecByteBlock key(128);
	bool pass=true, fail;

	while (valdata.MaxRetrieveable())
	{
		byte keyLen, effectiveLen;

		valdata.Get(keyLen);
		valdata.Get(effectiveLen);
		valdata.Get(key, keyLen);
		valdata.Get(plain, RC2Encryption::BLOCKSIZE);
		valdata.Get(cipher, RC2Encryption::BLOCKSIZE);

		apbt trans(new RC2Encryption(key, keyLen, effectiveLen));
		trans->ProcessBlock(plain, out);
		fail = memcmp(out, cipher, RC2Encryption::BLOCKSIZE) != 0;

		trans = (apbt&) apbt(new RC2Decryption(key, keyLen, effectiveLen));
		trans->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, RC2Encryption::BLOCKSIZE);

		pass = pass && !fail;

		cout << (fail ? "FAILED   " : "passed   ");
		output.Put(key, keyLen);
		cout << "   ";
		output.Put(outplain, RC2Encryption::BLOCKSIZE);
		cout << "   ";
		output.Put(out, RC2Encryption::BLOCKSIZE);
		cout << endl;
	}
	return pass;
}

bool ARC4Validate()
{
	unsigned char Key0[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };
	unsigned char Input0[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	unsigned char Output0[] = {0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96};

	unsigned char Key1[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	unsigned char Input1[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Output1[]={0x74,0x94,0xc2,0xe7,0x10,0x4b,0x08,0x79};

	unsigned char Key2[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Input2[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Output2[]={0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a};

	unsigned char Key3[]={0xef,0x01,0x23,0x45};
	unsigned char Input3[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char Output3[]={0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61};

	unsigned char Key4[]={ 0x01,0x23,0x45,0x67,0x89,0xab, 0xcd,0xef };
	unsigned char Input4[] =
	{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	0x01};
	unsigned char Output4[]= {
	0x75,0x95,0xc3,0xe6,0x11,0x4a,0x09,0x78,0x0c,0x4a,0xd4,
	0x52,0x33,0x8e,0x1f,0xfd,0x9a,0x1b,0xe9,0x49,0x8f,
	0x81,0x3d,0x76,0x53,0x34,0x49,0xb6,0x77,0x8d,0xca,
	0xd8,0xc7,0x8a,0x8d,0x2b,0xa9,0xac,0x66,0x08,0x5d,
	0x0e,0x53,0xd5,0x9c,0x26,0xc2,0xd1,0xc4,0x90,0xc1,
	0xeb,0xbe,0x0c,0xe6,0x6d,0x1b,0x6b,0x1b,0x13,0xb6,
	0xb9,0x19,0xb8,0x47,0xc2,0x5a,0x91,0x44,0x7a,0x95,
	0xe7,0x5e,0x4e,0xf1,0x67,0x79,0xcd,0xe8,0xbf,0x0a,
	0x95,0x85,0x0e,0x32,0xaf,0x96,0x89,0x44,0x4f,0xd3,
	0x77,0x10,0x8f,0x98,0xfd,0xcb,0xd4,0xe7,0x26,0x56,
	0x75,0x00,0x99,0x0b,0xcc,0x7e,0x0c,0xa3,0xc4,0xaa,
	0xa3,0x04,0xa3,0x87,0xd2,0x0f,0x3b,0x8f,0xbb,0xcd,
	0x42,0xa1,0xbd,0x31,0x1d,0x7a,0x43,0x03,0xdd,0xa5,
	0xab,0x07,0x88,0x96,0xae,0x80,0xc1,0x8b,0x0a,0xf6,
	0x6d,0xff,0x31,0x96,0x16,0xeb,0x78,0x4e,0x49,0x5a,
	0xd2,0xce,0x90,0xd7,0xf7,0x72,0xa8,0x17,0x47,0xb6,
	0x5f,0x62,0x09,0x3b,0x1e,0x0d,0xb9,0xe5,0xba,0x53,
	0x2f,0xaf,0xec,0x47,0x50,0x83,0x23,0xe6,0x71,0x32,
	0x7d,0xf9,0x44,0x44,0x32,0xcb,0x73,0x67,0xce,0xc8,
	0x2f,0x5d,0x44,0xc0,0xd0,0x0b,0x67,0xd6,0x50,0xa0,
	0x75,0xcd,0x4b,0x70,0xde,0xdd,0x77,0xeb,0x9b,0x10,
	0x23,0x1b,0x6b,0x5b,0x74,0x13,0x47,0x39,0x6d,0x62,
	0x89,0x74,0x21,0xd4,0x3d,0xf9,0xb4,0x2e,0x44,0x6e,
	0x35,0x8e,0x9c,0x11,0xa9,0xb2,0x18,0x4e,0xcb,0xef,
	0x0c,0xd8,0xe7,0xa8,0x77,0xef,0x96,0x8f,0x13,0x90,
	0xec,0x9b,0x3d,0x35,0xa5,0x58,0x5c,0xb0,0x09,0x29,
	0x0e,0x2f,0xcd,0xe7,0xb5,0xec,0x66,0xd9,0x08,0x4b,
	0xe4,0x40,0x55,0xa6,0x19,0xd9,0xdd,0x7f,0xc3,0x16,
	0x6f,0x94,0x87,0xf7,0xcb,0x27,0x29,0x12,0x42,0x64,
	0x45,0x99,0x85,0x14,0xc1,0x5d,0x53,0xa1,0x8c,0x86,
	0x4c,0xe3,0xa2,0xb7,0x55,0x57,0x93,0x98,0x81,0x26,
	0x52,0x0e,0xac,0xf2,0xe3,0x06,0x6e,0x23,0x0c,0x91,
	0xbe,0xe4,0xdd,0x53,0x04,0xf5,0xfd,0x04,0x05,0xb3,
	0x5b,0xd9,0x9c,0x73,0x13,0x5d,0x3d,0x9b,0xc3,0x35,
	0xee,0x04,0x9e,0xf6,0x9b,0x38,0x67,0xbf,0x2d,0x7b,
	0xd1,0xea,0xa5,0x95,0xd8,0xbf,0xc0,0x06,0x6f,0xf8,
	0xd3,0x15,0x09,0xeb,0x0c,0x6c,0xaa,0x00,0x6c,0x80,
	0x7a,0x62,0x3e,0xf8,0x4c,0x3d,0x33,0xc1,0x95,0xd2,
	0x3e,0xe3,0x20,0xc4,0x0d,0xe0,0x55,0x81,0x57,0xc8,
	0x22,0xd4,0xb8,0xc5,0x69,0xd8,0x49,0xae,0xd5,0x9d,
	0x4e,0x0f,0xd7,0xf3,0x79,0x58,0x6b,0x4b,0x7f,0xf6,
	0x84,0xed,0x6a,0x18,0x9f,0x74,0x86,0xd4,0x9b,0x9c,
	0x4b,0xad,0x9b,0xa2,0x4b,0x96,0xab,0xf9,0x24,0x37,
	0x2c,0x8a,0x8f,0xff,0xb1,0x0d,0x55,0x35,0x49,0x00,
	0xa7,0x7a,0x3d,0xb5,0xf2,0x05,0xe1,0xb9,0x9f,0xcd,
	0x86,0x60,0x86,0x3a,0x15,0x9a,0xd4,0xab,0xe4,0x0f,
	0xa4,0x89,0x34,0x16,0x3d,0xdd,0xe5,0x42,0xa6,0x58,
	0x55,0x40,0xfd,0x68,0x3c,0xbf,0xd8,0xc0,0x0f,0x12,
	0x12,0x9a,0x28,0x4d,0xea,0xcc,0x4c,0xde,0xfe,0x58,
	0xbe,0x71,0x37,0x54,0x1c,0x04,0x71,0x26,0xc8,0xd4,
	0x9e,0x27,0x55,0xab,0x18,0x1a,0xb7,0xe9,0x40,0xb0,
	0xc0};

	// VC60 workaround: auto_ptr lacks reset()
	member_ptr<ARC4> arc4;
	bool pass=true, fail;
	int i;

	cout << "\nARC4 validation suite running...\n\n";

	arc4.reset(new ARC4(Key0, sizeof(Key0)));
	arc4->ProcessString(Input0, sizeof(Input0));
	fail = memcmp(Input0, Output0, sizeof(Input0)) != 0;
	cout << (fail ? "FAILED" : "passed") << "    Test 0" << endl;
	pass = pass && !fail;

	arc4.reset(new ARC4(Key1, sizeof(Key1)));
	arc4->ProcessString(Key1, Input1, sizeof(Key1));
	fail = memcmp(Output1, Key1, sizeof(Key1)) != 0;
	cout << (fail ? "FAILED" : "passed") << "    Test 1" << endl;
	pass = pass && !fail;

	arc4.reset(new ARC4(Key2, sizeof(Key2)));
	for (i=0, fail=false; i<sizeof(Input2); i++)
		if (arc4->ProcessByte(Input2[i]) != Output2[i])
			fail = true;
	cout << (fail ? "FAILED" : "passed") << "    Test 2" << endl;
	pass = pass && !fail;

	arc4.reset(new ARC4(Key3, sizeof(Key3)));
	for (i=0, fail=false; i<sizeof(Input3); i++)
		if (arc4->ProcessByte(Input3[i]) != Output3[i])
			fail = true;
	cout << (fail ? "FAILED" : "passed") << "    Test 3" << endl;
	pass = pass && !fail;

	arc4.reset(new ARC4(Key4, sizeof(Key4)));
	for (i=0, fail=false; i<sizeof(Input4); i++)
		if (arc4->ProcessByte(Input4[i]) != Output4[i])
			fail = true;
	cout << (fail ? "FAILED" : "passed") << "    Test 4" << endl;
	pass = pass && !fail;

	return pass;
}

bool RC5Validate()
{
	cout << "\nRC5 validation suite running...\n\n";

	FileSource valdata("rc5val.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<RC5Encryption, RC5Decryption>(), valdata);
}

bool RC6Validate()
{
	cout << "\nRC6 validation suite running...\n\n";

	FileSource valdata("rc6val.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(16), valdata, 2) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(24), valdata, 2) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<RC6Encryption, RC6Decryption>(32), valdata, 2) && pass;
	return pass;
}

bool MARSValidate()
{
	cout << "\nMARS validation suite running...\n\n";

	FileSource valdata("marsval.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(16), valdata, 4) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(24), valdata, 3) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<MARSEncryption, MARSDecryption>(32), valdata, 2) && pass;
	return pass;
}

bool RijndaelValidate()
{
	cout << "\nRijndael validation suite running...\n\n";

	FileSource valdata("rijndael.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(16), valdata, 4) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(24), valdata, 3) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<RijndaelEncryption, RijndaelDecryption>(32), valdata, 2) && pass;
	return pass;
}

bool TwofishValidate()
{
	cout << "\nTwofish validation suite running...\n\n";

	FileSource valdata("twofishv.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(16), valdata, 4) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(24), valdata, 3) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<TwofishEncryption, TwofishDecryption>(32), valdata, 2) && pass;
	return pass;
}

bool SerpentValidate()
{
	cout << "\nSerpent validation suite running...\n\n";

	FileSource valdata("serpentv.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(16), valdata, 4) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(24), valdata, 3) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<SerpentEncryption, SerpentDecryption>(32), valdata, 2) && pass;
	return pass;
}

bool BlowfishValidate()
{
	cout << "\nBlowfish validation suite running...\n\n";

	HexEncoder output(new FileSink(cout));
	char *key[]={"abcdefghijklmnopqrstuvwxyz", "Who is John Galt?"};
	byte *plain[]={(byte *)"BLOWFISH", (byte *)"\xfe\xdc\xba\x98\x76\x54\x32\x10"};
	byte *cipher[]={(byte *)"\x32\x4e\xd0\xfe\xf4\x13\xa2\x03", (byte *)"\xcc\x91\x73\x2b\x80\x22\xf6\x84"};
	byte out[8], outplain[8];
	bool pass=true, fail;

	for (int i=0; i<2; i++)
	{
		BlowfishEncryption enc((byte *)key[i], strlen(key[i]));
		enc.ProcessBlock(plain[i], out);
		fail = memcmp(out, cipher[i], 8) != 0;

		BlowfishDecryption dec((byte *)key[i], strlen(key[i]));
		dec.ProcessBlock(cipher[i], outplain);
		fail = fail || memcmp(outplain, plain[i], 8);
		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		cout << '\"' << key[i] << '\"';
		for (int j=0; j<(signed int)(30-strlen(key[i])); j++)
			cout << ' ';
		output.Put(outplain, 8);
		cout << "  ";
		output.Put(out, 8);
		cout << endl;
	}
	return pass;
}

bool Diamond2Validate()
{
	cout << "\nDiamond2 validation suite running...\n\n";

	FileSource valdata("diamond.dat", true, new HexDecoder);
	HexEncoder output(new FileSink(cout));
	byte key[32], plain[16], cipher[16], out[16], outplain[16];
	byte blocksize, rounds, keysize;
	bool pass=true, fail;
	apbt diamond;

	while (valdata.MaxRetrieveable() >= 1)
	{
		valdata.Get(blocksize);
		valdata.Get(rounds);
		valdata.Get(keysize);
		valdata.Get(key, keysize);
		valdata.Get(plain, blocksize);
		valdata.Get(cipher, blocksize);

		if (blocksize==16)
			diamond = (apbt&) apbt(new Diamond2Encryption(key, keysize, rounds));
		else
			diamond = (apbt&) apbt(new Diamond2LiteEncryption(key, keysize, rounds));

		diamond->ProcessBlock(plain, out);
		fail=memcmp(out, cipher, blocksize) != 0;

		if (blocksize==16)
			diamond = (apbt&) apbt(new Diamond2Decryption(key, keysize, rounds));
		else
			diamond = (apbt&) apbt(new Diamond2LiteDecryption(key, keysize, rounds));

		diamond->ProcessBlock(out, outplain);
		fail=fail || memcmp(outplain, plain, blocksize);

		pass = pass && !fail;

		cout << (fail ? "FAILED    " : "passed    ");
		output.Put(key, keysize);
		cout << "\n          ";
		output.Put(outplain, blocksize);
		cout << "  ";
		output.Put(out, blocksize);
		cout << endl;
	}
	return pass;
}

bool ThreeWayValidate()
{
	cout << "\n3-WAY validation suite running...\n\n";

	FileSource valdata("3wayval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<ThreeWayEncryption, ThreeWayDecryption>(), valdata);
}

bool GOSTValidate()
{
	cout << "\nGOST validation suite running...\n\n";

	FileSource valdata("gostval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<GOSTEncryption, GOSTDecryption>(), valdata);
}

bool SHARKValidate()
{
	cout << "\nSHARK validation suite running...\n\n";

#ifdef WORD64_AVAILABLE
	FileSource valdata("sharkval.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SHARKEncryption, SHARKDecryption>(), valdata);
#else
	cout << "word64 not available, skipping SHARK validation." << endl;
	return true;
#endif
}

bool SHARK2Validate()
{
	return true;	// SHARK2 is not yet available

#if 0
	cout << "\nSHARK2 validation suite running...\n\n";

#ifdef WORD64_AVAILABLE
	FileSource valdata("shark2va.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SHARK2Encryption, SHARK2Decryption>(), valdata);
#else
	cout << "word64 not available, skipping SHARK2 validation." << endl;
	return true;
#endif
#endif
}

bool CASTValidate()
{
	cout << "\nCAST-128 validation suite running...\n\n";

	FileSource valdata("castval.dat", true, new HexDecoder);
	bool pass = true;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(16), valdata, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(10), valdata, 1) && pass;
	pass = BlockTransformationTest(FixedRoundsCipherFactory<CAST128Encryption, CAST128Decryption>(5), valdata, 1) && pass;
	return pass;
}

bool SquareValidate()
{
	cout << "\nSquare validation suite running...\n\n";

	FileSource valdata("squareva.dat", true, new HexDecoder);
	return BlockTransformationTest(FixedRoundsCipherFactory<SquareEncryption, SquareDecryption>(), valdata);
}

bool SEALValidate()
{
	byte input[] = {0x37,0xa0,0x05,0x95,0x9b,0x84,0xc4,0x9c,0xa4,0xbe,0x1e,0x05,0x06,0x73,0x53,0x0f,0x5f,0xb0,0x97,0xfd,0xf6,0xa1,0x3f,0xbd,0x6c,0x2c,0xde,0xcd,0x81,0xfd,0xee,0x7c};
	byte output[32];
	byte key[]={0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0};
	word32 start = 0x013577af;

	cout << "\nSEAL validation suite running...\n\n";

	SEAL seal(key, start);
	unsigned int size = sizeof(input);
	bool pass = true;

	memset(output, 1, size);
	seal.ProcessString(output, input, size);
	for (unsigned int i=0; i<size; i++)
		if (output[i] != 0)
			pass = false;

	seal.Seek(0);
	output[0] = seal.ProcessByte(output[0]);
	seal.ProcessString(output+1, size-1);
	pass = pass && memcmp(output, input, size) == 0;

	cout << (pass ? "passed" : "FAILED") << endl;
	return pass;
}
