// test.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#include "asn.h"
#include "md2.h"
#include "md5.h"
#include "sha.h"
#include "ripemd.h"
#include "files.h"
#include "validate.h"
#include "rng.h"
#include "secshare.h"
#include "hex.h"
#include "bench.h"
#include "gzip.h"
#include "default.h"
#include "modes.h"
#include "rabin.h"
#include "rsa.h"
#include "randpool.h"

#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <memory>
#include <exception>
#include <list>

#if (_MSC_VER >= 1000)
#include <crtdbg.h>		// for the debug heap
#endif

#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

const int MAX_PHRASE_LENGTH=250;

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed);
char *RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
char *RSADecryptString(const char *privFilename, const char *ciphertext);
void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename);
bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename);

void DigestFile(const char *file);

char *EncryptString(const char *plaintext, const char *passPhrase);
char *DecryptString(const char *ciphertext, const char *passPhrase);

void EncryptFile(const char *in, const char *out, const char *passPhrase);
void DecryptFile(const char *in, const char *out, const char *passPhrase);

void ShareFile(int n, int m, const char *filename);
void AssembleFile(char *outfile, char **infiles, int n);

void GzipFile(const char *in, const char *out, int deflate_level);
void GunzipFile(const char *in, const char *out);

bool Validate(int);

#ifdef __BCPLUSPLUS__
int cmain(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
#ifdef _CRTDBG_LEAK_CHECK_DF
	// Turn on leak-checking
	int tempflag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
	tempflag |= _CRTDBG_LEAK_CHECK_DF;
	_CrtSetDbgFlag( tempflag );
#endif

#if defined(__MWERKS__) && defined(macintosh)
	argc = ccommand(&argv);
#endif

	try
	{
		char command;

		if (argc < 2)
			command = 'h';
		else
			command = argv[1][0];

		switch (command)
		{
		case 'g':
		  {
			char seed[1024], privFilename[128], pubFilename[128];
			unsigned int keyLength;

			cout << "Key length in bits: ";
			cin >> keyLength;

			cout << "\nSave private key to file: ";
			cin >> privFilename;

			cout << "\nSave public key to file: ";
			cin >> pubFilename;

			cout << "\nSeed: ";
			ws(cin);
			cin.getline(seed, 1024);

			GenerateRSAKey(keyLength, privFilename, pubFilename, seed);
			return 0;
		  }
		case 'r':
		  {
			switch (argv[1][1])
			{
			case 's':
				RSASignFile(argv[2], argv[3], argv[4]);
				return 0;
			case 'v':
			  {
				bool verified = RSAVerifyFile(argv[2], argv[3], argv[4]);
				cout << (verified ? "valid signature" : "invalid signature") << endl;
				return 0;
			  }
			default:
			  {
				char privFilename[128], pubFilename[128];
				char seed[1024], message[1024];

				cout << "Private key file: ";
				cin >> privFilename;

				cout << "\nPublic key file: ";
				cin >> pubFilename;

				cout << "\nSeed: ";
				ws(cin);
				cin.getline(seed, 1024);

				cout << "\nMessage: ";
				cin.getline(message, 1024);

				char *ciphertext = RSAEncryptString(pubFilename, seed, message);
				cout << "\nCiphertext: " << ciphertext << endl;

				char *decrypted = RSADecryptString(privFilename, ciphertext);
				cout << "\nDecrypted: " << decrypted << endl;

				delete [] ciphertext;
				return 0;
			  }
			}
		  }
		case 'm':
			DigestFile(argv[2]);
			return 0;
		case 't':
		  {
			char passPhrase[MAX_PHRASE_LENGTH], plaintext[1024];

			cout << "Passphrase: ";
			cin.getline(passPhrase, MAX_PHRASE_LENGTH);

			cout << "\nPlaintext: ";
			cin.getline(plaintext, 1024);

			char *ciphertext = EncryptString(plaintext, passPhrase);
			cout << "\nCiphertext: " << ciphertext << endl;

			char *decrypted = DecryptString(ciphertext, passPhrase);
			cout << "\nDecrypted: " << decrypted << endl;

			delete [] ciphertext;
			delete [] decrypted;
			return 0;
		  }
		case 'e':
		case 'd':
		  {
			char passPhrase[MAX_PHRASE_LENGTH];
			cout << "Passphrase: ";
			cin.getline(passPhrase, MAX_PHRASE_LENGTH);
			if (command == 'e')
				EncryptFile(argv[2], argv[3], passPhrase);
			else
				DecryptFile(argv[2], argv[3], passPhrase);
			return 0;
		  }
		case 's':
			ShareFile(atoi(argv[2]), atoi(argv[3]), argv[4]);
			return 0;
		case 'j':
			AssembleFile(argv[2], argv+3, argc-3);
			return 0;
		case 'v':
			return !Validate(argc>2 ? atoi(argv[2]) : 0);
		case 'b':
			if (argc<3)
				BenchMarkAll();
			else
				BenchMarkAll((float)atof(argv[2]));
			return 0;
		case 'z':
			GzipFile(argv[3], argv[4], argv[2][0]-'0');
			return 0;
		case 'u':
			GunzipFile(argv[2], argv[3]);
			return 0;
		default:
			FileSource usage("usage.dat", true, new FileSink(cout));
			return 1;
		}
	}
	catch(CryptoPP::Exception &e)
	{
		cout << "CryptoPP::Exception caught: " << e.what() << endl;
		return -1;
	}
	catch(std::exception &e)
	{
		cout << "std::exception caught: " << e.what() << endl;
		return -2;
	}
	catch(...)
	{
		cout << "unknown exception caught" << endl;
		return -3;
	}
}

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
	RandomPool randPool;
	randPool.Put((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.Close();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.Close();
}

char *RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	if (strlen(message) > pub.MaxPlainTextLength())
	{
		cerr << "message too long for this key\n";
		abort();
	}

	RandomPool randPool;
	randPool.Put((byte *)seed, strlen(seed));

	char *outstr = new char[2*pub.CipherTextLength()+1];
	pub.Encrypt(randPool, (byte *)message, strlen(message), (byte *)outstr);

	HexEncoder hexEncoder;
	hexEncoder.Put((byte *)outstr, pub.CipherTextLength());
	hexEncoder.Close();
	hexEncoder.Get((byte *)outstr, 2*pub.CipherTextLength());

	outstr[2*pub.CipherTextLength()] = 0;
	return outstr;
}

char *RSADecryptString(const char *privFilename, const char *ciphertext)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	HexDecoder hexDecoder;
	hexDecoder.Put((byte *)ciphertext, strlen(ciphertext));
	hexDecoder.Close();
	SecByteBlock buf(priv.CipherTextLength());
	hexDecoder.Get(buf, priv.CipherTextLength());

	char *outstr = new char[priv.MaxPlainTextLength()+1];
	unsigned messageLength = priv.Decrypt(buf, (byte *)outstr);
	outstr[messageLength] = 0;
	return outstr;
}

void RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSASSA_PKCS1v15_SHA_Signer priv(privFile);
	NullRNG rng;	// RSASSA_PKCS1v15_SHA_Signer ignores the rng. Use a real RNG for other signature schemes!
	FileSource f(messageFilename, true, new SignerFilter(rng, priv, new HexEncoder(new FileSink(signatureFilename))));
}

bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFilename)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASSA_PKCS1v15_SHA_Verifier pub(pubFile);

	FileSource signatureFile(signatureFilename, true, new HexDecoder);
	if (signatureFile.MaxRetrieveable() != pub.SignatureLength())
		return false;
	SecByteBlock signature(pub.SignatureLength());
	signatureFile.Get(signature, signature.size);

	VerifierFilter *verifierFilter = new VerifierFilter(pub);
	verifierFilter->PutSignature(signature);
	FileSource f(messageFilename, true, verifierFilter);

	byte result = 0;
	f.Get(result);
	return result == 1;
}

void DigestFile(const char *filename)
{
	MD5 md5;
	SHA shs;
	RIPEMD160 ripemd;
	BufferedTransformation *outputs[]={new HashFilter(md5), new HashFilter(shs), new HashFilter(ripemd)};
	FileSource file(filename, true, new Fork(3, outputs));

	cout << "MD5:        ";
	outputs[0]->Attach(new HexEncoder(new FileSink(cout)));
	cout << endl;
	cout << "SHA:        ";
	outputs[1]->Attach(new HexEncoder(new FileSink(cout)));
	cout << endl;
	cout << "RIPEMD-160: ";
	outputs[2]->Attach(new HexEncoder(new FileSink(cout)));
	cout << endl;
}

char *EncryptString(const char *instr, const char *passPhrase)
{
	unsigned int len=strlen(instr);
	char* outstr;

	DefaultEncryptorWithMAC encryptor(passPhrase, new HexEncoder());
	encryptor.Put((byte *)instr, len);
	encryptor.Close();

	unsigned int outputLength = encryptor.MaxRetrieveable();
	outstr = new char[outputLength+1];
	encryptor.Get((byte *)outstr, outputLength);
	outstr[outputLength] = 0;
	return outstr;
}

char *DecryptString(const char *instr, const char *passPhrase)
{
	unsigned int len=strlen(instr);
	char* outstr;
	DefaultDecryptorWithMAC *p;

	HexDecoder decryptor(p=new DefaultDecryptorWithMAC(passPhrase));
	decryptor.Put((byte *)instr, len);
	decryptor.Close();
	assert(p->CurrentState() == DefaultDecryptorWithMAC::MAC_GOOD);

	unsigned int outputLength = decryptor.MaxRetrieveable();
	outstr = new char[outputLength+1];
	decryptor.Get((byte *)outstr, outputLength);
	outstr[outputLength] = 0;
	return outstr;
}

void EncryptFile(const char *in, const char *out, const char *passPhrase)
{
	FileSource f(in, true, new DefaultEncryptorWithMAC(passPhrase, new FileSink(out)));
}

void DecryptFile(const char *in, const char *out, const char *passPhrase)
{
	DefaultDecryptorWithMAC *p;
	FileSource file(in, false, p = new DefaultDecryptorWithMAC(passPhrase));
	file.Pump(256);
	if (p->CurrentState() != DefaultDecryptorWithMAC::KEY_GOOD)
	{
		cerr << "Incorrect passphrase.\n";
		return;
	}

	file.Attach(new FileSink(out));
	file.PumpAll();
	file.Close();
	if (p->CurrentState() != DefaultDecryptorWithMAC::MAC_GOOD)
		cerr << "Invalid MAC. The file may have been tempered with.\n";
}

void ShareFile(int n, int m, const char *filename)
{
	assert(n<=100);

	SecByteBlock key(16), IV(16);

	{   // use braces to force file to close
		MD5 md5;
		FileSource file(filename, true, new HashFilter(md5));
		file.Get(key, 16);
	}

	X917RNG rng(new Default_ECB_Encryption(key), key);
	rng.GetBlock(key, 16);
	ShareFork pss(rng, m, n);
	pss.Put(key, 16);
	pss.Close();

	char outname[256];
	strcpy(outname, filename);
	int inFilenameLength = strlen(filename);
	outname[inFilenameLength] = '.';

	BufferedTransformation *outFiles[100];
	for (int i=0; i<n; i++)
	{
		outname[inFilenameLength+1]='0'+byte(i/10);
		outname[inFilenameLength+2]='0'+byte(i%10);
		outname[inFilenameLength+3]='\0';
		outFiles[i] = new FileSink(outname);

		pss.SelectOutPort(i);
		pss.TransferTo(*outFiles[i]);
	}

	MD5 md5;
	md5.CalculateDigest(IV, key, 16);

	Default_ECB_Encryption ecb(key);
	CFBEncryption cipher(ecb, IV);

	FileSource file(filename, true,
					new StreamCipherFilter(cipher, 
					new DisperseFork(m, n, outFiles)));
}

void AssembleFile(char *out, char **filenames, int n)
{
	assert(n<=100);

	auto_ptr<FileSource> inFiles[100];
	ShareJoin pss(n);
	int i;

	for (i=0; i<n; i++)
	{
		inFiles[i] = (auto_ptr<FileSource>&) auto_ptr<FileSource>(new FileSource(filenames[i], false, pss.ReleaseInterface(i)));
		inFiles[i]->Pump(28);
		inFiles[i]->Detach();
	}

	SecByteBlock key(16), IV(16);
	inFiles[n-1]->Get(key, 16);
	Default_ECB_Encryption ecb(key);
	MD5 md5;
	md5.CalculateDigest(IV, key, 16);
	CFBDecryption cfb(ecb, IV);
	DisperseJoin j(n, new StreamCipherFilter(cfb, new FileSink(out)));

	for (i=0; i<n; i++)
		inFiles[i]->Attach(j.ReleaseInterface(i));

	while (inFiles[0]->Pump(256))
		for (i=1; i<n; i++)
			inFiles[i]->Pump(256);

	for (i=0; i<n; i++)
	{
		inFiles[i]->PumpAll();
		inFiles[i]->Close();
	}
}

void GzipFile(const char *in, const char *out, int deflate_level)
{
	FileSource(in, true, new Gzip(deflate_level, new FileSink(out)));
}

void GunzipFile(const char *in, const char *out)
{
	FileSource(in, true, new Gunzip(new FileSink(out)));
}

bool Validate(int alg)
{
	switch (alg)
	{
	case 1: return TestSettings();
	case 3: return MD5Validate();
	case 4: return SHAValidate();
	case 5: return DESValidate();
	case 6: return IDEAValidate();
	case 7: return ARC4Validate();
	case 8: return RC5Validate();
	case 9: return BlowfishValidate();
	case 10: return Diamond2Validate();
	case 11: return ThreeWayValidate();
	case 12: return BBSValidate();
	case 13: return DHValidate();
	case 14: return RSAValidate();
	case 15: return ElGamalValidate();
	case 16: return DSAValidate();
	case 17: return HAVALValidate();
	case 18: return SAFERValidate();
	case 19: return LUCValidate();
	case 20: return RabinValidate();
	case 21: return BlumGoldwasserValidate();
	case 22: return ECPValidate();
	case 23: return EC2NValidate();
	case 24: return MD5MACValidate();
	case 25: return GOSTValidate();
	case 26: return TigerValidate();
	case 27: return RIPEMDValidate();
	case 28: return HMACValidate();
	case 29: return XMACCValidate();
	case 30: return SHARKValidate();
	case 31: return SHARK2Validate();
	case 32: return LUCDIFValidate();
	case 33: return LUCELGValidate();
	case 34: return SEALValidate();
	case 35: return CASTValidate();
	case 36: return SquareValidate();
	case 37: return RC2Validate();
	case 38: return RC6Validate();
	case 39: return MARSValidate();
	case 40: return RWValidate();
	case 41: return MD2Validate();
	case 42: return NRValidate();
	case 43: return MQVValidate();
	case 44: return RijndaelValidate();
	case 45: return TwofishValidate();
	case 46: return SerpentValidate();
	case 47: return CipherModesValidate();
	case 48: return CRC32Validate();
	case 49: return ECDSAValidate();
	default: return ValidateAll();
	}
}
