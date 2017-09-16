// bench.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#include "crc.h"
#include "md2.h"
#include "md5.h"
#include "md5mac.h"
#include "sha.h"
#include "haval.h"
#include "tiger.h"
#include "ripemd.h"
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
#include "hmac.h"
#include "xormac.h"
#include "cbcmac.h"
#include "dmac.h"
#include "blumshub.h"
#include "rsa.h"
#include "elgamal.h"
#include "nr.h"
#include "dsa.h"
#include "luc.h"
#include "rabin.h"
#include "rw.h"
#include "blumgold.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "asn.h"
#include "rng.h"
#include "files.h"
#include "hex.h"
#include "modes.h"
#include "mdc.h"
#include "lubyrack.h"
#include "sapphire.h"
#include "tea.h"
#include "dh.h"
#include "mqv.h"

#include "bench.h"

#include <time.h>
#include <math.h>
#include <iostream>
#include <iomanip>

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

#ifdef CLOCKS_PER_SEC
static const float CLOCK_TICKS_PER_SECOND = (float)CLOCKS_PER_SEC;
#elif defined(CLK_TCK)
static const float CLOCK_TICKS_PER_SECOND = (float)CLK_TCK;
#else
static const float CLOCK_TICKS_PER_SECOND = 1000000.0;
#endif

static const byte *const key=(byte *)"0123456789abcdef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

static double logtotal = 0;
static unsigned int logcount = 0;

void BenchMark(const char *name, BlockTransformation &cipher, float timeTotal)
{
	const int BUF_SIZE = cipher.BlockSize();
	SecByteBlock buf(BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, length=BUF_SIZE;
	float timeTaken;
	do
	{
		length *= 2;
		for (; i<length; i+=BUF_SIZE)
			cipher.ProcessBlock(buf);
		timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	float kbs = length / timeTaken;
	cout << "<TR><TH>" << name;
	cout << "<TD>" << length;
	cout << "<TD>" << timeTaken;
	cout << "<TD>" << (long)kbs << endl;

	logtotal += log(kbs);
	logcount++;
}

void BenchMark(const char *name, StreamCipher &cipher, float timeTotal)
{
	const int BUF_SIZE=128; // encrypt 128 bytes at a time
	SecByteBlock buf(BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, length=BUF_SIZE;
	float timeTaken;
	do
	{
		length *= 2;
		for (; i<length; i+=BUF_SIZE)
			cipher.ProcessString(buf, BUF_SIZE);
		timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	float kbs = length / timeTaken;
	cout << "<TR><TH>" << name;
	cout << "<TD>" << length;
	cout << "<TD>" << timeTaken;
	cout << "<TD>" << (long)kbs << endl;

	logtotal += log(kbs);
	logcount++;
}

void BenchMark(const char *name, HashModule &hash, float timeTotal)
{
	const int BUF_SIZE=128; // update 128 bytes at a time
	SecByteBlock buf(BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, length=BUF_SIZE;
	float timeTaken;
	do
	{
		length *= 2;
		for (; i<length; i+=BUF_SIZE)
			hash.Update(buf, BUF_SIZE);
		timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	float kbs = length / timeTaken;
	cout << "<TR><TH>" << name;
	cout << "<TD>" << length;
	cout << "<TD>" << timeTaken;
	cout << "<TD>" << (long)kbs << endl;

	logtotal += log(kbs);
	logcount++;
}

void BenchMark(const char *name, BufferedTransformation &bt, float timeTotal)
{
	const int BUF_SIZE=128; // update 128 bytes at a time
	SecByteBlock buf(BUF_SIZE);
	clock_t start = clock();

	unsigned long i=0, length=BUF_SIZE;
	float timeTaken;
	do
	{
		length *= 2;
		for (; i<length; i+=BUF_SIZE)
			bt.Put(buf, BUF_SIZE);
		timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND;
	}
	while (timeTaken < 2.0/3*timeTotal);

	float kbs = length / timeTaken;
	cout << "<TR><TH>" << name;
	cout << "<TD>" << length;
	cout << "<TD>" << timeTaken;
	cout << "<TD>" << (long)kbs << endl;

	logtotal += log(kbs);
	logcount++;
}

void BenchMarkEncryption(const char *name, PK_Encryptor &key, float timeTotal, bool pc=false)
{
	unsigned int len = 16;
	LC_RNG rng(time(NULL));
	SecByteBlock plaintext(len), ciphertext(key.CipherTextLength(len));
	rng.GetBlock(plaintext, len);

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		key.Encrypt(rng, plaintext, len, ciphertext);

	cout << "<TR><TH>" << name << " Encryption" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkEncryption(const char *name, PK_WithPrecomputation<PK_FixedLengthEncryptor> &key, float timeTotal)
{
	BenchMarkEncryption(name, dynamic_cast<PK_Encryptor &>(key), timeTotal);
	key.Precompute(16);
	BenchMarkEncryption(name, dynamic_cast<PK_Encryptor &>(key), timeTotal, true);
}

void BenchMarkDecryption(const char *name, PK_Decryptor &priv, PK_Encryptor &pub, float timeTotal)
{
	unsigned int len = 16;
	LC_RNG rng(time(NULL));
	SecByteBlock ciphertext(pub.CipherTextLength(len));
	SecByteBlock plaintext(pub.MaxPlainTextLength(ciphertext.size));
	rng.GetBlock(plaintext, len);
	pub.Encrypt(rng, plaintext, len, ciphertext);

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		priv.Decrypt(ciphertext, ciphertext.size, plaintext);

	cout << "<TR><TH>" << name << " Decryption";
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkSigning(const char *name, PK_Signer &key, float timeTotal, bool pc=false)
{
	unsigned int len = 16;
	LC_RNG rng(time(NULL));
	SecByteBlock message(len), signature(key.SignatureLength());
	rng.GetBlock(message, len);

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		key.SignMessage(rng, message, len, signature);

	cout << "<TR><TH>" << name << " Signature" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkSigning(const char *name, PK_WithPrecomputation<PK_Signer> &key, float timeTotal)
{
	BenchMarkSigning(name, dynamic_cast<PK_Signer &>(key), timeTotal);
	key.Precompute(16);
	BenchMarkSigning(name, dynamic_cast<PK_Signer &>(key), timeTotal, true);
}

void BenchMarkVerification(const char *name, PK_Signer &priv, PK_Verifier &pub, float timeTotal, bool pc=false)
{
	unsigned int len = 16;
	LC_RNG rng(time(NULL));
	SecByteBlock message(len), signature(pub.SignatureLength());
	rng.GetBlock(message, len);
	priv.SignMessage(rng, message, len, signature);

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		pub.VerifyMessage(message, len, signature);

	cout << "<TR><TH>" << name << " Verification" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkVerification(const char *name, PK_Signer &priv, PK_WithPrecomputation<PK_Verifier> &pub, float timeTotal)
{
	BenchMarkVerification(name, priv, dynamic_cast<PK_Verifier &>(pub), timeTotal);
	pub.Precompute(16);
	BenchMarkVerification(name, priv, dynamic_cast<PK_Verifier &>(pub), timeTotal, true);
}

void BenchMarkKeyGen(const char *name, PK_SimpleKeyAgreementDomain &d, float timeTotal, bool pc=false)
{
	LC_RNG rng(time(NULL));
	SecByteBlock priv(d.PrivateKeyLength()), pub(d.PublicKeyLength());

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		d.GenerateKeyPair(rng, priv, pub);

	cout << "<TR><TH>" << name << " Key-Pair Generation" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkKeyGen(const char *name, PK_WithPrecomputation<PK_SimpleKeyAgreementDomain> &d, float timeTotal)
{
	BenchMarkKeyGen(name, dynamic_cast<PK_SimpleKeyAgreementDomain &>(d), timeTotal);
	d.Precompute(16);
	BenchMarkKeyGen(name, dynamic_cast<PK_SimpleKeyAgreementDomain &>(d), timeTotal, true);
}

void BenchMarkKeyGen(const char *name, PK_AuthenticatedKeyAgreementDomain &d, float timeTotal, bool pc=false)
{
	LC_RNG rng(time(NULL));
	SecByteBlock priv(d.EphemeralPrivateKeyLength()), pub(d.EphemeralPublicKeyLength());

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i++)
		d.GenerateEphemeralKeyPair(rng, priv, pub);

	cout << "<TR><TH>" << name << " Key-Pair Generation" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkKeyGen(const char *name, PK_WithPrecomputation<PK_AuthenticatedKeyAgreementDomain> &d, float timeTotal)
{
	BenchMarkKeyGen(name, dynamic_cast<PK_AuthenticatedKeyAgreementDomain &>(d), timeTotal);
	d.Precompute(16);
	BenchMarkKeyGen(name, dynamic_cast<PK_AuthenticatedKeyAgreementDomain &>(d), timeTotal, true);
}

void BenchMarkAgreement(const char *name, PK_SimpleKeyAgreementDomain &d, float timeTotal, bool pc=false)
{
	LC_RNG rng(time(NULL));
	SecByteBlock priv1(d.PrivateKeyLength()), priv2(d.PrivateKeyLength());
	SecByteBlock pub1(d.PublicKeyLength()), pub2(d.PublicKeyLength());
	d.GenerateKeyPair(rng, priv1, pub1);
	d.GenerateKeyPair(rng, priv2, pub2);
	SecByteBlock val(d.AgreedValueLength());

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i+=2)
	{
		d.Agree(val, priv1, pub2);
		d.Agree(val, priv2, pub1);
	}

	cout << "<TR><TH>" << name << " Agreement" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

void BenchMarkAgreement(const char *name, PK_AuthenticatedKeyAgreementDomain &d, float timeTotal, bool pc=false)
{
	LC_RNG rng(time(NULL));
	SecByteBlock spriv1(d.StaticPrivateKeyLength()), spriv2(d.StaticPrivateKeyLength());
	SecByteBlock epriv1(d.EphemeralPrivateKeyLength()), epriv2(d.EphemeralPrivateKeyLength());
	SecByteBlock spub1(d.StaticPublicKeyLength()), spub2(d.StaticPublicKeyLength());
	SecByteBlock epub1(d.EphemeralPublicKeyLength()), epub2(d.EphemeralPublicKeyLength());
	d.GenerateStaticKeyPair(rng, spriv1, spub1);
	d.GenerateStaticKeyPair(rng, spriv2, spub2);
	d.GenerateEphemeralKeyPair(rng, epriv1, epub1);
	d.GenerateEphemeralKeyPair(rng, epriv2, epub2);
	SecByteBlock val(d.AgreedValueLength());

	clock_t start = clock();
	unsigned int i;
	float timeTaken;
	for (timeTaken=(float)0, i=0; timeTaken < timeTotal; timeTaken = float(clock() - start) / CLOCK_TICKS_PER_SECOND, i+=2)
	{
		d.Agree(val, spriv1, epriv1, spub2, epub2);
		d.Agree(val, spriv2, epriv2, spub1, epub1);
	}

	cout << "<TR><TH>" << name << " Key Agreement" << (pc ? " with precomputation" : "");
	cout << "<TD>" << i;
	cout << "<TD>" << setprecision(3) << timeTaken;
	cout << "<TD>" << (unsigned int)(1000*timeTaken/i) << endl;

	logtotal += log(i/timeTaken);
	logcount++;
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyed(const char *name, float timeTotal, T *x=NULL)
{
	T c(key);
	BenchMark(name, c, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class T>
void BenchMarkKeyless(const char *name, float timeTotal, T *x=NULL)
{
	T c;
	BenchMark(name, c, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class D, class E>
void BenchMarkCrypto(const char *filename, const char *name, float timeTotal, D *x=NULL, E *y=NULL)
{
	FileSource f(filename, true, new HexDecoder());
	D priv(f);
	E pub(priv);
	BenchMarkEncryption(name, pub, timeTotal);
	BenchMarkDecryption(name, priv, pub, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class S, class V>
void BenchMarkSignature(const char *filename, const char *name, float timeTotal, S *x=NULL, V *y=NULL)
{
	FileSource f(filename, true, new HexDecoder());
	S priv(f);
	V pub(priv);
	BenchMarkSigning(name, priv, timeTotal);
	BenchMarkVerification(name, priv, pub, timeTotal);
}

//VC60 workaround: compiler bug triggered without the extra dummy parameters
template <class D>
void BenchMarkKeyAgreement(const char *filename, const char *name, float timeTotal, D *x=NULL)
{
	FileSource f(filename, true, new HexDecoder());
	D d(f);
	BenchMarkKeyGen(name, d, timeTotal);
	BenchMarkAgreement(name, d, timeTotal);
}

void BenchMarkAll(float t)
{
	logtotal = 0;
	logcount = 0;

	cout << "<TABLE border=1><COLGROUP><COL align=left><COL align=right><COL align=right><COL align=right>" << endl;
	cout << "<THEAD><TR><TH>Cipher<TH>Total Bytes<TH>Time<TH>Bytes/Second\n<TBODY>" << endl;

	BenchMarkKeyless<CRC32>("CRC-32", t);
	BenchMarkKeyless<MD2>("MD2", t);
	BenchMarkKeyless<MD5>("MD5", t);
	BenchMarkKeyless<SHA>("SHA-1", t);
	BenchMarkKeyless<HAVAL3>("HAVAL (pass=3)", t);
	BenchMarkKeyless<HAVAL4>("HAVAL (pass=4)", t);
	BenchMarkKeyless<HAVAL5>("HAVAL (pass=5)", t);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyless<Tiger>("Tiger", t);
#endif
	BenchMarkKeyless<RIPEMD160>("RIPE-MD160", t);
	BenchMarkKeyed<MDC<MD5> >("MDC/MD5", t);
	BenchMarkKeyed<LREncryption<MD5> >("Luby-Rackoff/MD5", t);
	BenchMarkKeyed<DESEncryption>("DES", t);
	BenchMarkKeyed<DES_XEX3_Encryption>("DES-XEX3", t);
	BenchMarkKeyed<DES_EDE3_Encryption>("DES-EDE3", t);
	BenchMarkKeyed<IDEAEncryption>("IDEA", t);
	BenchMarkKeyed<RC2Encryption>("RC2", t);
	BenchMarkKeyed<RC5Encryption>("RC5 (r=12)", t);
	BenchMarkKeyed<BlowfishEncryption>("Blowfish", t);
	BenchMarkKeyed<Diamond2Encryption>("Diamond2", t);
	BenchMarkKeyed<Diamond2LiteEncryption>("Diamond2 Lite", t);
	BenchMarkKeyed<ThreeWayDecryption>("3-WAY", t);
	BenchMarkKeyed<TEAEncryption>("TEA", t);
	BenchMarkKeyed<SAFER_SK64_Encryption>("SAFER (r=8)", t);
	BenchMarkKeyed<GOSTEncryption>("GOST", t);
#ifdef WORD64_AVAILABLE
	BenchMarkKeyed<SHARKEncryption>("SHARK (r=6)", t);
#endif
	BenchMarkKeyed<CAST128Encryption>("CAST-128", t);
	BenchMarkKeyed<SquareEncryption>("Square", t);
	BenchMarkKeyed<RC6Encryption>("RC6", t);
	BenchMarkKeyed<MARSEncryption>("MARS", t);
	BenchMarkKeyed<RijndaelEncryption>("Rijndael", t);
	BenchMarkKeyed<TwofishEncryption>("Twofish", t);
	BenchMarkKeyed<SerpentEncryption>("Serpent", t);
	BenchMarkKeyed<ARC4>("ARC4", t);
	BenchMarkKeyed<SEAL>("SEAL", t);
	{
		WAKEEncryption c(key, new BitBucket);
		BenchMark("WAKE", c, t);
	}
	BenchMarkKeyed<SapphireEncryption>("Sapphire", t);
	BenchMarkKeyed<MD5MAC>("MD5-MAC", t);
	BenchMarkKeyed<XMACC<MD5> >("XMACC/MD5", t);
	BenchMarkKeyed<HMAC<MD5> >("HMAC/MD5", t);
	BenchMarkKeyed<CBC_MAC<RC6Encryption> >("CBC-MAC/RC6", t);
	BenchMarkKeyed<DMAC<RC6Encryption> >("DMAC/RC6", t);

	{
		Integer p("CB6C,B8CE,6351,164F,5D0C,0C9E,9E31,E231,CF4E,D551,CBD0,E671,5D6A,7B06,D8DF,C4A7h");
		Integer q("FD2A,8594,A132,20CC,4E6D,DE77,3AAA,CF15,CD9E,E447,8592,FF46,CC77,87BE,9876,A2AFh");
		Integer s("63239752671357255800299643604761065219897634268887145610573595874544114193025997412441121667211431");
		BlumBlumShub c(p, q, s);
		BenchMark("BlumBlumShub 512", c, t);
	}
	{
		Integer p("FD2A,8594,A132,20CC,4E6D,DE77,3AAA,CF15,CD9E,E447,8592,FF46,CC77,87BE,9876,9E2C,"
				  "8572,64C3,4CF4,188A,44D4,2130,1135,7982,6FF6,EDD3,26F0,5FAA,BAF4,A81E,7ADC,B80Bh");
		Integer q("C8B9,5797,B349,6BA3,FD72,F2C0,A796,8A65,EE0F,B4BA,272F,4FEE,4DB1,06D5,ECEB,7142,"
				  "E8A8,E5A8,6BF9,A32F,BA37,BACC,8A75,8A6B,2DCE,D6EC,B515,980A,4BB1,08FB,6F2C,2383h");
		Integer s("3578,8F00,2965,71A4,4382,699F,45FD,3922,8238,241B,CEBA,0543,3443,E8D9,12FB,AC46,"
				  "7EC4,8505,EC9E,7EE8,5A23,9B2A,B615,D0C4,9448,F23A,ADEE,E850,1A7A,CA30,0B5B,A408,"
				  "D936,21BA,844E,BDD6,7848,3D1E,9137,CC87,DAA5,773B,D45A,C8BB,5392,1393,108B,6992,"
				  "74E3,C5E2,C235,A321,0111,3BA4,BAB4,1A2F,17EE,C371,DE67,01C9,0F3D,907A,B252,9BDDh");
		BlumBlumShub c(p, q, s);
		BenchMark("BlumBlumShub 1024", c, t);
	}
	{
		Integer p("EB56,978A,7BA7,B5D9,1383,4611,94F5,4766,FCEF,CF41,958A,FC41,43D0,839F,C56B,B568,"
				  "4ED3,9E5A,BABB,5ACE,8B11,CEBC,88A2,7C12,FFEE,E6E8,CF0A,E231,5BC2,DEDE,80B7,32F6,"
				  "340E,D8A6,B7DE,C779,7EE5,0E16,9C88,FC9F,2A0E,EE6C,7D47,C5F2,6B06,EB8C,F1C8,2E67,"
				  "5B82,8C28,4FB8,542F,2874,C355,CEEE,7A54,1B06,A8AB,8B66,6A5C,9DB2,72B8,74F3,7BC7h");
		Integer q("EB6B,3645,4591,8343,7331,7CAC,B02E,4BB9,DEF5,8EDC,1772,DB9B,9571,5FAB,1CDD,4FB1,"
				  "7B9A,07CD,E715,D448,F552,CBBD,D387,C037,DE70,6661,F360,D0E8,D42E,292A,9321,DDCB,"
				  "0BF9,C514,BFAC,3F2C,C06E,DF64,A9B8,50D6,AC4F,B9E4,014B,5624,2B40,A0D4,5D0B,6DD4,"
				  "0989,D00E,0268,99AB,21DB,0BB4,DB38,84DA,594F,575F,95AC,1B70,45E4,96C8,C6AD,CE67h");
		Integer s("C75A,8A0D,E231,295F,C08A,1716,8611,D5EC,E9EF,B565,90EC,58C0,57D0,DA7D,C6E6,DB00,"
				  "2282,1CA7,EA31,D64E,768C,0B19,8563,36DF,2226,F4EC,74A4,2844,2E8D,37E8,53DC,0172,"
				  "5F56,8CF9,B444,CA02,78B3,17AF,7C78,D320,16AE,AC3D,B97F,7259,1B8F,9C84,6A16,B878,"
				  "0595,70BB,9C52,18B5,9100,9C1F,E85A,4035,06F3,5F38,7462,F01D,0462,BFBC,A4CD,4A45,"
				  "3A77,E7F8,DED1,D6EF,CEF7,0937,CD3F,3AF1,4F88,932D,6D4B,002C,3735,304C,C5D3,B88A,"
				  "B57B,24B6,5346,9B46,5153,B7ED,B216,C181,B1C6,C52E,CD2B,E0AA,B1BB,0A93,C92E,4F79,"
				  "4931,E303,7C8F,A408,8ACF,56CD,6EC0,76A2,5015,6BA4,4C50,C44D,53B9,E168,5F84,B381,"
				  "2514,10B2,00E5,B4D1,4156,A2FE,0BF6,6F33,0A1B,91C6,31B8,1C90,02F1,FB1F,C494,8B65h");
		BlumBlumShub c(p, q, s);
		BenchMark("BlumBlumShub 2048", c, t);
	}
	cout << "</TABLE>" << endl;

	cout << "<TABLE border=1><COLGROUP><COL align=left><COL align=right><COL align=right><COL align=right>" << endl;
	cout << "<THEAD><TR><TH>Operation<TH>Iterations<TH>Total Time<TH>Milliseconds/Operation" << endl;

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkCrypto<RSAES_OAEP_SHA_Decryptor, RSAES_OAEP_SHA_Encryptor>("rsa512.dat", "RSA 512", t);
	BenchMarkCrypto<RabinDecryptor, RabinEncryptor>("rabi512.dat", "Rabin 512", t);
	BenchMarkCrypto<BlumGoldwasserPrivateKey, BlumGoldwasserPublicKey>("blum512.dat", "BlumGoldwasser 512", t);
	BenchMarkCrypto<LUCES_OAEP_SHA_Decryptor, LUCES_OAEP_SHA_Encryptor>("luc512.dat", "LUC 512", t);
	BenchMarkCrypto<ElGamalDecryptor, ElGamalEncryptor>("elgc512.dat", "ElGamal 512", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	BenchMarkCrypto<RSAES_OAEP_SHA_Decryptor, RSAES_OAEP_SHA_Encryptor>("rsa1024.dat", "RSA 1024", t);
	BenchMarkCrypto<RabinDecryptor, RabinEncryptor>("rabi1024.dat", "Rabin 1024", t);
	BenchMarkCrypto<BlumGoldwasserPrivateKey, BlumGoldwasserPublicKey>("blum1024.dat", "BlumGoldwasser 1024", t);
	BenchMarkCrypto<LUCES_OAEP_SHA_Decryptor, LUCES_OAEP_SHA_Encryptor>("luc1024.dat", "LUC 1024", t);
	BenchMarkCrypto<ElGamalDecryptor, ElGamalEncryptor>("elgc1024.dat", "ElGamal 1024", t);
	BenchMarkCrypto<LUCELG_Decryptor, LUCELG_Encryptor>("lucc512.dat", "LUCELG 512", t);

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkCrypto<RSAES_OAEP_SHA_Decryptor, RSAES_OAEP_SHA_Encryptor>("rsa2048.dat", "RSA 2048", t);
	BenchMarkCrypto<RabinDecryptor, RabinEncryptor>("rabi2048.dat", "Rabin 2048", t);
	BenchMarkCrypto<BlumGoldwasserPrivateKey, BlumGoldwasserPublicKey>("blum2048.dat", "BlumGoldwasser 2048", t);
	BenchMarkCrypto<LUCES_OAEP_SHA_Decryptor, LUCES_OAEP_SHA_Encryptor>("luc2048.dat", "LUC 2048", t);
	BenchMarkCrypto<ElGamalDecryptor, ElGamalEncryptor>("elgc2048.dat", "ElGamal 2048", t);
	BenchMarkCrypto<LUCELG_Decryptor, LUCELG_Encryptor>("lucc1024.dat", "LUCELG 1024", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	BenchMarkSignature<RSASSA_PKCS1v15_SHA_Signer, RSASSA_PKCS1v15_SHA_Verifier>("rsa512.dat", "RSA 512", t);
	BenchMarkSignature<RabinSignerWith(SHA), RabinVerifierWith(SHA) >("rabi512.dat", "Rabin 512", t);
	BenchMarkSignature<RWSigner<SHA>, RWVerifier<SHA> >("rw512.dat", "RW 512", t);
	BenchMarkSignature<LUCSSA_PKCS1v15_SHA_Signer, LUCSSA_PKCS1v15_SHA_Verifier>("luc512.dat", "LUC 512", t);
	BenchMarkSignature<NRSigner<SHA>, NRVerifier<SHA> >("nr512.dat", "NR 512", t);
	BenchMarkSignature<DSAPrivateKey, DSAPublicKey>("dsa512.dat", "DSA 512", t);

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkSignature<RSASSA_PKCS1v15_SHA_Signer, RSASSA_PKCS1v15_SHA_Verifier>("rsa1024.dat", "RSA 1024", t);
	BenchMarkSignature<RabinSignerWith(SHA), RabinVerifierWith(SHA) >("rabi1024.dat", "Rabin 1024", t);
	BenchMarkSignature<RWSigner<SHA>, RWVerifier<SHA> >("rw1024.dat", "RW 1024", t);
	BenchMarkSignature<LUCSSA_PKCS1v15_SHA_Signer, LUCSSA_PKCS1v15_SHA_Verifier>("luc1024.dat", "LUC 1024", t);
	BenchMarkSignature<NRSigner<SHA>, NRVerifier<SHA> >("nr1024.dat", "NR 1024", t);
	BenchMarkSignature<DSAPrivateKey, DSAPublicKey>("dsa1024.dat", "DSA 1024", t);
	BenchMarkSignature<LUCELG_Signer<SHA>, LUCELG_Verifier<SHA> >("lucs512.dat", "LUCELG 512", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	BenchMarkSignature<RSASSA_PKCS1v15_SHA_Signer, RSASSA_PKCS1v15_SHA_Verifier>("rsa2048.dat", "RSA 2048", t);
	BenchMarkSignature<RabinSignerWith(SHA), RabinVerifierWith(SHA) >("rabi2048.dat", "Rabin 2048", t);
	BenchMarkSignature<RWSigner<SHA>, RWVerifier<SHA> >("rw2048.dat", "RW 2048", t);
	BenchMarkSignature<LUCSSA_PKCS1v15_SHA_Signer, LUCSSA_PKCS1v15_SHA_Verifier>("luc2048.dat", "LUC 2048", t);
	BenchMarkSignature<NRSigner<SHA>, NRVerifier<SHA> >("nr2048.dat", "NR 2048", t);
	BenchMarkSignature<LUCELG_Signer<SHA>, LUCELG_Verifier<SHA> >("lucs1024.dat", "LUCELG 1024", t);

	cout << "<TBODY style=\"background: yellow\">" << endl;
	BenchMarkKeyAgreement<DH>("dh512.dat", "DH 512", t);
	BenchMarkKeyAgreement<DH>("dh1024.dat", "DH 1024", t);
	BenchMarkKeyAgreement<DH>("dh2048.dat", "DH 2048", t);
	BenchMarkKeyAgreement<MQV>("mqv512.dat", "MQV 512", t);
	BenchMarkKeyAgreement<MQV>("mqv1024.dat", "MQV 1024", t);
	BenchMarkKeyAgreement<MQV>("mqv2048.dat", "MQV 2048", t);

	cout << "<TBODY style=\"background: white\">" << endl;
	{
		Integer modulus("199999999999999999999999980586675243082581144187569");
		Integer a("659942,b7261b,249174,c86bd5,e2a65b,45fe07,37d110h");
		Integer b("3ece7d,09473d,666000,5baef5,d4e00e,30159d,2df49ah");
		Integer x("25dd61,4c0667,81abc0,fe6c84,fefaa3,858ca6,96d0e8h");
		Integer y("4e2477,05aab0,b3497f,d62b5e,78a531,446729,6c3fach");
		Integer r("100000000000000000000000000000000000000000000000151");
		Integer k(2);
		Integer d("76572944925670636209790912427415155085360939712345");

		ECP ec(modulus, a, b);
		ECP::Point P(x, y);
		P = ec.Multiply(k, P);
		ECP::Point Q(ec.Multiply(d, P));
		ECPrivateKey<ECP> cpriv(ec, P, Q, r, d);
		ECPublicKey<ECP> cpub(cpriv);
		ECSigner<ECP, SHA> spriv(ec, P, Q, r, d);
		ECVerifier<ECP, SHA> spub(spriv);
		ECDHC<ECP> ecdhc(ec, P, r, k);
		ECMQVC<ECP> ecmqvc(ec, P, r, k);

		BenchMarkEncryption("EC over GF(p) 168", cpub, t);
		BenchMarkDecryption("EC over GF(p) 168", cpriv, cpub, t);
		BenchMarkSigning("EC over GF(p) 168 NR", spriv, t);
		BenchMarkVerification("EC over GF(p) 168 NR", spriv, spub, t);
		BenchMarkKeyGen("EC over GF(p) 168 DHC", ecdhc, t);
		BenchMarkAgreement("EC over GF(p) 168 DHC", ecdhc, t);
		BenchMarkKeyGen("EC over GF(p) 168 MQVC", ecmqvc, t);
		BenchMarkAgreement("EC over GF(p) 168 MQVC", ecmqvc, t);
	}

	cout << "<TBODY style=\"background: yellow\">" << endl;
	{
		Integer r("3805993847215893016155463826195386266397436443");
		Integer k(12);
		Integer d("2065729449256706362097909124274151550853609397");

		GF2N gf2n(155, 62, 0);
		byte b[]={0x7, 0x33, 0x8f};
		EC2N ec(gf2n, PolynomialMod2::Zero(), PolynomialMod2(b,3));
		EC2N::Point P(0x7B, 0x1C8);
		P = ec.Multiply(k, P);
		EC2N::Point Q(ec.Multiply(d, P));
		ECPrivateKey<EC2N> cpriv(ec, P, Q, r, d);
		ECPublicKey<EC2N> cpub(cpriv);
		ECSigner<EC2N, SHA> spriv(ec, P, Q, r, d);
		ECVerifier<EC2N, SHA> spub(spriv);
		ECDHC<EC2N> ecdhc(ec, P, r, k);
		ECMQVC<EC2N> ecmqvc(ec, P, r, k);

		BenchMarkEncryption("EC over GF(2^n) 155", cpub, t);
		BenchMarkDecryption("EC over GF(2^n) 155", cpriv, cpub, t);
		BenchMarkSigning("EC over GF(2^n) 155", spriv, t);
		BenchMarkVerification("EC over GF(2^n) 155", spriv, spub, t);
		BenchMarkKeyGen("EC over GF(2^n) 155 DHC", ecdhc, t);
		BenchMarkAgreement("EC over GF(2^n) 155 DHC", ecdhc, t);
		BenchMarkKeyGen("EC over GF(2^n) 155 MQVC", ecmqvc, t);
		BenchMarkAgreement("EC over GF(2^n) 155 MQVC", ecmqvc, t);
	}
	cout << "</TABLE>" << endl;

	cout << "Throughput Geometric Average: " << setiosflags(ios::fixed) << exp(logtotal/logcount) << endl;
}
