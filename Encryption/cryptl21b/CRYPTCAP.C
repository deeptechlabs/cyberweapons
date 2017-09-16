/****************************************************************************
*																			*
*					cryptlib Capability Management Routines					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"

/****************************************************************************
*																			*
*						Capability Management Functions						*
*																			*
****************************************************************************/

/* The parameters of most encryption algorithms are traditionally specified
   in bytes, so we define a shorter form of the bitsToBytes() macro to allow
   the capability information to be specified in bits */

#define bits(x)	bitsToBytes(x)

/* The loadIV() function is shared among all the built-in capabilities */

int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength );

/* The functions used to implement the Blowfish encryption routines */

int blowfishSelfTest( void );
int blowfishInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int blowfishEnd( CRYPT_INFO *cryptInfo );
int blowfishInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int blowfishEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the CAST-128 encryption routines */

int castSelfTest( void );
int castInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int castEnd( CRYPT_INFO *cryptInfo );
int castInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int castEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DES encryption routines */

int desSelfTest( void );
int desInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int desEnd( CRYPT_INFO *cryptInfo );
int desInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int desEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the triple DES encryption routines */

int des3SelfTest( void );
int des3Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int des3End( CRYPT_INFO *cryptInfo );
int des3InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int des3EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the IDEA encryption routines */

int ideaSelfTest( void );
int ideaInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int ideaEnd( CRYPT_INFO *cryptInfo );
int ideaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int ideaEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement RC2 encryption routines */

int rc2SelfTest( void );
int rc2Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int rc2End( CRYPT_INFO *cryptInfo );
int rc2InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rc2EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RC4 encryption routines */

int rc4SelfTest( void );
int rc4Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int rc4End( CRYPT_INFO *cryptInfo );
int rc4InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rc4Encrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement RC5 encryption routines */

int rc5SelfTest( void );
int rc5Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int rc5End( CRYPT_INFO *cryptInfo );
int rc5InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rc5EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SAFER and SAFER_SK encryption
   routines */

int saferSelfTest( void );
int saferInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int saferEnd( CRYPT_INFO *cryptInfo );
int saferInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int saferGetKeysize( CRYPT_INFO *cryptInfo );
int saferEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Skipjack encryption routines */

int skipjackSelfTest( void );
int skipjackInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int skipjackEnd( CRYPT_INFO *cryptInfo );
int skipjackInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int skipjackEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Diffie-Hellman key exchange routines */

int dhSelfTest( void );
int dhInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int dhGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int dhEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int dhDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DSA encryption routines */

int dsaSelfTest( void );
int dsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int dsaGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int dsaSign( CRYPT_INFO *cryptInfo, void *buffer, int length );
int dsaSigCheck( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Elgamal encryption routines */

int elgamalSelfTest( void );
int elgamalInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int elgamalGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int elgamalEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int elgamalDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int elgamalSign( CRYPT_INFO *cryptInfo, void *buffer, int length );
int elgamalSigCheck( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RSA encryption routines */

int rsaSelfTest( void );
int rsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rsaGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int rsaEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rsaDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD2 hash routines */

int md2SelfTest( void );
int md2Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int md2End( CRYPT_INFO *cryptInfo );
int md2Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD4 hash routines */

int md4SelfTest( void );
int md4Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int md4End( CRYPT_INFO *cryptInfo );
int md4Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD5 hash routines */

int md5SelfTest( void );
int md5Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int md5End( CRYPT_INFO *cryptInfo );
int md5Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MDC2 hash routines */

int mdc2SelfTest( void );
int mdc2Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int mdc2End( CRYPT_INFO *cryptInfo );
int mdc2Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RIPEMD-160 hash routines */

int ripemd160SelfTest( void );
int ripemd160Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int ripemd160End( CRYPT_INFO *cryptInfo );
int ripemd160Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SHA hash routines */

int shaSelfTest( void );
int shaInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int shaEnd( CRYPT_INFO *cryptInfo );
int shaHash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the HMAC-MD5 MAC routines */

int hmacMD5SelfTest( void );
int hmacMD5Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int hmacMD5End( CRYPT_INFO *cryptInfo );
int hmacMD5InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacMD5Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the HMAC-RIPEMD-160 MAC routines */

int hmacRIPEMD160SelfTest( void );
int hmacRIPEMD160Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int hmacRIPEMD160End( CRYPT_INFO *cryptInfo );
int hmacRIPEMD160InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacRIPEMD160Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the HMAC-SHA MAC routines */

int hmacSHASelfTest( void );
int hmacSHAInit( CRYPT_INFO *cryptInfo, const void *cryptInfoEx );
int hmacSHAEnd( CRYPT_INFO *cryptInfo );
int hmacSHAInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacSHAHash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The encryption library intrinsic capability list */

static CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The no-encryption capability */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, 0, "None", "None",
		0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, CRYPT_ERROR },

	/* The DES capabilities */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB, bits( 64 ), "DES", "ECB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		desSelfTest, desInit, desEnd, NULL, desInitKey, NULL,
		NULL, desEncryptECB, desDecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC, bits( 64 ), "DES", "CBC",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		desSelfTest, desInit, desEnd, loadIV, desInitKey, NULL,
		NULL, desEncryptCBC, desDecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB, bits( 8 ), "DES", "CFB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		desSelfTest, desInit, desEnd, loadIV, desInitKey, NULL,
		NULL, desEncryptCFB, desDecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB, bits( 8 ), "DES", "OFB",
		bits( 40 ), bits( 64 ), bits( 64 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		desSelfTest, desInit, desEnd, loadIV, desInitKey, NULL,
		NULL, desEncryptOFB, desDecryptOFB, NULL, NULL,
		CRYPT_ERROR },

	/* The triple DES capabilities.  Unlike the other algorithms, the minimum
	   key size here is 64 + 8 bits (nominally 56 + 1 bits) because using a
	   key any shorter is (a) no better than single DES, and (b) will result
	   in a key load error since the second key will be an all-zero weak
	   key */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_ECB, bits( 64 ), "3DES", "ECB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 0 ), bits( 0 ), bits( 0  ),
		des3SelfTest, des3Init, des3End, NULL, des3InitKey, NULL,
		NULL, des3EncryptECB, des3DecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC, bits( 64 ), "3DES", "CBC",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		des3SelfTest, des3Init, des3End, loadIV, des3InitKey, NULL,
		NULL, des3EncryptCBC, des3DecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CFB, bits( 8 ), "3DES", "CFB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		des3SelfTest, des3Init, des3End, loadIV, des3InitKey, NULL,
		NULL, des3EncryptCFB, des3DecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_3DES, CRYPT_MODE_OFB, bits( 8 ), "3DES", "OFB",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		des3SelfTest, des3Init, des3End, loadIV, des3InitKey, NULL,
		NULL, des3EncryptOFB, des3DecryptOFB, NULL, NULL,
		CRYPT_ERROR },

#ifndef NO_IDEA
	/* The IDEA capabilities */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, bits( 64 ), "IDEA", "ECB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		ideaSelfTest, ideaInit, ideaEnd, NULL, ideaInitKey, NULL,
		NULL, ideaEncryptECB, ideaDecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, bits( 64 ), "IDEA", "CBC",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaEnd, loadIV, ideaInitKey, NULL,
		NULL, ideaEncryptCBC, ideaDecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB, bits( 8 ), "IDEA", "CFB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaEnd, loadIV, ideaInitKey, NULL,
		NULL, ideaEncryptCFB, ideaDecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB, bits( 8 ), "IDEA", "OFB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		ideaSelfTest, ideaInit, ideaEnd, loadIV, ideaInitKey, NULL,
		NULL, ideaEncryptOFB, ideaDecryptOFB, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_IDEA */

#ifndef NO_CAST
	/* The CAST-128 capabilities */
	{ CRYPT_ALGO_CAST, CRYPT_MODE_ECB, bits( 64 ), "CAST-128", "ECB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		castSelfTest, castInit, castEnd, NULL, castInitKey, NULL,
		NULL, castEncryptECB, castDecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_CAST, CRYPT_MODE_CBC, bits( 64 ), "CAST-128", "CBC",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		castSelfTest, castInit, castEnd, loadIV, castInitKey, NULL,
		NULL, castEncryptCBC, castDecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_CAST, CRYPT_MODE_CFB, bits( 8 ), "CAST-128", "CFB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		castSelfTest, castInit, castEnd, loadIV, castInitKey, NULL,
		NULL, castEncryptCFB, castDecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_CAST, CRYPT_MODE_OFB, bits( 8 ), "CAST-128", "OFB",
		bits( 40 ), bits( 128 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		castSelfTest, castInit, castEnd, loadIV, castInitKey, NULL,
		NULL, castEncryptOFB, castDecryptOFB, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_CAST */

#ifndef NO_RC2
	/* The RC2 capabilities */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB, bits( 64 ), "RC2", "ECB",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc2SelfTest, rc2Init, rc2End, NULL, rc2InitKey, NULL,
		NULL, rc2EncryptECB, rc2DecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC, bits( 64 ), "RC2", "CBC",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2End, loadIV, rc2InitKey, NULL,
		NULL, rc2EncryptCBC, rc2DecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CFB, bits( 8 ), "RC2", "CFB",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2End, loadIV, rc2InitKey, NULL,
		NULL, rc2EncryptCFB, rc2DecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_RC2, CRYPT_MODE_OFB, bits( 8 ), "RC2", "OFB",
		bits( 40 ), bits( 128 ), bits( 1024 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		rc2SelfTest, rc2Init, rc2End, loadIV, rc2InitKey, NULL,
		NULL, rc2EncryptOFB, rc2DecryptOFB, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_RC2 */

#ifndef NO_RC4
	/* The RC4 capabilities */
	{ CRYPT_ALGO_RC4, CRYPT_MODE_STREAM, bits( 8 ), "RC4", "Stream",
		bits( 40 ), bits( 128 ), 256,
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc4SelfTest, rc4Init, rc4End, NULL, rc4InitKey, NULL,
		NULL, rc4Encrypt, rc4Encrypt, NULL, NULL, CRYPT_ERROR },
#endif /* NO_RC4 */

#ifndef NO_RC5
	/* The RC5 capabilities */
	{ CRYPT_ALGO_RC5, CRYPT_MODE_ECB, bits( 64 ), "RC5", "ECB",
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		rc5SelfTest, rc5Init, rc5End, NULL, rc5InitKey, NULL,
		NULL, rc5EncryptECB, rc5DecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC, bits( 64 ), "RC5", "CBC",
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5End, loadIV, rc5InitKey, NULL,
		NULL, rc5EncryptCBC, rc5DecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CFB, bits( 8 ), "RC5", "CFB",
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5End, loadIV, rc5InitKey, NULL,
		NULL, rc5EncryptCFB, rc5DecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_RC5, CRYPT_MODE_OFB, bits( 8 ), "RC5", "OFB",
		bits( 40 ), bits( 128 ), bits( 832 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		rc5SelfTest, rc5Init, rc5End, loadIV, rc5InitKey, NULL,
		NULL, rc5EncryptOFB, rc5DecryptOFB, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_RC5 */

#ifndef NO_SAFER
	/* The SAFER capabilities */
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_ECB, bits( 64 ), "SAFER", "ECB",
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		saferSelfTest, saferInit, saferEnd, loadIV, saferInitKey, NULL,
		saferGetKeysize, saferEncryptECB, saferDecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CBC, bits( 64 ), "SAFER", "CBC",
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		saferSelfTest, saferInit, saferEnd, loadIV, saferInitKey, NULL,
		saferGetKeysize, saferEncryptCBC, saferDecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_CFB, bits( 8 ), "SAFER", "CFB",
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		saferSelfTest, saferInit, saferEnd, loadIV, saferInitKey, NULL,
		saferGetKeysize, saferEncryptCFB, saferDecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SAFER, CRYPT_MODE_OFB, bits( 8 ), "SAFER", "OFB",
		bits( 40 ), bits( 64 ), bits( 128 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		saferSelfTest, saferInit, saferEnd, loadIV, saferInitKey, NULL,
		saferGetKeysize, saferEncryptOFB, saferDecryptOFB, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_SAFER */

	/* The Blowfish capabilities */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_ECB, bits( 64 ), "Blowfish", "ECB",
		bits( 40 ), bits( 128 ), bits( 448 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		blowfishSelfTest, blowfishInit, blowfishEnd, NULL, blowfishInitKey,
		NULL, NULL, blowfishEncryptECB, blowfishDecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC, bits( 64 ), "Blowfish", "CBC",
		bits( 40 ), bits( 128 ), bits( 448 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishEnd, loadIV, blowfishInitKey,
		NULL, NULL, blowfishEncryptCBC, blowfishDecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB, bits( 8 ), "Blowfish", "CFB",
		bits( 40 ), bits( 128 ), bits( 448 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishEnd, loadIV, blowfishInitKey,
		NULL, NULL, blowfishEncryptCFB, blowfishDecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_OFB, bits( 8 ), "Blowfish", "OFB",
		bits( 40 ), bits( 128 ), bits( 448 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		blowfishSelfTest, blowfishInit, blowfishEnd, loadIV, blowfishInitKey,
		NULL, NULL, blowfishEncryptOFB, blowfishDecryptOFB, NULL, NULL,
		CRYPT_ERROR },

#ifndef NO_SKIPJACK
	/* The Skipjack capabilities */
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB, bits( 64 ), "Skipjack", "ECB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 0 ), bits( 0 ), bits( 0 ),
		skipjackSelfTest, skipjackInit, skipjackEnd, NULL, skipjackInitKey,
		NULL, NULL, skipjackEncryptECB, skipjackDecryptECB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC, bits( 64 ), "Skipjack", "CBC",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		skipjackSelfTest, skipjackInit, skipjackEnd, loadIV, skipjackInitKey,
		NULL, NULL, skipjackEncryptCBC, skipjackDecryptCBC, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CFB, bits( 8 ), "Skipjack", "CFB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		skipjackSelfTest, skipjackInit, skipjackEnd, loadIV, skipjackInitKey,
		NULL, NULL, skipjackEncryptCFB, skipjackDecryptCFB, NULL, NULL,
		CRYPT_ERROR },
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_OFB, bits( 8 ), "Skipjack", "OFB",
		bits( 80 ), bits( 80 ), bits( 80 ),
		bits( 32 ), bits( 64 ), bits( 64 ),
		skipjackSelfTest, skipjackInit, skipjackEnd, loadIV, skipjackInitKey,
		NULL, NULL, skipjackEncryptOFB, skipjackDecryptOFB, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_SKIPJACK */

	/* The MD2 capabilities */
	{ CRYPT_ALGO_MD2, CRYPT_MODE_NONE, bits( 128 ), "MD2", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		md2SelfTest, md2Init, md2End, NULL,
		NULL, NULL, NULL, md2Hash, md2Hash, NULL, NULL,CRYPT_ERROR },

#ifndef NO_MD4
	/* The MD4 capabilities */
	{ CRYPT_ALGO_MD4, CRYPT_MODE_NONE, bits( 128 ), "MD4", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		md4SelfTest, md4Init, md4End, NULL,
		NULL, NULL, NULL, md4Hash, md4Hash, NULL, NULL,CRYPT_ERROR },
#endif /* NO_MD4 */

	/* The MD5 capabilities */
	{ CRYPT_ALGO_MD5, CRYPT_MODE_NONE, bits( 128 ), "MD5", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		md5SelfTest, md5Init, md5End, NULL,
		NULL, NULL, NULL, md5Hash, md5Hash, NULL, NULL,CRYPT_ERROR },

	/* The SHA capabilities */
	{ CRYPT_ALGO_SHA, CRYPT_MODE_NONE, bits( 160 ), "SHA", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		shaSelfTest, shaInit, shaEnd, NULL,
		NULL, NULL, NULL, shaHash, shaHash, NULL, NULL,CRYPT_ERROR },

	/* The RIPEMD-160 capabilities */
	{ CRYPT_ALGO_RIPEMD160, CRYPT_MODE_NONE, bits( 160 ),
		"RIPEMD-160", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		ripemd160SelfTest, ripemd160Init, ripemd160End, NULL,
		NULL, NULL, NULL, ripemd160Hash, ripemd160Hash, NULL, NULL,
		CRYPT_ERROR },

#ifndef NO_MDC2
	/* The MDC-2 capabilities */
	{ CRYPT_ALGO_MDC2, CRYPT_MODE_NONE, bits( 128 ), "MDC-2", "Hash algorithm",
		bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ), bits( 0 ),
		mdc2SelfTest, mdc2Init, mdc2End, NULL,
		NULL, NULL, NULL, mdc2Hash, mdc2Hash, NULL, NULL, CRYPT_ERROR },
#endif /* NO_MDC2 */

#ifndef NO_HMAC_MD5
	/* The HMAC-MD5 capabilities */
	{ CRYPT_ALGO_HMAC_MD5, CRYPT_MODE_NONE, bits( 128 ), "HMAC-MD5",
		"MAC algorithm",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		hmacMD5SelfTest, hmacMD5Init, hmacMD5End, NULL, hmacMD5InitKey,
		NULL, NULL, hmacMD5Hash, hmacMD5Hash, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_HMAC_MD5 */

	/* The HMAC-SHA capabilities */
	{ CRYPT_ALGO_HMAC_SHA, CRYPT_MODE_NONE, bits( 160 ), "HMAC-SHA",
		"MAC algorithm",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		hmacSHASelfTest, hmacSHAInit, hmacSHAEnd, NULL, hmacSHAInitKey,
		NULL, NULL, hmacSHAHash, hmacSHAHash, NULL, NULL,
		CRYPT_ERROR },

#ifndef NO_HMAC_RIPEMD160
	/* The HMAC-RIPEMD160 capabilities */
	{ CRYPT_ALGO_HMAC_RIPEMD160, CRYPT_MODE_NONE, bits( 160 ), "HMAC-RIPEMD160",
		"MAC algorithm",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		hmacRIPEMD160SelfTest, hmacRIPEMD160Init, hmacRIPEMD160End, NULL, hmacRIPEMD160InitKey,
		NULL, NULL, hmacRIPEMD160Hash, hmacRIPEMD160Hash, NULL, NULL,
		CRYPT_ERROR },
#endif /* NO_HMAC_RIPEMD160 */

	/* The Diffie-Hellman capabilities */
	{ CRYPT_ALGO_DH, CRYPT_MODE_PKC, bits( 0 ), "Diffie-Hellman",
		"Key exchange algorithm",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		dhSelfTest, NULL, NULL, NULL, dhInitKey,
		dhGenerateKey, NULL, dhEncrypt, dhDecrypt, NULL, NULL,
		CRYPT_ERROR },

	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, CRYPT_MODE_PKC, bits( 0 ), "RSA",
		"Public-key algorithm",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		rsaSelfTest, NULL, NULL, NULL, rsaInitKey,
		rsaGenerateKey, NULL, rsaEncrypt, rsaDecrypt, rsaDecrypt, rsaEncrypt,
		CRYPT_ERROR },

	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, CRYPT_MODE_PKC, bits( 0 ), "DSA",
		"Public-key algorithm",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		dsaSelfTest, NULL, NULL, NULL, dsaInitKey,
		dsaGenerateKey, NULL, NULL, NULL, dsaSign, dsaSigCheck,
		CRYPT_ERROR },

#ifndef NO_ELGAMAL
	/* The ElGamal capabilities */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_MODE_PKC, bits( 0 ), "Elgamal",
		"Public-key algorithm",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE,
		bits( 0 ), bits( 0 ), bits( 0 ),
		elgamalSelfTest, NULL, NULL, NULL, elgamalInitKey,
		elgamalGenerateKey, NULL, elgamalEncrypt, elgamalDecrypt,
		elgamalSign, elgamalSigCheck, CRYPT_ERROR },
#endif /* NO_ELGAMAL */

	/* Vendors may want to use their own algorithms which aren't part of the
	   general cryptlib suite.  The following includes the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE, CRYPT_MODE_NONE, CRYPT_ERROR, "", "",
		0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, CRYPT_ERROR }
	};

/* Query whether the capabilities have been initialised */

BOOLEAN queryCapabilitiesInited( void )
	{
	return( ( capabilities[ 1 ].selfTestStatus != CRYPT_ERROR ) ? TRUE : FALSE );
	}

/* Check that a capability info record is consistent */

int checkCapability( const CAPABILITY_INFO *capabilityInfoPtr )
	{
	CRYPT_ALGO cryptAlgo = capabilityInfoPtr->cryptAlgo;
	CRYPT_MODE cryptMode = capabilityInfoPtr->cryptMode;

	/* Check the algorithm and mode parameters */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST_MAC || \
		cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST || \
		capabilityInfoPtr->algoName == NULL || \
		capabilityInfoPtr->modeName == NULL )
		return( CRYPT_ERROR );

	/* Make sure that the minimum functions are present */
	if( cryptAlgo != CRYPT_ALGO_NONE && \
		( capabilityInfoPtr->selfTestFunction == NULL || \
		( ( capabilityInfoPtr->encryptFunction == NULL || \
			capabilityInfoPtr->decryptFunction == NULL ) && \
		  ( capabilityInfoPtr->signFunction == NULL || \
			capabilityInfoPtr->sigCheckFunction == NULL ) ) ) )
		return( CRYPT_ERROR );

	/* Make sure the algorithm/mode names will fit inside the query
	   information structure */
	if( strlen( capabilityInfoPtr->algoName ) > CRYPT_MAX_TEXTSIZE - 1 || \
		strlen( capabilityInfoPtr->modeName ) > CRYPT_MAX_TEXTSIZE - 1 )
		return( CRYPT_ERROR );

	/* Make sure the algorithm/mode-specific parameters are consistent */
	if( capabilityInfoPtr->minKeySize > capabilityInfoPtr->keySize || \
		capabilityInfoPtr->maxKeySize < capabilityInfoPtr->keySize || \
		capabilityInfoPtr->minIVsize > capabilityInfoPtr->ivSize || \
		capabilityInfoPtr->maxIVsize < capabilityInfoPtr->ivSize )
		return( CRYPT_ERROR );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		if( cryptMode < CRYPT_MODE_FIRST_CONVENTIONAL || \
			cryptMode > CRYPT_MODE_LAST_CONVENTIONAL )
			return( CRYPT_ERROR );
		if( ( capabilityInfoPtr->blockSize < bits( 8 ) || \
        	  capabilityInfoPtr->blockSize > 256 ) || \
			( capabilityInfoPtr->minKeySize < bits( 40 ) || \
			  capabilityInfoPtr->keySize < bits( 40 ) || \
			  capabilityInfoPtr->keySize > CRYPT_MAX_KEYSIZE || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_KEYSIZE ) )
			return( CRYPT_ERROR );
		if( cryptMode == CRYPT_MODE_ECB || cryptMode == CRYPT_MODE_STREAM )
			{
			if( capabilityInfoPtr->minIVsize || capabilityInfoPtr->ivSize || \
				capabilityInfoPtr->maxIVsize )
				return( CRYPT_ERROR );
			}
		else
			if( capabilityInfoPtr->initIVFunction == NULL || \
				capabilityInfoPtr->minIVsize < bits( 32 ) || \
				capabilityInfoPtr->ivSize < bits( 32 ) || \
				capabilityInfoPtr->ivSize > CRYPT_MAX_IVSIZE || \
				capabilityInfoPtr->maxIVsize > CRYPT_MAX_IVSIZE )
				return( CRYPT_ERROR );
		if( capabilityInfoPtr->initFunction == NULL || \
			capabilityInfoPtr->initKeyFunction == NULL )
			return( CRYPT_ERROR );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
		cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		if( cryptMode != CRYPT_MODE_PKC || \
			capabilityInfoPtr->blockSize || \
			( capabilityInfoPtr->minKeySize < bits( 512 ) || \
			  capabilityInfoPtr->keySize < bits( 512 ) || \
			  capabilityInfoPtr->keySize > CRYPT_MAX_PKCSIZE || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_PKCSIZE ) || \
			( capabilityInfoPtr->minIVsize || capabilityInfoPtr->ivSize || \
              capabilityInfoPtr->maxIVsize ) )
			return( CRYPT_ERROR );
		if( capabilityInfoPtr->initKeyFunction == NULL )
			return( CRYPT_ERROR );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
		cryptAlgo <= CRYPT_ALGO_LAST_HASH )
		{
		if( cryptMode != CRYPT_MODE_NONE || \
			( capabilityInfoPtr->blockSize < bits( 64 ) || \
			  capabilityInfoPtr->blockSize > 256 ) || \
			( capabilityInfoPtr->minKeySize || capabilityInfoPtr->keySize || \
			  capabilityInfoPtr->maxKeySize ) || \
			( capabilityInfoPtr->minIVsize || capabilityInfoPtr->ivSize || \
              capabilityInfoPtr->maxIVsize ) )
			return( CRYPT_ERROR );
		if( capabilityInfoPtr->initFunction == NULL )
			return( CRYPT_ERROR );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
		cryptAlgo <= CRYPT_ALGO_LAST_MAC )
		{
		if( cryptMode != CRYPT_MODE_NONE || \
			( capabilityInfoPtr->blockSize < bits( 64 ) || \
			  capabilityInfoPtr->blockSize > 256 ) || \
			( capabilityInfoPtr->minKeySize < bits( 40 ) || \
			  capabilityInfoPtr->keySize < bits( 40 ) || \
			  capabilityInfoPtr->keySize > CRYPT_MAX_KEYSIZE || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_KEYSIZE ) || \
			( capabilityInfoPtr->minIVsize || capabilityInfoPtr->ivSize || \
              capabilityInfoPtr->maxIVsize ) )
			return( CRYPT_ERROR );
		if( capabilityInfoPtr->initFunction == NULL || \
			capabilityInfoPtr->initKeyFunction == NULL )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/* Initialise and shut down the intrinsic capabilities */

int initCapabilities( const BOOLEAN doSelfTest )
	{
	CRYPT_ALGO cryptAlgo = CRYPT_ERROR;
	int index;

	/* Perform the initialisation required for each capability */
	for( index = 0; capabilities[ index ].blockSize != CRYPT_ERROR; index++ )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = &capabilities[ index ];
		int status;

		/* Perform a sanity check for each capability */
		status = checkCapability( capabilityInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* Perform a self-test if necessary */
		if( doSelfTest )
			{
			int j, status = CRYPT_OK;

			/* If we've already encountered this algorithm, don't try the
			   self-test again */
			if( capabilityInfoPtr->cryptAlgo == cryptAlgo )
				continue;
			cryptAlgo = capabilityInfoPtr->cryptAlgo;

			/* Perform the self-test for this algorithm type */
			if( cryptAlgo != CRYPT_ALGO_NONE )
				status = capabilityInfoPtr->selfTestFunction();

			/* Set the test status for each capability using this algorithm */
			for( j = index; capabilities[ j ].blockSize != CRYPT_ERROR; j++ )
				if( capabilities[ j ].cryptAlgo == capabilityInfoPtr->cryptAlgo )
					capabilities[ j ].selfTestStatus = status;
			}
		else
			/* Set the test status for each capability.  Although we haven't
			   actually performed the self-test, we need to do this to avoid
			   getting a self-test error when we use a particular
			   capability */
			capabilities[ index ].selfTestStatus = CRYPT_OK;
		}

	return( CRYPT_OK );
	}

/* Find the capability record for a given encryption algorithm */

int findCapabilityInfo( const CAPABILITY_INFO FAR_BSS **capabilityInfoPtr,
						const CRYPT_ALGO cryptAlgo,
						const CRYPT_MODE cryptMode )
	{
	int index, status = CRYPT_NOALGO;

	/* Find the capability corresponding to the requested algorithm/mode */
	for( index = 0; capabilities[ index ].blockSize != CRYPT_ERROR; index++ )
		if( capabilities[ index ].cryptAlgo == cryptAlgo )
			{
			status = CRYPT_NOMODE;
			if( capabilities[ index ].cryptMode == cryptMode || \
				cryptMode == CRYPT_UNUSED )
				{
				*capabilityInfoPtr = &capabilities[ index ];
				status = CRYPT_OK;
				break;
				}
			}
	return( status );
	}

/****************************************************************************
*																			*
*							Capability Query Functions						*
*																			*
****************************************************************************/

/* Copy information from a capability record to a query record */

void copyCapabilityInfo( const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr,
						 CRYPT_QUERY_INFO *cryptQueryInfo )
	{
	memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
	cryptQueryInfo->cryptAlgo = capabilityInfoPtr->cryptAlgo;
	cryptQueryInfo->cryptMode = capabilityInfoPtr->cryptMode;
	strcpy( cryptQueryInfo->algoName, capabilityInfoPtr->algoName );
	strcpy( cryptQueryInfo->modeName, capabilityInfoPtr->modeName );
	cryptQueryInfo->blockSize = capabilityInfoPtr->blockSize;
	cryptQueryInfo->minKeySize = capabilityInfoPtr->minKeySize;
	cryptQueryInfo->keySize = capabilityInfoPtr->keySize;
	cryptQueryInfo->maxKeySize = capabilityInfoPtr->maxKeySize;
	cryptQueryInfo->minIVsize = capabilityInfoPtr->minIVsize;
	cryptQueryInfo->ivSize = capabilityInfoPtr->ivSize;
	cryptQueryInfo->maxIVsize = capabilityInfoPtr->maxIVsize;
	}

/* Get information on a given encryption capability */

CRET cryptQueryCapability( const CRYPT_ALGO cryptAlgo,
						   const CRYPT_MODE cryptMode,
						   CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	const CAPABILITY_INFO FAR_BSS *capabilityInfo;
	int status;

	/* Perform basic error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM1 );
	if( ( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST ) && \
		cryptMode != CRYPT_UNUSED )
		return( CRYPT_BADPARM2 );
	if( cryptQueryInfo != NULL )
		{
		if( checkBadPtrWrite( cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) ) )
			return( CRYPT_BADPARM3 );
		memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
		}

	/* Make sure the library has been initalised */
	if( !queryCapabilitiesInited() )
		return( CRYPT_NOTINITED );

	/* Find the information for this algorithm and return the appropriate
	   information */
	status = findCapabilityInfo( &capabilityInfo, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) || cryptQueryInfo == NULL )
		return( status );
	copyCapabilityInfo( capabilityInfo, cryptQueryInfo );
	return( CRYPT_OK );
	}

/* Get information on the algorithm used by a given encryption context */

CRET cryptQueryContext( const CRYPT_HANDLE cryptHandle,
						CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	CRYPT_CONTEXT context;
	CRYPT_INFO *cryptInfoPtr;
	const CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* Get the context and perform basic error checking */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA, &context,
							  RESOURCE_MESSAGE_DATA_CONTEXT, CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( checkBadPtrWrite( cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );

	/* Fill in the basic information */
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	copyCapabilityInfo( capabilityInfoPtr, cryptQueryInfo );

	/* We may be able to get more specific information than the generic
	   cryptQueryCapability() call could give us since the encryption context
	   contains extra information on the algorithm being used */
	if( capabilityInfoPtr->getKeysizeFunction != NULL )
		cryptQueryInfo->maxKeySize = \
					capabilityInfoPtr->getKeysizeFunction( cryptInfoPtr );
	if( cryptInfoPtr->type == CONTEXT_CONV )
		cryptQueryInfo->actualKeySize = cryptInfoPtr->ctxConv.userKeyLength;
	if( cryptInfoPtr->type == CONTEXT_PKC )
		cryptQueryInfo->actualKeySize = bitsToBytes( cryptInfoPtr->ctxPKC.keySizeBits );
	if( cryptInfoPtr->type == CONTEXT_MAC )
		cryptQueryInfo->actualKeySize = cryptInfoPtr->ctxMAC.userKeyLength;

	/* If it's a hash or MAC function and the hashing has completed, copy in
	   the current state */
	if( cryptInfoPtr->type == CONTEXT_HASH && cryptInfoPtr->ctxHash.done )
		memcpy( cryptQueryInfo->hashValue, cryptInfoPtr->ctxHash.hash,
				capabilityInfoPtr->blockSize );
	if( cryptInfoPtr->type == CONTEXT_MAC && cryptInfoPtr->ctxMAC.done )
		memcpy( cryptQueryInfo->hashValue, cryptInfoPtr->ctxMAC.mac,
				capabilityInfoPtr->blockSize );

	unlockResourceExit( cryptInfoPtr, CRYPT_OK );
	}

