/*
 * This is version 1.2 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

/*
 * This file contains the routines which interface with the Bignum 
 * concept and the different message digest algorithms MD5 and
 * NIST's shs.
 *
 * coded by Jack Lacy 2/92.
 * Copyright (c) 1992 AT&T Bell Laboratories
 */

#include "libcrypt.h"

static void fBigMD5Digest P((FILE *, BigInt));
static void bigMD5Digest P((unsigned char *, int, BigInt));
static void fBigMD4Digest P((FILE *, BigInt));
static void bigMD4Digest P((unsigned char *, int, BigInt));
static void fBigMD2Digest P((FILE *, BigInt));
static void bigMD2Digest P((unsigned char *, int, BigInt));
static void MD5Print  P((MD5_CTX *mdContext, FILE *out));
static void fMD5BinPrint  P((MD5_CTX *mdContext, FILE *out));
static void MD4Print  P((MD4_CTX *mdContext, FILE *out));
static void fMD4BinPrint  P((MD4_CTX *mdContext, FILE *out));
static void MD2Print  P((unsigned char *, FILE *out));
static void fMD2BinPrint  P((unsigned char *, FILE *out));
static void bigShsDigest P((unsigned char *, int, BigInt));
static void fBigShsDigest P((FILE *, BigInt));

/* The next two functions are the MD5 message digest routines. */
#ifdef K_AND_R
static void
fBigMD5Digest(in, bigDigest)
  FILE *in;
  BigInt bigDigest;
#else
  static void fBigMD5Digest(FILE *in,
			    BigInt bigDigest)
#endif
{
	MD5_CTX *mdContext;
	int bytes;
	unsigned char data[16];
	unsigned char digest[16];
#ifdef DLLEXPORT
	HGLOBAL md5_handle = clib_malloc(sizeof(MD5_CTX));
	mdContext = (MD5_CTX *)GlobalLock(md5_handle);
	mdContext->md5_handle = md5_handle;
#else
	mdContext = (MD5_CTX *)clib_malloc(sizeof(MD5_CTX));
#endif
	MD5Init (mdContext);
	while ((bytes = fread ((char *)data, 1, 16, in)) != 0)
		MD5Update (mdContext, data, (unsigned)bytes);
	MD5Final (digest, mdContext);
	
	RSA_bufToBig(digest, 16, bigDigest);
}


/* This function returns a Bignum which represents a message
   digest for message.  This is called for a fixed length
   message.
   */
#ifdef K_AND_R
static void
bigMD5Digest(message, messageLength, bigDigest)
  unsigned char *message;
  int messageLength;
  BigInt bigDigest;
#else
  static void bigMD5Digest(unsigned char *message,
			   int messageLength,
			   BigInt bigDigest)
#endif
{
	MD5_CTX *mdContext;
	int chunks, i;
	unsigned char data[16];
	unsigned char digest[16];
	unsigned char *mp;
#ifdef DLLEXPORT
	HGLOBAL md5_handle = clib_malloc(sizeof(MD5_CTX));
	mdContext = (MD5_CTX *)GlobalLock(md5_handle);
	mdContext->md5_handle = md5_handle;
#else
	mdContext = (MD5_CTX *)clib_malloc(sizeof(MD5_CTX));
#endif
	
	mp = message;
	MD5Init (mdContext);
	chunks = messageLength/16;
	while (chunks--) {
		for (i=0; i<16; i++)
			data[i] = *mp++;
		MD5Update(mdContext, data, 16);
	}
	if (messageLength%16) {
		for (i=0; i < messageLength%16; i++)
			data[i] = *mp++;
		MD5Update(mdContext, data, (unsigned)messageLength%16);
	}
	MD5Final(digest, mdContext);
	RSA_bufToBig(digest, 16, bigDigest);
}



/* Prints message digest buffer in mdContext as 32 hexadecimal
   digits.  Order is from low-order byte to high-order byte of
   digest.  Each byte is printed with high-order hexadecimal
   digit first.
   */
#ifdef notdef
#ifdef K_AND_R
static
void MD5Print (mdContext, out)
  MD5_CTX *mdContext;
  FILE *out;
#else
  static void MD5Print (MD5_CTX *mdContext,
			FILE *out)
#endif
{
	int i;
	
	for (i = 0; i < 16; i++)
		fprintf (out, "%02x", mdContext->digest[i]);
}

#ifdef K_AND_R
static void
fMD5BinPrint (mdContext, out)
  MD5_CTX *mdContext;
  FILE *out;
#else
  static void fMD5BinPrint (MD5_CTX *mdContext,
			    FILE *out)
#endif
{
	int i;
	
	for (i = 0; i < 16; i++)
		fprintf (out, "%c", mdContext->digest[i]);
}
#endif
/* END OF MD5 STUFF */

/* MD4 utilities */

#ifdef K_AND_R
static void
fBigMD4Digest(in, bigDigest)
  FILE *in;
  BigInt bigDigest;
#else
  static void fBigMD4Digest( FILE *in,
			    BigInt bigDigest)
#endif
{
	MD4_CTX *mdContext;
	int bytes;
	unsigned char data[16];
#ifdef DLLEXPORT
	HGLOBAL md4_handle = clib_malloc(sizeof(MD4_CTX));
	mdContext = (MD4_CTX *)GlobalLock(md4_handle);
	mdContext->md4_handle = md4_handle;
#else
	mdContext = (MD4_CTX *)clib_malloc(sizeof(MD4_CTX));
#endif
	
	MD4Init (mdContext);
	while ((bytes = fread ((char *)data, 1, 16, in)) != 0)
		MD4Update (mdContext, data, (unsigned)bytes);
	MD4Final (mdContext);
	
	RSA_bufToBig(mdContext->digest, 16, bigDigest);
}


/* This function returns a Bignum which represents a message
   digest for message.  This is called for a fixed length
   message.
   */
#ifdef K_AND_R
static void
bigMD4Digest(message, messageLength, bigDigest)
  unsigned char *message;
  int messageLength;
  BigInt bigDigest;
#else
  static void bigMD4Digest(unsigned char *message,
			   int messageLength,
			   BigInt bigDigest)
#endif
{
	MD4_CTX *mdContext;
	int chunks, i;
	unsigned char data[16];
	unsigned char *mp;
#ifdef DLLEXPORT
	HGLOBAL md4_handle = clib_malloc(sizeof(MD4_CTX));
	mdContext = (MD4_CTX *)GlobalLock(md4_handle);
	mdContext->md4_handle = md4_handle;
#else
	mdContext = (MD4_CTX *)clib_malloc(sizeof(MD4_CTX));
#endif
	
	mp = message;
	MD4Init (mdContext);
	chunks = messageLength/16;
	while (chunks--) {
		for (i=0; i<16; i++)
			data[i] = *mp++;
		MD4Update(mdContext, data, 16);
	}
	if (messageLength%16) {
		for (i=0; i < messageLength%16; i++)
			data[i] = *mp++;
		MD4Update(mdContext, data, (unsigned)messageLength%16);
	}
	MD4Final(mdContext);
	RSA_bufToBig(mdContext->digest, 16, bigDigest);
}



/* Prints message digest buffer in mdContext as 32 hexadecimal
   digits.  Order is from low-order byte to high-order byte of
   digest.  Each byte is printed with high-order hexadecimal
   digit first.
   */
#ifdef K_AND_R
static
void MD4Print (mdContext, out)
  MD4_CTX *mdContext;
  FILE *out;
#else
  static void MD4Print (MD4_CTX *mdContext,
			FILE *out)
#endif
{
	int i;
	
	for (i = 0; i < 16; i++)
		fprintf (out, "%02x", mdContext->digest[i]);
}

#ifdef K_AND_R
static
void fMD4BinPrint (mdContext, out)
  MD4_CTX *mdContext;
  FILE *out;
#else
  static void fMD4BinPrint (MD4_CTX *mdContext,
			    FILE *out)
#endif
{
	int i;
	
	for (i = 0; i < 16; i++)
		fprintf (out, "%c", mdContext->digest[i]);
}

/* MD2 utilities */

#ifdef K_AND_R
static void
fBigMD2Digest(in, bigDigest)
  FILE *in;
  BigInt bigDigest;
#else
  static void fBigMD2Digest(FILE *in,
			    BigInt bigDigest)
#endif
{
	MD2_CTX *mdContext;
	int bytes;
	unsigned char data[16];
	unsigned char digest[16];
#ifdef DLLEXPORT
	HGLOBAL MD2_handle = clib_malloc(sizeof(MD2_CTX));
	mdContext = (MD2_CTX *)GlobalLock(MD2_handle);
	mdContext->md2_handle = MD2_handle;
#else
	mdContext = (MD2_CTX *)clib_malloc(sizeof(MD2_CTX));
#endif
	
	MD2Init (mdContext);
	while ((bytes = fread ((char *)data, 1, 16, in)) != 0)
		MD2Update (mdContext, data, (unsigned)bytes);
	MD2Final (digest, mdContext);
	
	RSA_bufToBig(digest, 16, bigDigest);
}


/* This function returns a Bignum which represents a message
   digest for message.  This is called for a fixed length
   message.
   */
#ifdef K_AND_R
static void
bigMD2Digest(message, messageLength, bigDigest)
  unsigned char *message;
  int messageLength;
  BigInt bigDigest;
#else
  static void bigMD2Digest(unsigned char *message,
			   int messageLength,
			   BigInt bigDigest)
#endif
{
	MD2_CTX *mdContext;
	int chunks, i;
	unsigned char data[16];
	unsigned char digest[16];
	unsigned char *mp;
#ifdef DLLEXPORT
	HGLOBAL md2_handle = clib_malloc(sizeof(MD2_CTX));
	mdContext = (MD2_CTX *)GlobalLock(md2_handle);
	mdContext->md2_handle = md2_handle;
#else
	mdContext = (MD2_CTX *)clib_malloc(sizeof(MD2_CTX));
#endif
	
	mp = message;
	MD2Init (mdContext);
	chunks = messageLength/16;
	while (chunks--) {
		for (i=0; i<16; i++)
			data[i] = *mp++;
		MD2Update(mdContext, data, 16);
	}
	if (messageLength%16) {
		for (i=0; i < messageLength%16; i++)
			data[i] = *mp++;
		MD2Update(mdContext, data, (unsigned)messageLength%16);
	}
	MD2Final(digest, mdContext);
	RSA_bufToBig(digest, 16, bigDigest);
}



/* Prints message digest buffer in mdContext as 32 hexadecimal
   digits.  Order is from low-order byte to high-order byte of
   digest.  Each byte is printed with high-order hexadecimal
   digit first.
   */
#ifdef K_AND_R
static
void MD2Print (digest, out)
  unsigned char *digest;
  FILE *out;
#else
  static void MD2Print (unsigned char *digest,
			FILE *out)
#endif
{
	int i;
	
	for (i = 0; i < 16; i++)
		fprintf (out, "%02x", digest[i]);
}

#ifdef K_AND_R
static
void fMD2BinPrint (digest, out)
  unsigned char *digest;
  FILE *out;
#else
  static void fMD2BinPrint (unsigned char *digest,
			    FILE *out)
#endif
{
	int i;
	
	for (i = 0; i < 16; i++)
		fprintf (out, "%c", digest[i]);
}

/* shs interface function -- NIST Secure Hash Std. */

#ifdef K_AND_R
static void
bigShsDigest(message, messageLength, md)
  unsigned char *message;
  int messageLength;
  BigInt md;
#else
  static void bigShsDigest(unsigned char *message,
			   int messageLength,
			   BigInt md)
#endif
{
	unsigned long *digest;
	int i;
	
	digest = (unsigned long *)shs(message, messageLength);
	shs(message, messageLength);
	GUARANTEE(md, 5);
	
	for (i=4; i>=0; i--) {
		NUM(md)[i] = *digest++;
	}
	LENGTH(md) = 5;
}

#ifdef K_AND_R
static void
fBigShsDigest(in, bigDigest)
  FILE *in;
  BigInt bigDigest;
#else
  static void fBigShsDigest(FILE *in,
			    BigInt bigDigest)
#endif
{
	int i;
	unsigned long *digest;
	
	digest = fShsDigest(in);
	GUARANTEE(bigDigest, 5);
	
	for (i=4; i>=0; i--) {
		NUM(bigDigest)[i] = *digest++;
	}
	LENGTH(bigDigest) = 5;
}



/* Functions included in CryptoLib */

#ifdef K_AND_R
_TYPE( void )
fBigMessageDigest(filename, bigDigest, type)
  char *filename;
  BigInt bigDigest;
  DigestType type;
#else
_TYPE( void ) fBigMessageDigest(char *filename,
				BigInt bigDigest,
				DigestType type)
#endif
{
	FILE *in = fopen(filename, "r");
	if (in == NULL)
		handle_exception(CRITICAL, "fBigMessageDigest: Can't open input file\n");

	if (type == SHS)
		fBigShsDigest(in, bigDigest);
	else if (type == MD5)
		fBigMD5Digest(in, bigDigest);
	else if (type == MD4)
		fBigMD4Digest(in, bigDigest);
	else if (type == MD2)
		fBigMD2Digest(in, bigDigest);
}

#ifdef K_AND_R
_TYPE( void )
bigMessageDigest(message, messageLength, md, type)
  unsigned char *message;
  int messageLength;
  BigInt md;
  DigestType type;
#else
_TYPE( void ) bigMessageDigest(unsigned char *message,
			       int messageLength,
			       BigInt md,
			       DigestType type)
#endif
{
	if (type == SHS)
		bigShsDigest(message, messageLength, md);
	else if (type == MD5)
		bigMD5Digest(message, messageLength, md);
	else if (type == MD4)
		bigMD4Digest(message, messageLength, md);
	else if (type == MD2)
		bigMD2Digest(message, messageLength, md);
}

#ifdef K_AND_R
_TYPE( int ) messageDigest(message, messageLength, md, mdsize, type)
  unsigned char *message;
  Ushort messageLength;
  unsigned char *md;
  Ushort mdsize;
  DigestType type;
#else
_TYPE( int ) messageDigest(unsigned char *message,
			  Ushort messageLength,
			  unsigned char *md,
			  Ushort mdsize,
			  DigestType type)
#endif
{
	int retval;
	BigInt big = bigInit(0);
	
	if (type == SHS) {
		bigShsDigest(message, messageLength, big);
		if (mdsize < 20)
			handle_exception(CRITICAL, "SHS Digest needs 20 bytes\n");
	}
	else if (type == MD5) {
		bigMD5Digest(message, (int)messageLength, big);
		if (mdsize < 16)
			handle_exception(CRITICAL, "MD5 Digest needs 16 bytes\n");
	}
	else if (type == MD4) {
		bigMD4Digest(message, (int)messageLength, big);
		if (mdsize < 16)
			handle_exception(CRITICAL, "MD4 Digest needs 16 bytes\n");
	}
	else if (type == MD2) {
		bigMD2Digest(message, (int)messageLength, big);
		if (mdsize < 16)
			handle_exception(CRITICAL, "MD2 Digest needs 16 bytes\n");
	}
	retval = bigBytes(big);
	bigToBuf(big, mdsize, md);
	freeBignum(big);
	
	return retval;
}
