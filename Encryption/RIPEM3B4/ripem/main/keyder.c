/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*
 *   keyder.c
 *  Routines to translate from R_RSA_{PUBLIC,PRIVATE}_KEY
 *  to ASN.1 DER encodings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "keyderpr.h"
#include "certder.h"
#include "derkeypr.h"
#include "p.h"

static unsigned int len_small_int P((unsigned int));
static void put_der_small_int P((unsigned char **, unsigned int));
static unsigned int len_relative_dn P((DistinguishedNameStruct *, int));
static unsigned int len_UTC P((void));
static void put_UTC P((unsigned char **, unsigned long));
static void put_der_attributevalueassertion
  P((unsigned char **, int, int, char *));
static int AttributeValueGreater P((char *, int, int, char *, int, int));
static void put_der_relativedistinguishedname
  P((unsigned char **, DistinguishedNameStruct *, int));
static unsigned int len_chainLensAllowed P((RIPEMInfo *));
static unsigned int len_crlEntries
  P((unsigned char *, unsigned char *, unsigned int));
static unsigned int len_crlEntry P((unsigned char *, unsigned int));
static unsigned int AttrTypePrefixSize P((int));
static unsigned char *AttrTypePrefixData P((int));

/* DER class/tag codes */
#define DER_INT   0x02
#define DER_BITSTRING 0x03
#define DER_OCTETSTRING 0x04
#define DER_NULL  0x05
#define DER_OBJID 0x06
#define DER_SEQ   0x30
#define DER_SET   0x31
#define DER_UTC   0x17

/* Alg ID - rsa - {2, 5, 8, 1, 1}*/
static unsigned char rsa_alg[] = { DER_OBJID, 4, 2*40+5, 0x08, 0x01, 0x01 };

/* rsaEncryption data structure, with algorithm {1 2 840 113549 1 1 1} and
 * NULL parameter
 */
static unsigned char rsaEnc_alg[] = { DER_SEQ, 13, DER_OBJID, 9,
  1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  DER_NULL, 0 };

/* Version = 0 */
static unsigned char version[] = { DER_INT, 1, 0 };


/* Return the number of bytes taken for the DER-encoding of the data
 * structure of specified length.  This includes the bytes themselves,
 * the 1 byte for the DER class and tag, and the variable number of bytes
 * for the length encoding.
 */
unsigned int der_len (len)
unsigned int len;
{
  if (len < 0x80)
    return 2+len;
  if (len < 0x100)
    return 3+len;
  if ((long unsigned int)len < 0x10000)
    return 4+len;
  if ((long unsigned int)len < 0x1000000)
    return 5+len;
  return 6+len;
}


/* Return the number of bytes for the DER-encoding of the specified small
 * signed integer.  Do not include the type byte and the length bytes.
 */
static unsigned int
len_small_int (n)
unsigned int n;
{
  if ((((n&0xff)^0x80)-0x80) == n)
    return 1;
  else if ((((n&0xffff)^0x8000)-0x8000) == n)
    return 2;
  else if ((((n&0xffffffL)^0x800000L)-0x800000L) == n)
    return 3;
  else
    return 4;
}
 
/* Return the number of bytes for the DER-encoding of the specified large
 * unsigned integer.  Do not include the type byte and the length bytes.
 */
unsigned int len_large_unsigned (n, nsize)
unsigned char *n;
unsigned int nsize;
{
  unsigned int i;
    
  for (i=0; i<nsize && n[i]==0; ++i)
    ; /* Intentionally blank */
  if (i == nsize)
    return 1; /* Value is 0 */
  if (n[i]&0x80)
    return nsize-i + 1; /* Need an extra byte so doesn't sign extend */
  else
    return nsize-i;
}


/* Output DER encoding for length */
void put_der_len (p, len)
unsigned char **p;
unsigned int len;
{
  if (len < 0x80) {
    *(*p)++ = len;
  } else if (len < 0x100) {
    *(*p)++ = 0x81;
    *(*p)++ = len;
  } else if ((long unsigned int) len < 0x10000L) {
    *(*p)++ = 0x82;
    *(*p)++ = (len>>8);
    *(*p)++ = len&0xff;
  } else if ((long unsigned int) len < 0x1000000L) {
    *(*p)++ = 0x83;
    *(*p)++ = (len>>16)&0xff;
    *(*p)++ = (len>>8)&0xff;
    *(*p)++ = len&0xff;
  } else {
    *(*p)++ = 0x84;
    *(*p)++ = (len>>24)&0xff;
    *(*p)++ = (len>>16)&0xff;
    *(*p)++ = (len>>8)&0xff;
    *(*p)++ = len&0xff;
  }
}


void put_der_data (p, dat, len)
unsigned char **p;
unsigned char *dat;
unsigned int len;
{
  while (len--) {
    *(*p)++ = *dat++;
  }
}


static void
put_der_small_int (p, n)
unsigned char **p;
unsigned int n;
{
  unsigned int len;

  *(*p)++ = DER_INT;
  len = len_small_int(n);
  put_der_len (p, len);
  while (len--)
    *(*p)++ = (n >> (len*8)) & 0xff;
}


/* Output the DER encoding for the large unsigned integer n, which is in
 * an array of size nsize, but whose length (from len_large_unsigned) is
 * len.
 */
void put_der_large_unsigned (p, n, nsize, len)
unsigned char **p;
unsigned char *n;
unsigned int nsize;
unsigned int len;
{
  *(*p)++ = DER_INT;
  put_der_len (p, len);
  
  /* Catch the boundary condition in which the integer entirely fills
   * the output buffer, and has the high bit set.
   * In this case, we put out an explicit zero and compensate for this
   * zero, which was allowed for in len_large_unsigned.
   */
  if(len==nsize+1 && (0x80 & *n)) {
    *(*p)++ = 0;
    len--;
  }
  /* Skip past leading zeros. */
  n += nsize-len;
  while (len--)
    *(*p)++ = *n++;
}



/*
 *  Beginning of public entry points for this module
 */



/* function  int PubKeyToDERLen (key)
 *
 *  Return the length in bytes of the DER translation of the RSA
 *  public key given, including the tag and length bytes.
 */
unsigned int
PubKeyToDERLen (key)
R_RSA_PUBLIC_KEY *key;
{
  unsigned int alglen, modexplen, keybitlen, keylen, tlen;
  unsigned int modlen, explen;
  unsigned int bits = key->bits;
  
  alglen = sizeof(rsa_alg) + der_len(len_small_int(bits));
  modlen = len_large_unsigned(key->modulus,sizeof(key->modulus));
  explen = len_large_unsigned(key->exponent,sizeof(key->exponent));
  modexplen = der_len(modlen) + der_len(explen);
  keybitlen = der_len (modexplen);
  keylen = 1 + keybitlen; /* Padding byte for bit string */
  tlen = der_len(alglen) + der_len(keylen);
  return der_len(tlen);
}

/* Translate RSA public key using Distinguished Encoding Rules into
     a byte string.  Return the string in der and the length of the
     string in derlen.
   The der buffer must be at least PubKeyToDERLen (key) in size.
   Return 0 on success, nonzero on failure.
 */
int PubKeyToDER (key, der, derlen)
R_RSA_PUBLIC_KEY *key;
unsigned char *der;
unsigned int *derlen;
{
  unsigned int alglen, modexplen, keybitlen, keylen, tlen;
  unsigned int modlen, explen;
  unsigned int bits = key->bits;

  alglen = sizeof(rsa_alg) + der_len(len_small_int(bits));
  modlen = len_large_unsigned(key->modulus,(unsigned int)sizeof(key->modulus));
  explen =
    len_large_unsigned(key->exponent,(unsigned int)sizeof(key->exponent));
  modexplen = der_len(modlen) + der_len(explen);
  keybitlen = der_len (modexplen);
  keylen = 1 + keybitlen; /* Padding byte for bit string */
  tlen = der_len(alglen) + der_len(keylen);
  *derlen = der_len(tlen);
  *der++ = DER_SEQ;
  put_der_len (&der, tlen);
  /* Now output algorithm info */
  *der++ = DER_SEQ;
  put_der_len (&der, alglen);
  put_der_data (&der, rsa_alg, (unsigned int)sizeof(rsa_alg));
  put_der_small_int(&der, bits);
  *der++ = DER_BITSTRING;
  put_der_len (&der, keylen);
  *der++ = 0;     /* Padding for key bits */
  *der++ = DER_SEQ;
  put_der_len (&der, modexplen);
  put_der_large_unsigned
    (&der, key->modulus, (unsigned int)sizeof(key->modulus), modlen);
  put_der_large_unsigned
    (&der, key->exponent, (unsigned int)sizeof(key->exponent), explen);
  return 0;
}

/*   int privkeytoderlen (key)
 *  Return the length in bytes of the DER translation of the RSA
 *  public key given.
 */
unsigned int
PrivKeyToDERLen (key)
R_RSA_PRIVATE_KEY *key;
{
  unsigned int alglen, modlen, pexplen, explen, p1len, p2len;
  unsigned int pexp1len, pexp2len, coeflen, pklen, tlen;

  alglen = sizeof (rsaEnc_alg) + sizeof (version);
  modlen = len_large_unsigned(key->modulus,(unsigned int)sizeof(key->modulus));
  pexplen = len_large_unsigned
    (key->publicExponent, (unsigned int)sizeof(key->publicExponent));
  explen = len_large_unsigned
    (key->exponent,(unsigned int)sizeof(key->exponent));
  p1len = len_large_unsigned
    (key->prime[0],(unsigned int)sizeof(key->prime[0]));
  p2len = len_large_unsigned
    (key->prime[1],(unsigned int)sizeof(key->prime[1]));
  pexp1len = len_large_unsigned
    (key->primeExponent[0], (unsigned int)sizeof(key->primeExponent[0]));
  pexp2len = len_large_unsigned
    (key->primeExponent[1], (unsigned int)sizeof(key->primeExponent[1]));
  coeflen = len_large_unsigned
    (key->coefficient, (unsigned int)sizeof(key->coefficient));
  pklen = sizeof(version) + der_len(modlen) + der_len(pexplen) +
    der_len(explen) + der_len(p1len) + der_len(p2len) +
    der_len(pexp1len) + der_len(pexp2len) + der_len(coeflen);
  tlen = alglen + der_len(der_len(pklen));
  return der_len(tlen);
}


/*   int privkeytoder (key, der, derlen)
 *  Translate RSA private key using Distinguished Encoding Rules into
 *  a byte string.  Return the string in der and the length of the
 *  string in derlen.
 */
void PrivKeyToDER (key, der, derlen)
R_RSA_PRIVATE_KEY *key;
unsigned char *der;
unsigned int *derlen;
{
  unsigned int alglen, modlen, pexplen, explen, p1len, p2len;
  unsigned int pexp1len, pexp2len, coeflen, pklen, tlen;
  
  alglen = sizeof (rsaEnc_alg) + sizeof (version);
  modlen = len_large_unsigned(key->modulus,(unsigned int)sizeof(key->modulus));
  pexplen = len_large_unsigned
    (key->publicExponent, (unsigned int)sizeof(key->publicExponent));
  explen = len_large_unsigned
    (key->exponent,(unsigned int)sizeof(key->exponent));
  p1len = len_large_unsigned
    (key->prime[0],(unsigned int)sizeof(key->prime[0]));
  p2len = len_large_unsigned
    (key->prime[1],(unsigned int)sizeof(key->prime[1]));
  pexp1len = len_large_unsigned
    (key->primeExponent[0], (unsigned int)sizeof(key->primeExponent[0]));
  pexp2len = len_large_unsigned
    (key->primeExponent[1], (unsigned int)sizeof(key->primeExponent[1]));
  coeflen = len_large_unsigned
    (key->coefficient, (unsigned int)sizeof(key->coefficient));
  pklen = sizeof(version) + der_len(modlen) + der_len(pexplen) +
    der_len(explen) + der_len(p1len) + der_len(p2len) +
    der_len(pexp1len) + der_len(pexp2len) + der_len(coeflen);
  tlen = alglen + der_len(der_len(pklen));
  *derlen = der_len(tlen);
  *der++ = DER_SEQ;
  put_der_len (&der, tlen);
  put_der_data (&der, version, (unsigned int)sizeof(version));
  put_der_data (&der, rsaEnc_alg, (unsigned int)sizeof(rsaEnc_alg));
  *der++ = DER_OCTETSTRING;
  put_der_len (&der, der_len(pklen));
  /* Now the RSAPrivateKey */
  *der++ = DER_SEQ;
  put_der_len (&der, pklen);
  put_der_data (&der, version, (unsigned int)sizeof(version));
  put_der_large_unsigned
    (&der, key->modulus, (unsigned int)sizeof(key->modulus), modlen);
  put_der_large_unsigned
    (&der, key->publicExponent, (unsigned int)sizeof(key->publicExponent),
     pexplen);
  put_der_large_unsigned
    (&der, key->exponent, (unsigned int)sizeof(key->exponent), explen);
  put_der_large_unsigned
    (&der, key->prime[0], (unsigned int)sizeof(key->prime[0]), p1len);
  put_der_large_unsigned
    (&der, key->prime[1], (unsigned int)sizeof(key->prime[1]), p2len);
  put_der_large_unsigned
    (&der, key->primeExponent[0], (unsigned int)sizeof(key->primeExponent[0]),
     pexp1len);
  put_der_large_unsigned
    (&der, key->primeExponent[1], (unsigned int)sizeof(key->primeExponent[1]),
     pexp2len);
  put_der_large_unsigned
    (&der, key->coefficient, (unsigned int)sizeof(key->coefficient), coeflen);
}

/* Data structure specifying "algorithm=pbeWithMD5AndDES-CBC"
 * for encoding of encrypted private key.
 * Decodes to OBJECT_ID = 1 2 840 113549 1 5 3
 */
static unsigned char pbeWithMD5AndDES_CBC[] = { DER_OBJID, 9,
  1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03 };


/*--- function EncryptedPrivKeyToDERLen ---------------------------
 *
 *  Return the length in bytes of the DER translation of the
 *  encrypted public key given.
 */
unsigned int
EncryptedPrivKeyToDERLen (iterationCount,encLen)
unsigned int iterationCount;
unsigned int encLen;
{
  unsigned int alg_len, salt_len, iter_len, param_len;
  unsigned int octet_len, enc_seq_len, total_len;

  alg_len = sizeof(pbeWithMD5AndDES_CBC);

  salt_len = der_len(8);
  iter_len = der_len(len_small_int(iterationCount));
  param_len = der_len(salt_len+iter_len);

  octet_len = der_len(encLen);

  enc_seq_len = der_len(alg_len+param_len);
  
  total_len = der_len(enc_seq_len+octet_len);
  return der_len(total_len);
}



/*--- function EncryptedPrivKeyToDER ---------------------------
 *
 * Encode an encrypted RSA private key into DER form.
 *
 * Encrypted key encoding looks like this:
 *
 *  Sequence
 *  Sequence                           # encryption algorithm
 *      Object ID 1 2 840 113549 1 5 3  # algorithm MD5AndDES-CBC
 *      Sequence                        # algorithm parameters:
 *        Octet string, 8 bytes long   # salt
 *         Integer                      # iteration count
 *    Octet string                # encrypted data
 */
void EncryptedPrivKeyToDER (salt,iterationCount,encBytes,encLen, der, derlen)
unsigned char *salt;
unsigned int iterationCount;
unsigned char *encBytes;
unsigned int encLen;
unsigned char *der;
unsigned int *derlen;
{
  unsigned int alg_len, salt_len, iter_len, param_len;
  unsigned int octet_len, enc_seq_len, tlen;
  
  alg_len = sizeof (pbeWithMD5AndDES_CBC);
  
  salt_len = der_len(SALT_SIZE);
  iter_len = der_len(len_small_int(iterationCount));
  param_len = der_len(salt_len+iter_len);
  
  octet_len = der_len(encLen);
  
  enc_seq_len = der_len(alg_len+param_len);
  
  tlen = enc_seq_len+octet_len;
  
  
  /* Output highest level sequence indicator */
  *derlen = der_len(tlen);
  *der++ = DER_SEQ;
  put_der_len (&der, tlen);

  /* Output sequence indicator for encryption Algorithm (which
   * includes algorithm + parameters.
   */
  *der++ = DER_SEQ;
  put_der_len(&der,alg_len+param_len);

  /* Output encryption algorithm */
  put_der_data (&der, pbeWithMD5AndDES_CBC, alg_len );

   /* Output sequence for parameters */
  *der++ = DER_SEQ;
  put_der_len(&der,salt_len + iter_len);

  /* Output salt (first parameter) */
  *der++ = DER_OCTETSTRING;
  put_der_len(&der,SALT_SIZE);
  put_der_data (&der, salt,SALT_SIZE);

  /* Output iteration count (second parameter) */
  put_der_small_int(&der,iterationCount);

  /* Output the encrypted key */
  *der++ = DER_OCTETSTRING;
  put_der_len(&der,encLen);
  put_der_data(&der,encBytes,encLen);
}

/* Extensions for certificate encoding follow.
 */

#define LEN_OF_MONTH(year, month) \
  ((((year) % 4) || (month) != 2) ? MONTH_LENS[((month)-1)] : 29)

#define SECONDS_IN_DAY ((UINT4)3600 * (UINT4)24)

static unsigned int MONTH_LENS[] =
  {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* Data structure specifying "algorithm=md2WithRSAEncryption" followed by
     NULL param
   iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) pkcs-1(1) 2
   Decodes to OBJECT_ID = 1 2 840 113549 1 1 2
 */
static unsigned char md2WithRSAEncryption[] =
  { DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02,
    DER_NULL, 0 };

/* Data structure specifying "algorithm=md5WithRSAEncryption" followed by
     NULL param
   iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) pkcs-1(1) 4
   Decodes to OBJECT_ID = 1 2 840 113549 1 1 4
 */
static unsigned char md5WithRSAEncryption[] =
  { DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04,
    DER_NULL, 0 };

/* Data structure specifying "algorithm=sha-1WithRSAEncryption" followed by
     NULL param
   iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) pkcs-1(1) 5
   Decodes to OBJECT_ID = 1 2 840 113549 1 1 5
 */
static unsigned char sha1WithRSAEncryption[] =
  { DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
    DER_NULL, 0 };

/* Data structure for MD2 digest algorithm. */
static unsigned char MD2_ALGORITHM_ID[] =
  { DER_OBJID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x03,
    DER_NULL, 0 };

/* Data structure for MD5 digest algorithm. */
static unsigned char MD5_ALGORITHM_ID[] =
  { DER_OBJID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
    DER_NULL, 0 };

/* Data structure for SHA1 digest algorithm. */
static unsigned char SHA1_ALGORITHM_ID[] = {
  DER_OBJID, 5, 0x2b, 0x0e, 0x03, 0x02, 26,
    DER_NULL, 0
};

/* Attribute type ID - joint-iso-ccittt(2) ds(5) 4 followed by attrtype */
static unsigned char X520_ATTR_TYPE_PREFIX[] = { DER_OBJID, 3, 2*40+5, 4 };

/* Attribute object ID for PKCS #9 to be followed by attrtype byte */
static unsigned char PKCS9_ATTR_TYPE_PREFIX[] =
  {DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9 };

static unsigned int len_relative_dn (dn, rdn)
DistinguishedNameStruct *dn;
int rdn;
{
  int sequencelen = 0,j;

  if(dn->RDNIndexStart[rdn] == -1)
    return 0;
  
  for(j=dn->RDNIndexStart[rdn];j<MAX_AVA;j++) {
    if(dn->AVATypes[j] == -1 || j>dn->RDNIndexEnd[rdn])
      break;
    else {
      int namelen = der_len(strlen (dn->AVAValues[j]));
      sequencelen += der_len
        (namelen + AttrTypePrefixSize ((int)dn->AVATypes[j]) + 1);
    }
  }
  
  if(sequencelen)
    return der_len(sequencelen);
  else
    return 0;
}


/* length without outer sequence */
unsigned int len_distinguishedname (dn)
DistinguishedNameStruct *dn;
{ 
  int i;
  int lenrel = 0;
  
  for(i=0;i<MAX_RDN;i++)
    lenrel += len_relative_dn(dn,i);
    
  return lenrel;
}


/* Length of an encoded UTC time including tag and length octets.
   always use YYMMDDhhmmssZ format.
 */
static unsigned int len_UTC ()
{
  return (der_len (13));
}

/* time is seconds since 1970.  Also, if the time is from 2000 to 2049, this
     encodes the year as 00 to 49.
 */
static void put_UTC (der, time)
unsigned char **der;
unsigned long time;
{
  int year, month, day, hour, minute, second;
  unsigned long tempTime;
  
  /* Count up seconds in the years starting from 1970 to bring the time
       down to the number of seconds in a year. */
  year = 70;
  while (time >= 
         (tempTime = year % 4 ?
          (SECONDS_IN_DAY * (UINT4)365):(SECONDS_IN_DAY * (UINT4)366))) {
    time -= tempTime;
    year++;
  }

  /* Count up seconds in the months starting from 1 to bring the time
       down to the number of seconds in a month. */
  month = 1;
  while (time >=
         (tempTime = SECONDS_IN_DAY * (UINT4)LEN_OF_MONTH (year, month))) {
    time -= tempTime;
    month++;
  }
  
  day = (int)(time / SECONDS_IN_DAY) + 1;
  time -= (UINT4)(day - 1) * SECONDS_IN_DAY;

  hour = (int)(time / ((UINT4)3600));
  time -= (UINT4)hour * (UINT4)3600;

  minute = (int)(time / (UINT4)60);
  time -= (UINT4)minute * (UINT4)60;

  second = (int)time;

  if (year >= 100) {
    /* Adjust year 2000 or more to encode as 00 and greater.
       If the year is greater than 2049, we can't encode it, so
       cap at 2049.  (Will use GeneralizedTime for this.) */
    if (year > 149)
      year = 149;

    year -= 100;
  }
  
  *(*der)++ = DER_UTC;
  put_der_len (der, 13);
  *(*der)++ = (year / 10) + '0';
  *(*der)++ = (year % 10) + '0';
  *(*der)++ = (month / 10) + '0';
  *(*der)++ = (month % 10) + '0';
  *(*der)++ = (day / 10) + '0';
  *(*der)++ = (day % 10) + '0';
  *(*der)++ = (hour / 10) + '0';
  *(*der)++ = (hour % 10) + '0';
  *(*der)++ = (minute / 10) + '0';
  *(*der)++ = (minute % 10) + '0';
  *(*der)++ = (second / 10) + '0';
  *(*der)++ = (second % 10) + '0';
  *(*der)++ = 'Z';
}

/* Returns length of certificate but without outermost tag and length octets.
 */
unsigned int len_certificate (cert, len_pub_key)
CertificateStruct *cert;
int len_pub_key;
{
  /* Note md5WithRSAEncryption is the same size so it will still work
       if we use md2WithRSAEncryption or sha-1WithRSAEncryption */
  return (der_len
          (len_large_unsigned
           (cert->serialNumber, sizeof(cert->serialNumber))) +
          der_len(sizeof(md2WithRSAEncryption)) +
          der_len(len_distinguishedname(&cert->issuer)) +
          der_len(2*len_UTC()) +
          der_len(len_distinguishedname(&cert->subject)) +
          len_pub_key);
}

/* Returns length of CRL but without outermost tag and length octets.
   The arguments are interpreted as in CRLToDer.
   This assumes crlentriesDER is either NULL or a valid encoding as the
     result of DERToCRL.
 */
unsigned int len_crl (crlStruct, crlEntriesDER, serialNumber, serialNumberLen)
CRLStruct *crlStruct;
unsigned char *crlEntriesDER;
unsigned char *serialNumber;
unsigned int serialNumberLen;
{
  unsigned int entriesLen;

  /* Get the length of the entire sequence of CRL entries. If there
       are none, then omit. */
  if (crlEntriesDER == (unsigned char *)NULL &&
      serialNumber == (unsigned char *)NULL)
    entriesLen = 0;
  else
    entriesLen = der_len
      (len_crlEntries (crlEntriesDER, serialNumber, serialNumberLen));

  /* Note md5WithRSAEncryption is the same size so it will still work
       if we use md2WithRSAEncryption or sha-1WithRSAEncryption */
  return (der_len (sizeof (md2WithRSAEncryption)) +
          der_len (len_distinguishedname (&crlStruct->issuer)) +
          (2 * len_UTC ()) + entriesLen);
}

/* Wraps signature info around derbytes and modifies derlen to new derlen.
   derbytes buffer must be at least *derlen (as input) plus
     MAX_UNSIGNED_TO_SIGNED_DELTA.
   signature should NOT be ASCII recoded.
   If useSignatureAlgorithmID is TRUE, digestAlgorithm is used to choose
     md2WithRSAEncryption vs. md5WithRSAEncryption vs. sha-1WithRSAEncryption.
     If useSignatureAlgorithmID is FALSE, the digest algorithm ID for
     digestAlgorithm is written.
 */
void DerUnsignedToDerSigned
  (derbytes, derlen, signature, signaturelen, digestAlgorithm,
   useSignatureAlgorithmID)
unsigned char *derbytes;
unsigned int *derlen;
unsigned char *signature;
unsigned int signaturelen;
int digestAlgorithm;
BOOL useSignatureAlgorithmID;
{ 
  unsigned char *p = derbytes + *derlen;
  int signed_len;
  
  /* add signature info. */
  
  *p++ = DER_SEQ;

  if (useSignatureAlgorithmID) {
    if (digestAlgorithm == DA_MD2) {
      put_der_len(&p,sizeof(md2WithRSAEncryption));
      put_der_data (&p, md2WithRSAEncryption, sizeof(md2WithRSAEncryption));
    }
    else if (digestAlgorithm == DA_SHA1) {
      put_der_len(&p,sizeof(sha1WithRSAEncryption));
      put_der_data (&p, sha1WithRSAEncryption, sizeof(sha1WithRSAEncryption));
    }
    else {
      /* Assume MD5 */
      put_der_len(&p,sizeof(md5WithRSAEncryption));
      put_der_data (&p, md5WithRSAEncryption, sizeof(md5WithRSAEncryption));
    }
  }
  else {
    /* Write the actual digest algorithm ID (not signature algorithm ID).
     */
    if (digestAlgorithm == DA_MD2) {
      put_der_len (&p, sizeof (MD2_ALGORITHM_ID));
      put_der_data (&p, MD2_ALGORITHM_ID, sizeof (MD2_ALGORITHM_ID));
    }
    else if (digestAlgorithm == DA_SHA1) {
      put_der_len (&p, sizeof (SHA1_ALGORITHM_ID));
      put_der_data (&p, SHA1_ALGORITHM_ID, sizeof (SHA1_ALGORITHM_ID));
    }
    else {
      /* Assume MD5 */
      put_der_len (&p, sizeof (MD5_ALGORITHM_ID));
      put_der_data (&p, MD5_ALGORITHM_ID, sizeof (MD5_ALGORITHM_ID));
    }
  }
  
  *p++ = DER_BITSTRING;
  put_der_len(&p,signaturelen+1);
  *p++ = 0;

  put_der_data (&p, signature, signaturelen);

  signed_len = p - derbytes;
  *derlen = der_len(signed_len);

  /* add initial SEQ & len by moving der endcoding over.
   */
  {
    int i;
    unsigned char *from, *to;

    from = derbytes + signed_len;
    to = from + (der_len (signed_len) - signed_len);
    for (i = 0; i < signed_len; ++i)
      *(--to) = *(--from);
  }
  *derbytes++ = DER_SEQ;

  put_der_len(&derbytes,signed_len);
}
    
/* Encode the cert into the der and return the length in derlen.
   This encodes the inner certificate without the signature.
   Right now, this ignores the version, assuming it is 1.
   The der buffer must be at least
     len_certificate (cert, PubKeyToDERLen (&cert->publicKey)) + 4.
 */     
void CertificateToDer (cert, der, derlen)
CertificateStruct *cert;
unsigned char *der;
unsigned int *derlen;
{
  unsigned char *origder = der;
  unsigned int pubkeyderlen;

  *derlen = 0;
  
  *der++ = DER_SEQ;
  put_der_len
    (&der, len_certificate (cert, PubKeyToDERLen (&cert->publicKey)));

  /* serial number */
  put_der_large_unsigned
    (&der, cert->serialNumber, (unsigned int)sizeof(cert->serialNumber),
     len_large_unsigned(cert->serialNumber,sizeof(cert->serialNumber)));

  /* Algorithm identifier */
  *der++ = DER_SEQ;
  if (cert->digestAlgorithm == DA_MD2) {
    put_der_len (&der, sizeof(md2WithRSAEncryption));
    put_der_data
      (&der, md2WithRSAEncryption, (unsigned int)sizeof(md2WithRSAEncryption));
  }
  else if (cert->digestAlgorithm == DA_SHA1) {
    put_der_len (&der, sizeof(sha1WithRSAEncryption));
    put_der_data
      (&der,sha1WithRSAEncryption,(unsigned int)sizeof(sha1WithRSAEncryption));
  }
  else {
    /* Assume md5-with-rsa */
    put_der_len (&der, sizeof(md5WithRSAEncryption));
    put_der_data
      (&der, md5WithRSAEncryption, (unsigned int)sizeof(md5WithRSAEncryption));
  }
  
  /* issuer */
  DistinguishedNameToDER(&cert->issuer,&der);
  
  /* validity */
  *der++ = DER_SEQ;
  put_der_len (&der, 2*len_UTC());
  put_UTC(&der,cert->notBefore);
  put_UTC(&der,cert->notAfter);
  
  /* subject */
  DistinguishedNameToDER(&cert->subject,&der);

  /* public key */
  PubKeyToDER (&cert->publicKey, der, &pubkeyderlen);
  der += pubkeyderlen;

  *derlen = der - origder;
}

/* Encode the CRL into the der and return the length in derlen.
   This encodes the inner CRL without the signature.
   crlEntriesDER is the result of the last decode from DERToCRL.  If
     it is NULL, then there were no CRL entries.  It can also be passed
     as NULL when creating a new CRL.
   If serialNumber is not NULL then it gives the serial number of a new
     revocation entry to be added with the given serialNumberLen and
     revocationTime.  If crlEntriesDER is NULL, then this becomes the
     only entry in the CRL.  If the serial number already exists in the
     CRL, no new entry is added.  If serialNumber is NULL, crlEntriesDER
     is kept as is and serialNumberLen and revocationTime are ignored.
   The der buffer must be at least
     len_crl (crlStruct, crlEntriesDER, serialNumber, serialNumberLen) + 4.
 */     
void CRLToDer
  (crlStruct, crlEntriesDER, serialNumber, serialNumberLen, revocationTime,
   der, derlen)
CRLStruct *crlStruct;
unsigned char *crlEntriesDER;
unsigned char *serialNumber;
unsigned int serialNumberLen;
UINT4 revocationTime;
unsigned char *der;
unsigned int *derlen;
{
  unsigned char *saveDER = der, *entriesPointer;
  UINT2 tag;
  unsigned int len;

  *derlen = 0;
  
  *der++ = DER_SEQ;
  put_der_len
    (&der, len_crl (crlStruct, crlEntriesDER, serialNumber, serialNumberLen));

  /* Algorithm identifier */
  *der++ = DER_SEQ;
  if (crlStruct->digestAlgorithm == DA_MD2) {
    put_der_len (&der, sizeof (md2WithRSAEncryption));
    put_der_data (&der, md2WithRSAEncryption, sizeof (md2WithRSAEncryption));
  }
  else if (crlStruct->digestAlgorithm == DA_SHA1) {
    put_der_len (&der, sizeof (sha1WithRSAEncryption));
    put_der_data (&der, sha1WithRSAEncryption, sizeof (sha1WithRSAEncryption));
  }
  else {
    /* Assume md5-with-rsa */
    put_der_len (&der, sizeof (md5WithRSAEncryption));
    put_der_data (&der, md5WithRSAEncryption, sizeof (md5WithRSAEncryption));
  }
  
  /* issuer */
  DistinguishedNameToDER (&crlStruct->issuer, &der);
  
  /* last and next update */
  put_UTC (&der, crlStruct->lastUpdate);
  put_UTC (&der, crlStruct->nextUpdate);
  
  if (crlEntriesDER != (unsigned char *)NULL ||
      serialNumber != (unsigned char *)NULL) {
    /* There is at least one CRL entry to encode. */

    *der++ = DER_SEQ;
    put_der_len
      (&der, len_crlEntries (crlEntriesDER, serialNumber, serialNumberLen));
    
    if (crlEntriesDER != (unsigned char *)NULL) {
      /* Set len and entriesPointer to the crlEntries content without the tag
           and length octets.  Assume it is encoded correctly. */
      entriesPointer = crlEntriesDER;
      gettaglen (&tag, &len, &entriesPointer);

      /* Copy the crlEntries content without the tag and length octets. */
      put_der_data (&der, entriesPointer, len);
    }

    if (serialNumber != (unsigned char *)NULL) {
      /* Add the new revocation entry.
       */
      *der++ = DER_SEQ;
      put_der_len (&der, len_crlEntry (serialNumber, serialNumberLen));

      /* serial number */
      put_der_large_unsigned
        (&der, serialNumber, serialNumberLen,
         len_large_unsigned (serialNumber, serialNumberLen));
      /* revocation time */
      put_UTC (&der, revocationTime);
    }
  }

  *derlen = der - saveDER;
}

/* value is a C string.
 */
static void put_der_attributevalueassertion (der, attr, tag, value)
unsigned char **der;
int attr;
int tag;
char *value;
{
  unsigned int valueLen = strlen (value);
  
  *(*der)++ = DER_SEQ;
  put_der_len (der, AttrTypePrefixSize (attr) + 1 + der_len(valueLen));
  put_der_data
    (der, AttrTypePrefixData (attr), AttrTypePrefixSize (attr));
  *(*der)++ = (unsigned char)attr;

  *(*der)++ = tag;

  put_der_len(der, valueLen);
  R_memcpy ((POINTER)*der, (POINTER)value, valueLen);
  (*der) += valueLen;
}

/* Returns TRUE if DER encoding of attr/value a > that of b,
   valuea and valueb are C strings.
 */
static int AttributeValueGreater (valuea, attra, taga, valueb, attrb, tagb)
char *valuea;
int attra;
int taga;
char *valueb;
int attrb;
int tagb;
{
  unsigned char a[MAX_NAME_LENGTH+30];
  unsigned char b[MAX_NAME_LENGTH+30];
  unsigned char *ap = a,*bp = b;
  int i = sizeof (a);

  /* Pre-zeroize buffers. */
  R_memset ((POINTER)a, 0, sizeof (a));  
  R_memset ((POINTER)b, 0, sizeof (b));
  
  put_der_attributevalueassertion (&ap, attra, taga, valuea);
  put_der_attributevalueassertion (&bp, attrb, tagb, valueb);
  
  ap = a;
  bp = b;
  
  while(--i >= 0) {
    if(*ap++ > *bp++)
      return TRUE;
  }

  return FALSE;
}

/* Warning -- dn may be changed by swaping AVAs in same RDN.
   Assumes rdn not empty.
 */
static void put_der_relativedistinguishedname (der, dn, rdn)
unsigned char **der;
DistinguishedNameStruct *dn;
int rdn;
{
  int j,sequencelen = 0,max,min;
  int sorted;
  
  min = dn->RDNIndexStart[rdn];
  max = dn->RDNIndexEnd[rdn];

  /* make sure everything is sorted. */
  /* DER encoding of SETs requires lexicographic ordering of DER encodings
       of ea. item!.*/
  do {
    sorted = TRUE;
    for(j=min;j<=(max-1);j++) {
      if(AttributeValueGreater
         (dn->AVAValues[j],(int)dn->AVATypes[j],dn->AVATag[j],
          dn->AVAValues[j+1],(int)dn->AVATypes[j+1],dn->AVATag[j+1])) {
        unsigned char temp[sizeof (dn->AVAValues[0])];
        short type = dn->AVATypes[j];
        dn->AVATypes[j] = dn->AVATypes[j+1];
        dn->AVATypes[j+1] = type;
        
        R_memcpy((POINTER)temp,(POINTER)dn->AVAValues[j],sizeof (temp));
        R_memcpy
          ((POINTER)dn->AVAValues[j],(POINTER)dn->AVAValues[j+1],
           sizeof (temp));
        R_memcpy((POINTER)dn->AVAValues[j+1],(POINTER)temp,sizeof (temp));
        sorted = FALSE;
      }
    }
  } while(!sorted);
  
  for(j=min;j<=max;j++) {
    int namelen = der_len(strlen (dn->AVAValues[j]));
    sequencelen += der_len
      (namelen + AttrTypePrefixSize ((int)dn->AVATypes[j]) + 1);
  }

  if(sequencelen) {
    *(*der)++ = DER_SET;
    put_der_len (der, sequencelen);

    for(j=min;j<=max;j++) {
      put_der_attributevalueassertion
        (der, (int)dn->AVATypes[j], dn->AVATag[j], dn->AVAValues[j]);
    }
  }
}


/* Encode the distingished name and update der.
   The der buffer must be at least len_distinguishedname (dn) + 4.
   This may modify the name if AVAs within an RDN must be reordered.
 */     
void DistinguishedNameToDER (dn, der)
DistinguishedNameStruct *dn;
unsigned char **der;
{
  int i;

  *(*der)++ = DER_SEQ;
    put_der_len (der, len_distinguishedname(dn));

  for(i=0;i<MAX_RDN;i++)
    if(dn->RDNIndexStart[i] != -1)
      put_der_relativedistinguishedname(der,dn,i);
}

/* Returns length of RIPEMPreferences but without outermost tag and
     length octets.
 */
unsigned int len_preferences (ripemInfo)
RIPEMInfo *ripemInfo;
{
  return (der_len (sizeof (MD5_ALGORITHM_ID)) +
          der_len (len_chainLensAllowed (ripemInfo)) +
          (ripemInfo->z.currentCRLLastUpdate == (UINT4)0 ? 0 : len_UTC ()));
}

/* Encode the preferences in the ripemInfo as a RIPEMPreferences type
     into the der and return the length in derLen.  See DerToPreferences
     for a definition of RIPEMPreferences.
   If ripemInfo->z.currentCRLLastUpdate is zero, it is omitted.
   This encodes the inner sequence without the signature.  Use
     DerUnsignedToDerSigned to add the signature.
   This assumes the digest algorithm is MD5.
   The der buffer must be at least len_preferences (ripemInfo) + 4.
 */     
void PreferencesToDer (ripemInfo, der, derLen)
RIPEMInfo *ripemInfo;
unsigned char *der;
unsigned int *derLen;
{
  unsigned char *derSave = der;
  unsigned int i;
  
  *derLen = 0;
  
  *der++ = DER_SEQ;
  put_der_len (&der, len_preferences (ripemInfo));

  /* Algorithm identifier */
  *der++ = DER_SEQ;
  put_der_len (&der, sizeof (MD5_ALGORITHM_ID));
  put_der_data (&der, MD5_ALGORITHM_ID, sizeof (MD5_ALGORITHM_ID));

  /* SEQUENCE of chainLenAllowed infos. */
  *der++ = DER_SEQ;
  put_der_len (&der, len_chainLensAllowed (ripemInfo));
  
  for (i = 0; i < ripemInfo->z.chainLensAllowedCount; ++i) {
    if (ripemInfo->z.chainLensAllowed[i].chainLenAllowed == 0)
      /* Skip entries with zero chainLenAllowed. */
      continue;

    *der++ = DER_SEQ;
    put_der_len (&der, der_len (MD5_LEN) +
                 der_len (len_small_int
                          (ripemInfo->z.chainLensAllowed[i].chainLenAllowed)));

    /* Put the publicKeyDigest */
    *der++ = DER_OCTETSTRING;
    put_der_len (&der, MD5_LEN);
    put_der_data
      (&der, ripemInfo->z.chainLensAllowed[i].publicKeyDigest, MD5_LEN);

    /* Put the chainLenAllowed */
    put_der_small_int (&der, ripemInfo->z.chainLensAllowed[i].chainLenAllowed);
  }

  if (ripemInfo->z.currentCRLLastUpdate != (UINT4)0)
    /* Put the currentCRLLastUpdate */
    put_UTC (&der, ripemInfo->z.currentCRLLastUpdate);

  *derLen = der - derSave;
}

/* Return the encoding length of all the chain lens allowed info in ripemInfo
     without the outer SEQUENCE tag and length octets.
   This skips entries with chainLenAllowed == 0.
 */
static unsigned int len_chainLensAllowed (ripemInfo)
RIPEMInfo *ripemInfo;
{
  unsigned int chainLensAllowedLen, i;

  chainLensAllowedLen = 0;
  for (i = 0; i < ripemInfo->z.chainLensAllowedCount; ++i) {
    if (ripemInfo->z.chainLensAllowed[i].chainLenAllowed == 0)
      continue;

    chainLensAllowedLen +=
      der_len (der_len (MD5_LEN) +
               der_len (len_small_int
                        (ripemInfo->z.chainLensAllowed[i].chainLenAllowed)));
  }

  return (chainLensAllowedLen);
}

/* Returns length of the sequence of CRL entries but without outermost tag
     and length octets.
   The arguments are interpreted as in CRLToDer.
   If crlentriesDER and serialNumber are NULL, then the whole sequence
     of CRL entries should be omitted from the CRL and there is no need
     to call this function.  Regardless, this function will return zero
     in this case.
   This assumes crlentriesDER is either NULL or a valid encoding as the
     result of DERToCRL.
 */
static unsigned int len_crlEntries
  (crlEntriesDER, serialNumber, serialNumberLen)
unsigned char *crlEntriesDER;
unsigned char *serialNumber;
unsigned int serialNumberLen;
{
  UINT2 tag;
  unsigned int len, result;
  unsigned char *pointer;

  result = 0;
  
  if (crlEntriesDER != (unsigned char *)NULL) {
    /* Set len to the length of the crlEntries content without the tag and
         length octets.  Assume it is encoded correctly. */
    pointer = crlEntriesDER;
    gettaglen (&tag, &len, &pointer);

    result += len;
  }
  
  if (serialNumber != (unsigned char *)NULL)
    /* Include the new entry. */
    result += der_len (len_crlEntry (serialNumber, serialNumberLen));

  return (result);
}

/* Returns length of the crl entry (having the serial number and revocation
     time) but without outermost tag and length octets.
 */
static unsigned int len_crlEntry (serialNumber, serialNumberLen)
unsigned char *serialNumber;
unsigned int serialNumberLen;
{
  return (der_len (len_large_unsigned (serialNumber, serialNumberLen)) +
          len_UTC ());
}

static unsigned int AttrTypePrefixSize (attr)
int attr;
{
  if ((attr & 0xff00) == PKCS9_ATTRIBUTE)
    return (sizeof (PKCS9_ATTR_TYPE_PREFIX));
  else
    return (sizeof (X520_ATTR_TYPE_PREFIX));
}

static unsigned char *AttrTypePrefixData (attr)
int attr;
{
  if ((attr & 0xff00) == PKCS9_ATTRIBUTE)
    return (PKCS9_ATTR_TYPE_PREFIX);
  else
    return (X520_ATTR_TYPE_PREFIX);
}

