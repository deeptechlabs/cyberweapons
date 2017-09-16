/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*
 *   derkey.c
 *  Routines to translate to R_RSA_{PUBLIC,PRIVATE}_KEY
 *  from ASN.1 DER encodings.
 */

#include <stdio.h>
#include <stdlib.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "derkeypr.h"
#include "certder.h"
#include "p.h"

static unsigned int largeunsignedbits P((unsigned char *, unsigned int));
static int getsmallint P((unsigned int *, unsigned char **));
static int getlargeunsignedbitstring
  P((unsigned char *, unsigned int, unsigned char **, int));
static int DateToSeconds P((unsigned long *, int, int, int, int, int, int));

/* Error return codes */
#define DK_ERR_FORMAT -1    /* Badly formatted DER string */
#define DK_ERR_ALG  -2    /* Unrecognized algorithm */

/* DER class/tag codes */
#define DER_CONSTRUCTED 0x20
#define DER_CONTEXT_SPECIFIC 0x80
#define DER_INT   0x02
#define DER_BITSTRING 0x03
#define DER_OCTETSTRING 0x04
#define DER_NULL  0x05
#define DER_OBJID 0x06
#define DER_SEQ   (16 | DER_CONSTRUCTED)
#define DER_SET   (17 | DER_CONSTRUCTED)
#define DER_UTC   0x17

/* Alg ID - rsa - {2, 5, 8, 1, 1}*/
static unsigned char rsa_alg[] = { DER_OBJID, 4, 2*40+5, 0x08, 0x01, 0x01 };

/* rsaEncryption data structure, with algorithm {1 2 840 113549 1 1 1} and
 * NULL parameter.
   NOTE: this starts at the object ID, not the algorithm ID sequence.
 */
static unsigned char rsaEnc_alg[] = { DER_OBJID, 9,
  1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  DER_NULL, 0 };

/* Version = 0 */
static unsigned char version[] = { DER_INT, 1, 0 };

/* Versions for certificates.  Note that we do not have integer zero because
     this is the default and DER should omit it.
   Version 2 is integer 1, version 3 is integer 2.
 */
static unsigned char EXPLICIT_VERSION_2[] = {
  DER_CONSTRUCTED | DER_CONTEXT_SPECIFIC | 0, 3,
    DER_INT, 1, 1
};
static unsigned char EXPLICIT_VERSION_3[] = {
  DER_CONSTRUCTED | DER_CONTEXT_SPECIFIC | 0, 3,
    DER_INT, 1, 2
};


/* Return the number of bits in large unsigned n */
static unsigned int
largeunsignedbits (n, nsize)
unsigned char *n;
unsigned int nsize;
{
  unsigned int i, j;

  for (i=0; i<nsize && n[i]==0; ++i)
    ;   /* Intentionally empty */
  if (i==nsize)
    return 0;
  j = n[i];
  i = ((nsize-i-1) << 3) + 1;
  while ((j>>=1))
    ++i;
  return i;
}


/* Read the tag and length information from a DER string.  Advance
 * der to past the length.  Return negative on error.
 */
int      /* Return < 0 on error */
gettaglen(tag, len, p)
UINT2 *tag;
unsigned int *len;
unsigned char **p;
{
  UINT2 t;
  unsigned int l;
  int c;
  int n;

  t = *(*p)++;
  if (!t)
    return -1;
  c = *(*p)++;
  if (c & 0x80) {
    if (!(n = c & 0x7f))
      return -1;
    l = 0;
    if (n > sizeof(unsigned int))
      return -1;
    while (n--) {
      c = *(*p)++;
      l = (l<<8) + c;
    }
  } else {
    l = c & 0x7f;
  }
  *tag = t;
  *len = l;
  return 0;
}


/* Check DER byte string against literal data to make sure they match.
 * Return negative on error, zero for success.  Advance der pointer p.
 * ALSO: for error return, this leaves p where it was.
 */
int DERCheckData (p, s, len)
unsigned char **p;
unsigned char *s;
unsigned int len;
{
  unsigned char *origp = *p;
  
  while (len--)
    if (*(*p)++ != *s++) {
    *p = origp;
    return -1;
  }
  return 0;
}


/* Read an integer from DER byte string.  It must be small enough to
 * fit in an int.  Return negative on error.
 */
static int
getsmallint (n, p)
unsigned int *n;
unsigned char **p;
{
  UINT2 tag;
  unsigned int len;
  unsigned int v;
  
  if (gettaglen(&tag,&len,p) < 0)
    return -1;
  if (tag != DER_INT)
    return -1;
  if (len > sizeof(int)  ||  len == 0)
    return -1;
  v = 0;
  while (len--)
    v = (v << 8) + *(*p)++;
  *n = v;
  return 0;
}


/* Read a large integer from the DER byte string pointed to by p.
 * Advance p as we read.  Put it into buffer n, of length nsize,
 * right justified.  Clear the rest of n.
 * Return negative on error.
 */
int getlargeunsigned (n, nsize, p)
unsigned char *n;
unsigned int nsize;
unsigned char **p;
{
  UINT2 tag;
  unsigned int len;

  if (gettaglen(&tag,&len,p) < 0)
    return -1;
  if (tag != DER_INT)
    return -1;
  /* Skip a leading zero  in the input; it may overflow the output
   * buffer if the large unsigned is just the same size as the output buffer.
   */
  if(! **p) {
    (*p)++;
    len--;
  }
  if (len > nsize)
    return -1;
  nsize -= len;
  while (nsize--)
    *n++ = 0;
  while (len--)
    *n++ = *(*p)++;
  return 0;
}



/*
 *  Beginning of public entry points for this module
 */



/*   int DERToPubKey (der, key)
 *  Translate the byte string DER, in ASN.1 syntax using the
 *  Distinguished Encoding Rules, into RSA public key.
 *  Return 0 on success, nonzero on error.
 */
int       /* 0 for OK, nonzero on error */
DERToPubKey (der, key)
unsigned char *der;
R_RSA_PUBLIC_KEY *key;
{
  UINT2 tag;
  unsigned int len;
  unsigned int bits;
  unsigned char *der1, *der2;

  /* Pre-zeroize key struct so byte-wise comparison of two
       structs for the same public key will be the same. */
  R_memset ((POINTER)key, 0, sizeof (*key));

  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  der1 = der + len;   /* Position of end of string */
  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  der2 = der + len;   /* Position of end of alg info */
  if (DERCheckData(&der, rsa_alg, (unsigned int)sizeof(rsa_alg)) < 0) {
    /* Try the rsaEncryption algorithm ID. */
    if (DERCheckData(&der, rsaEnc_alg, (unsigned int)sizeof(rsaEnc_alg)) < 0)
      return DK_ERR_ALG;
    key->bits = 0;
  } else {
    if (getsmallint(&bits, &der) < 0)
      return DK_ERR_FORMAT;
    key->bits = (int)bits;
  }
  if (der != der2)    /* Check end of alg info */
    return DK_ERR_FORMAT;
  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_BITSTRING)
    return DK_ERR_FORMAT;
  if (der + len != der1)  /* Should also be end of string */
    return DK_ERR_FORMAT;
  if (*der++ != 0)    /* Bitstring must be a mult of 8 bits */
    return DK_ERR_FORMAT;
  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  if (der + len != der1)  /* Should also be end of string */
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->modulus, (unsigned int)sizeof(key->modulus), &der) < 0)
    return DK_ERR_FORMAT;
  if(key->bits == 0) {
    /* In the rsaEncryption case, we must compute the modulus bits. */
    key->bits = (int)largeunsignedbits
      (key->modulus, (unsigned int)sizeof(key->modulus));
  }
  if (getlargeunsigned
      (key->exponent, (unsigned int)sizeof(key->exponent),&der) < 0)
    return DK_ERR_FORMAT;
  if (der != der1)    /* Check end of string */
    return DK_ERR_FORMAT;
  return 0;
}

/*   int DERToPrivKey (der, key)
 *  Translate the byte string DER, in ASN.1 syntax using the
 *  Distinguished Encoding Rules, into RSA private key.
 *  Return 0 on success, nonzero on error.
 */
int       /* 0 for OK, nonzero on error */
DERToPrivKey (der, key)
unsigned char *der;
R_RSA_PRIVATE_KEY *key;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *der1;

  R_memset((POINTER)key,0,sizeof *key);

  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  der1 = der + len;   /* Position of end of string */
  if (DERCheckData(&der, version, (unsigned int)sizeof(version)) < 0)
    return DK_ERR_ALG;
  /* rsaEnc_alg starts at the object ID, so decode the sequence here. */
  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  if (DERCheckData(&der, rsaEnc_alg, (unsigned int)sizeof(rsaEnc_alg)) < 0)
    return DK_ERR_ALG;
  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_OCTETSTRING)
    return DK_ERR_FORMAT;
  if (der+len != der1)  /* Should match end of string */
    return DK_ERR_FORMAT;
  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  if (der+len != der1)  /* Should match end of string */
    return DK_ERR_FORMAT;
  if (DERCheckData(&der, version, (unsigned int)sizeof(version)) < 0)
    return DK_ERR_ALG;
  if (getlargeunsigned
      (key->modulus, (unsigned int)sizeof(key->modulus), &der) < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->publicExponent, (unsigned int)sizeof(key->publicExponent), &der)
      < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->exponent, (unsigned int)sizeof(key->exponent),&der) < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->prime[0], (unsigned int)sizeof(key->prime[0]),&der) < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->prime[1], (unsigned int)sizeof(key->prime[1]),&der) < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->primeExponent[0], (unsigned int)sizeof(key->primeExponent[0]),
       &der) < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->primeExponent[1], (unsigned int)sizeof(key->primeExponent[1]),
       &der) < 0)
    return DK_ERR_FORMAT;
  if (getlargeunsigned
      (key->coefficient, (unsigned int)sizeof(key->coefficient), &der) < 0)
    return DK_ERR_FORMAT;
  if (der != der1)    /* Check end of string */
    return DK_ERR_FORMAT;
  /* This info isn't in the DER format, so we have to calculate it */
  key->bits = (int)largeunsignedbits
    (key->modulus, (unsigned int)sizeof(key->modulus));
  return 0;
}

/* Data structure specifying "algorithm=pbeWithMD2AndDES-CBC"
 * for encoding of encrypted private key.
 * Decodes to OBJECT_ID = 1 2 840 113549 1 5 1
 */
static unsigned char pbeWithMD2AndDES_CBC[] = { DER_OBJID, 9,
  1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x01 };

/* Data structure specifying "algorithm=pbeWithMD5AndDES-CBC"
 * for encoding of encrypted private key.
 * Decodes to OBJECT_ID = 1 2 840 113549 1 5 3
 */
static unsigned char pbeWithMD5AndDES_CBC[] = { DER_OBJID, 9,
  1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03 };

/*--- function int DERToEncryptedPrivKey --------------------------
 *
 *  Translate the byte string DER, in ASN.1 syntax using the
 *  Distinguished Encoding Rules, into encrypted RSA private key.
 *  Return 0 on success, nonzero on error.
 *
 * Encrypted key encoding looks like this:
 *
 *  Sequence
 *  Sequence                           # encryption algorithm
 *      Object ID 1 2 840 113549 1 5 3  # algorithm MD5AndDES-CBC (MD2 also OK)
 *      Sequence                        # algorithm parameters:
 *        Octet string, 8 bytes long   # salt
 *         Integer                      # iteration count
 *    Octet string                # encrypted data
 */
int       /* 0 for OK, nonzero on error */
DERToEncryptedPrivKey
  (der, maxLen, digestAlgorithm, salt, iterationCount, encBytes, encLen)
unsigned char *der;
unsigned int maxLen;
int *digestAlgorithm;
unsigned char *salt;
unsigned int *iterationCount;
unsigned char *encBytes;
unsigned int *encLen;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *der_end;

  /* Check first Sequence */
  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  der_end = der + len;   /* Position of end of string */
  
  /* Check second Sequence */
  if(gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if(tag != DER_SEQ)
    return DK_ERR_FORMAT;

  /* Check algorithm */
  if (DERCheckData
      (&der,pbeWithMD5AndDES_CBC, (unsigned int)sizeof(pbeWithMD5AndDES_CBC))
      < 0) {
    if (DERCheckData(&der,pbeWithMD2AndDES_CBC,
                     (unsigned int)sizeof(pbeWithMD2AndDES_CBC)) < 0)
      return DK_ERR_ALG;
    *digestAlgorithm = DA_MD2;
  } else
    *digestAlgorithm = DA_MD5;
  
  /* Check Sequence of algorithm parameters. */
  if(gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if(tag != DER_SEQ)
    return DK_ERR_FORMAT;

  /* Fetch salt */
  if(gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if(tag != DER_OCTETSTRING)
    return DK_ERR_FORMAT;
  if(len != 8)
    return DK_ERR_FORMAT;
  R_memcpy(salt,der,8);
  der += 8;

  /* Fetch iteration count */

  if(getsmallint(iterationCount,&der) < 0)
    return DK_ERR_FORMAT;
  
  /* Fetch encrypted private key */
  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_OCTETSTRING)
    return DK_ERR_FORMAT;
  if (der+len != der_end)  /* Should match end of string */
    return DK_ERR_FORMAT;

  if(len > maxLen)
    return DK_ERR_FORMAT;
  R_memcpy(encBytes,der,len);
  *encLen = len;
  
  return 0;
}

/* Extensions for certificate encoding follow.
 */

#define LEN_OF_MONTH(year, month) \
  ((((year) % 4) || (month) != 2) ? MONTH_LENS[((month)-1)] : 29)

#define SECONDS_IN_DAY ((unsigned long)3600 * (unsigned long)24)
    
static unsigned int MONTH_LENS[] =
  {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

/* Attribute type ID - joint-iso-ccittt(2) ds(5) 4 followed by attrtype */
static unsigned char X520_ATTR_TYPE_PREFIX[] = { DER_OBJID, 3, 2*40+5, 4 };

/* Attribute object ID for PKCS #9 to be followed by attrtype byte */
static unsigned char PKCS9_ATTR_TYPE_PREFIX[] =
  {DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9 };

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

/* Data structure specifying "algorithm=sha1WithRSAEncryption" followed by
     NULL param
   iso(1) member-body(2) US(840) rsadsi(113549) pkcs(1) pkcs-1(1) 5
   Decodes to OBJECT_ID = 1 2 840 113549 1 1 5
 */
static unsigned char sha1WithRSAEncryption[] =
  { DER_OBJID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
    DER_NULL, 0 };

/* Data structure for MD5 digest algorithm. */
static unsigned char MD5_ALGORITHM_ID[] = {
  DER_OBJID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
    DER_NULL, 0
};

/* Data structure for SHA1 digest algorithm. */
static unsigned char SHA1_ALGORITHM_ID[] = {
  DER_OBJID, 5, 0x2b, 0x0e, 0x03, 0x02, 26,
    DER_NULL, 0
};

/* Returns 0 if no error, nonzero if error
   Currently only accepts the 3-byte object identifiers for countryName,
     organizationName, etc.
   Allow any tag type (printable string, etc.), except exclude constructed
     (bit 0x20 set) or extended tags.
   This advances der by the length of the encoding.
 */
int DERToDistinguishedName (der, dn)
unsigned char **der;
DistinguishedNameStruct *dn;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *der1;
  int num_RDNs = 0, num_values = 0, sameSET;
  short attr;
  
  /* Pre-zeroize name struct so byte-wise comparison of two
       structs for the same name will be the same. */
  InitDistinguishedNameStruct (dn);

  if (gettaglen (&tag, &len, der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
    
  der1 = *der + len;
    
  while(*der < der1) {
    if (gettaglen(&tag,&len,der) < 0)
      return DK_ERR_FORMAT;
    
    if(tag == DER_SEQ && num_RDNs) {
      /* same as last set */
      sameSET = 1;
      goto in_set;
    } else
      sameSET = 0;
      
    if(tag != DER_SET)
      return DK_ERR_FORMAT;
      
    if (gettaglen(&tag,&len,der) < 0)
      return DK_ERR_FORMAT;
    if (tag != DER_SEQ)
      return DK_ERR_FORMAT;
  in_set:
    if (DERCheckData
        (der, X520_ATTR_TYPE_PREFIX,
         (unsigned int)sizeof (X520_ATTR_TYPE_PREFIX)) < 0) {
      /* Try PKCS #9 attribute */
      if (DERCheckData
          (der, PKCS9_ATTR_TYPE_PREFIX,
           (unsigned int)sizeof (PKCS9_ATTR_TYPE_PREFIX)) < 0)
        return DK_ERR_ALG;
      else
        attr = (*(*der)++) | PKCS9_ATTRIBUTE;
    }
    else
      /* Note that X520_ATTRIBUTE is 0 which makes this backward compatible
           with earlier versions of RIPEM. */
      attr = (*(*der)++) | X520_ATTRIBUTE;

    if (gettaglen(&tag,&len,der) < 0)
      return DK_ERR_FORMAT;
    /* Allow any tag, except exclude constructed (bit 0x20 set) or
         extended tags (all bits 0x1f set) */
    if ((tag & 0x20) || ((tag & 0x1f) == 0x1f))
      return DK_ERR_FORMAT;
    if(len > MAX_NAME_LENGTH)
      return DK_ERR_FORMAT;
    
    if(num_values < MAX_AVA && num_RDNs < MAX_RDN) {
      /* Set AVAValues as a C string. */
      R_memcpy ((POINTER)dn->AVAValues[num_values], (POINTER)(*der), len);
      /* No need to set null terminator since buffer is already zeroized. */
    
      dn->AVATypes[num_values] = attr;
      dn->AVATag[num_values] = tag;
      if(!sameSET) {
        /* new RDN */
        if(num_RDNs)
          /* Indicate where the end of the previous RDN was. */
          dn->RDNIndexEnd[num_RDNs-1] = num_values - 1;
        dn->RDNIndexStart[num_RDNs++] = num_values;
      }
      num_values++;
    }
    (*der) += len;
    
  }
  if(num_RDNs)
    /* Indicate where the end of the final RDN is. */
    dn->RDNIndexEnd[num_RDNs-1] = num_values - 1;

  return 0;
}

/* Zeroize and set AVATypes and RDN indexes to -1 so that a name can be
     constructed simply by setting the needed AVAs and RDN indexes.
   Preset tags to ATTRTAG_PRINTABLE_STRING.
 */
void InitDistinguishedNameStruct (name)
DistinguishedNameStruct *name;
{
  unsigned int i;

  R_memset ((POINTER)name, 0, sizeof (*name));
  for (i = 0; i < MAX_AVA; ++i) {
    name->AVATypes[i] = -1;
    name->AVATag[i] = ATTRTAG_PRINTABLE_STRING;
  }
  for (i = 0; i < MAX_RDN; ++i)
    name->RDNIndexStart[i] = name->RDNIndexEnd[i] = -1;
}

/* Read a bit string from the DER byte string pointed to by p.
 * Advance p as we read.  Put it into buffer n, of length nsize.
 * Zeroes out remaining bytes.
 * DOES NOT EXPECT AN INTEGER TAG. Caller must pass in length of of bits string
 * Return negative on error.
 */
static int getlargeunsignedbitstring (n, nsize, p, len)
unsigned char *n;
unsigned int nsize;
unsigned char **p;
int len;
{
  int extra = nsize - len;

  if (extra < 0)
    return -1;
  while (len--)
    *n++ = *(*p)++;
  while(extra--)
    *n++ = 0;
      
  return 0;
}

/* Convert values to time in seconds since 1970.
   Return 0 for success or error if year is less than 1970.
 */
static int DateToSeconds (time, year, month, day, hour, minute, second)
unsigned long *time;
int year, month, day, hour, minute, second;
{
  if (year < 50)
    /* this is a year from 2000 to 2049 (instead of 1900 to 1949) */
    year += 100;

  /* year is now in the range 50 to 149.  However, we represent the
       year as seconds since 1970, so we can't deal with a year less
       than 70. */
  if (year < 70)
    return (DK_ERR_FORMAT);
  
  /* "Carry" changes in minutes and hours through day, month and year.
   */
  if (minute < 0) {
    minute += 60;
    hour--;
  }
  else if (minute > 59) {
    minute -= 60;
    hour++;
  }
  
  if (hour < 0) {
    hour += 24;
    day--;
    if (day < 1) {
      month--;
      if (month < 1) {
        month += 12;
        /* if year came in as 0, it was converted to 100, so the year cannot
           fall below 0 */
        year--;
        if (year < 70)
          /* Cannot represent a year below 1970 */
          return (DK_ERR_FORMAT);
      }
      day += LEN_OF_MONTH (year, month);
    }
  }
  else if (hour > 23) {
    hour -= 24;
    day++;

    if (day > (int) LEN_OF_MONTH (year, month)) {
      day -= LEN_OF_MONTH (year, month);
      month++;
      if (month > 12) {
        month -= 12;
        year++;
      }
    }
  }
  
  *time = (unsigned long)second + (unsigned long)60 * (unsigned long)minute +
    (unsigned long)3600 * (unsigned long)hour +
    SECONDS_IN_DAY * (unsigned long)(day-1);
  
  /* Count month down to 2, adding up the number of seconds in the previous
       month.
   */
  while (month > 1) {
    *time += SECONDS_IN_DAY * (unsigned long)LEN_OF_MONTH (year, month - 1);
    month --;
  }

  /* Count year down to 71, adding up the number of seconds in the previous
       year.
   */
  while (year > 70) {
    *time += (year-1) % 4 ?
      (SECONDS_IN_DAY * (unsigned long)365)
      : (SECONDS_IN_DAY * (unsigned long)366);
    year--;
  }

  return (0);
}

/* Returns 0 if no error, nonzero if error.
   This sets time to seconds since 1970.  Also, if the incoming
     DER has a year less than '50', assume it is after the year 2000.
 */
int DERToUTC (der, time)
unsigned char **der;
unsigned long *time;
{
  UINT2 tag;
  unsigned int len;
  char s[64],*sp;
  int year, month, day, hour, minute, second;
  
  if (gettaglen(&tag,&len,der) < 0)
    return DK_ERR_FORMAT;
  
  if(tag != DER_UTC)
    return DK_ERR_FORMAT;
  
  sp = s;
  while(len--)
    *sp++ = *(*der)++;
  *sp = 0;

  /* now parse the string. */
  sp = s;
  year = ((*sp++) - '0') * 10;
  year += *sp++ - '0';
  month = ((*sp++) - '0') * 10;
  month += *sp++ - '0';
  day = ((*sp++) - '0') * 10;
  day += *sp++ - '0';
  hour = ((*sp++) - '0') * 10;
  hour += *sp++ - '0';
  minute = ((*sp++) - '0') * 10;
  minute += *sp++ - '0';
  second = 0;
  
  if(*sp != 'Z') {  /* Z means is local time -- done. */
    if(*sp != '+' && *sp != '-') {
      /* get seconds */
      second = ((*sp++) - '0') * 10;
      second += *sp++ - '0';
    }
    
    if(*sp != 'Z') {  /* Z means is local time -- done. */
      int diff;
      
      if(*sp == '+') {    /* time is ahead, so subtract to get GMT. */
        sp++;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        hour -= diff;
        
        if(*sp++ != '\'')
          return DK_ERR_FORMAT;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        minute -= diff;
        if(*sp != '\'')
          return DK_ERR_FORMAT;
      } else if(*sp == '-') {   /* time is behind, so add to get GMT. */
        sp++;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        hour += diff;
        
        if(*sp++ != '\'')
          return DK_ERR_FORMAT;
        diff = ((*sp++) - '0') * 10;
        diff += *sp++ - '0';
        minute += diff;
        if(*sp != '\'')
          return DK_ERR_FORMAT;
      } else
        return DK_ERR_FORMAT;
    }
  }
  
  return (DateToSeconds (time, year, month, day, hour, minute, second));
}

/* Returns length advanced for OK, negative for error.
     fieldPointers->innerDER and innerDERLen will give the der portion up
     to end of CertificateInfo but not including outer signature alg &
     signature.  This is useful because the signature is of the
     CertificateInfo portion, DER coded, only.
   fieldPointers may be NULL in which case it is ignored.
 */
int DERToCertificate (der, cert, fieldPointers)
unsigned char *der;
CertificateStruct *cert;
CertFieldPointers *fieldPointers;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *outerDEREnd, *innerDEREnd, *derStart = der;
  int result;

  if (gettaglen(&tag,&len,&der) < 0) /* SEQUENCE of cert, sig alg, signature */
    return DK_ERR_FORMAT;
  
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  outerDEREnd = der + len;                 /* Position of end of certificate */
   
  if (fieldPointers != (CertFieldPointers *)NULL)
    fieldPointers->innerDER = der;
  
  if (gettaglen(&tag,&len,&der) < 0)            /* SEQUENCE w/certinfo stuff */
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;
  innerDEREnd = der + len;             /* Position of end of inner cert info */

  if (DERCheckData (&der, EXPLICIT_VERSION_2, sizeof (EXPLICIT_VERSION_2))
      == 0)
    cert->version = 2;
  else if (DERCheckData (&der, EXPLICIT_VERSION_3, sizeof (EXPLICIT_VERSION_3))
      == 0)
    cert->version = 3;
  else
    cert->version = 1;
  
  if (getlargeunsigned
      (cert->serialNumber, sizeof (cert->serialNumber), &der) < 0)
    return DK_ERR_FORMAT;
    
  if (gettaglen(&tag,&len,&der) < 0)                    /* SEQUENCE w/alg ID */
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  if (DERCheckData
      (&der, md2WithRSAEncryption, (unsigned int)sizeof(md2WithRSAEncryption))
      < 0) {
    /* Try MD5 with RSA */
    if (DERCheckData
        (&der, md5WithRSAEncryption,
         (unsigned int)sizeof(md5WithRSAEncryption)) < 0) {
      /* Try SHA1 with RSA */
      if (DERCheckData
          (&der, sha1WithRSAEncryption,
           (unsigned int)sizeof(sha1WithRSAEncryption)) < 0)
        return DK_ERR_ALG;
      else
        cert->digestAlgorithm = DA_SHA1;
    }
    else
      cert->digestAlgorithm = DA_MD5;
  }
  else
    cert->digestAlgorithm = DA_MD2;
  
  if((result = DERToDistinguishedName(&der,&cert->issuer)) != 0)
    return result;
  
  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  if((result = DERToUTC(&der,&cert->notBefore)) != 0)
    return result;

  if((result = DERToUTC(&der,&cert->notAfter)) != 0)
    return result;

  if((result = DERToDistinguishedName(&der,&cert->subject)) != 0)
    return result;

  if((result = DERToPubKey(der,&cert->publicKey)) < 0)
    return result;
  /* Advance der past the public key.
   */
  if (gettaglen(&tag,&len,&der) < 0)
    return DK_ERR_FORMAT;
  der += len;

  /* Allow but ignore issuerUniqueIdentifier which is an IMPLICIT OCTET
       STRING */
  if (der < innerDEREnd && *der == (DER_CONTEXT_SPECIFIC | 1)) {
    if (cert->version < 2)
      return (DK_ERR_FORMAT);
    if (gettaglen (&tag, &len, &der) < 0)
      return (DK_ERR_FORMAT);
    der += len;
  }

  /* Allow but ignore subjectUniqueIdentifier which is an IMPLICIT OCTET
       STRING */
  if (der < innerDEREnd && *der == (DER_CONTEXT_SPECIFIC | 2)) {
    if (cert->version < 2)
      return (DK_ERR_FORMAT);
    if (gettaglen (&tag, &len, &der) < 0)
      return (DK_ERR_FORMAT);
    der += len;
  }

  /* Allow but ignore extensions which is EXPLICIT */
  if (der < innerDEREnd &&
      *der == (DER_CONSTRUCTED | DER_CONTEXT_SPECIFIC | 3)) {
    if (cert->version < 3)
      return (DK_ERR_FORMAT);
    if (gettaglen (&tag, &len, &der) < 0)
      return (DK_ERR_FORMAT);
    der += len;
  }

  if (der != innerDEREnd)
    return DK_ERR_ALG;
  if (fieldPointers != (CertFieldPointers *)NULL)
    fieldPointers->innerDERLen = (unsigned int)(der - fieldPointers->innerDER);
  
  if (gettaglen(&tag,&len,&der) < 0)                    /* SEQUENCE w/alg ID */
    return DK_ERR_FORMAT;
  if (tag != DER_SEQ)
    return DK_ERR_FORMAT;

  /* Make sure the signature algorithm is the same here as it was
       in the body */
  if (cert->digestAlgorithm == DA_MD2) {
    if (DERCheckData
        (&der, md2WithRSAEncryption,
         (unsigned int)sizeof(md2WithRSAEncryption)) < 0)
      return DK_ERR_ALG;
  }
  else if (cert->digestAlgorithm == DA_MD5) {
    if (DERCheckData
        (&der, md5WithRSAEncryption,
         (unsigned int)sizeof(md5WithRSAEncryption)) < 0)
      return DK_ERR_ALG;
  }
  else if (cert->digestAlgorithm == DA_SHA1) {
    if (DERCheckData
        (&der, sha1WithRSAEncryption,
         (unsigned int)sizeof(sha1WithRSAEncryption)) < 0)
      return DK_ERR_ALG;
  }

  if (gettaglen(&tag, &len, &der) < 0)
    return DK_ERR_FORMAT;
  if (tag != DER_BITSTRING)
    return DK_ERR_FORMAT;
  if (*der++ != 0)                     /* Bitstring must be a mult of 8 bits */
    return DK_ERR_FORMAT;
  
  cert->signatureLen = len-1;                  /* subtract one for pad bits. */
  if(getlargeunsignedbitstring
     (cert->signature, sizeof(cert->signature), &der, len-1))
    return DK_ERR_ALG;
  
  if(der != outerDEREnd)
    return DK_ERR_ALG;
  
  return ((int)(der - derStart));
}

/* Check for valid printable string character set.  Return a 1 if
     all characters are int the printable string set, 0 if not.
 */
int IsPrintableString (valuePointer, valueLen)
unsigned char *valuePointer;
unsigned int valueLen;
{
  unsigned char valueChar;
  unsigned int i;

  for (i = 0; i < valueLen; i++) {
    valueChar = valuePointer[i];
      
    if (! ((valueChar >= 0x41 && valueChar <= 0x5a) ||
           (valueChar >= 0x61 && valueChar <= 0x7a) ||
           valueChar == 0x20 ||
           (valueChar >= 0x27 && valueChar <= 0x3a && valueChar != 0x2a) ||
           valueChar == 0x3d || valueChar == 0x3f))
      return (0);
  }
  
  return (1);
}

/* Returns length advanced for OK, negative for error.
     fieldPointers->innerDER and innerDERLen will give the der portion up
     to end of CRL info but not including outer signature alg &
     signature.
   fieldPointers->crlEntriesDER will give the DER of the crl entries.
     This is useful for calling FindCRLEntry later.  If the crl entries
     is omitted from the der, this is set to NULL.
   fieldPointers may be NULL in which case it is ignored.
 */
int DERToCRL (der, crl, fieldPointers)
unsigned char *der;
CRLStruct *crl;
CRLFieldPointers *fieldPointers;
{
  UINT2 tag;
  unsigned int len;
  unsigned char *outerDEREnd, *derStart = der, *innerDEREnd;
  int result;

  /* SEQUENCE of crl, sig alg, signature */
  if (gettaglen (&tag, &len, &der) < 0)
    return (DK_ERR_FORMAT);  
  if (tag != DER_SEQ)
    return (DK_ERR_FORMAT);

  /* Position of end of CRL */
  outerDEREnd = der + len;
   
  if (fieldPointers != (CRLFieldPointers *)NULL)
    fieldPointers->innerDER = der;
  
  /* SEQUENCE with CRL info stuff */
  if (gettaglen (&tag, &len, &der) < 0)
    return (DK_ERR_FORMAT);
  if (tag != DER_SEQ)
    return (DK_ERR_FORMAT);

  /* Position of end of innerDER */
  innerDEREnd = der + len;
   
  /* SEQUENCE w/alg ID */
  if (gettaglen (&tag, &len, &der) < 0)
    return (DK_ERR_FORMAT);
  if (tag != DER_SEQ)
    return (DK_ERR_FORMAT);

  if (DERCheckData
      (&der, md2WithRSAEncryption, (unsigned int)sizeof(md2WithRSAEncryption))
      < 0) {
    /* Try MD5 with RSA */
    if (DERCheckData
        (&der, md5WithRSAEncryption,
         (unsigned int)sizeof(md5WithRSAEncryption)) < 0) {
      /* Try SHA1 with RSA */
      if (DERCheckData
          (&der, sha1WithRSAEncryption,
           (unsigned int)sizeof(sha1WithRSAEncryption)) < 0)
        return DK_ERR_ALG;
      else
        crl->digestAlgorithm = DA_SHA1;
    }
    else
      crl->digestAlgorithm = DA_MD5;
  }
  else
    crl->digestAlgorithm = DA_MD2;
  
  if ((result = DERToDistinguishedName (&der, &crl->issuer)) != 0)
    return (result);
  
  if ((result = DERToUTC (&der, &crl->lastUpdate)) != 0)
    return (result);

  if ((result = DERToUTC (&der, &crl->nextUpdate)) != 0)
    return (result);

  if (der == innerDEREnd) {
    /* The CRL entries have been omitted. */
    if (fieldPointers != (CRLFieldPointers *)NULL)
      fieldPointers->crlEntriesDER = (unsigned char *)NULL;
  }
  else {
    /* Get the crlEntries DER in its entirety */
    if (fieldPointers != (CRLFieldPointers *)NULL)
      fieldPointers->crlEntriesDER = der;

    if (gettaglen (&tag, &len, &der) < 0)
      return (DK_ERR_FORMAT);
    der += len;
  }
  
  if (fieldPointers != (CRLFieldPointers *)NULL)
    fieldPointers->innerDERLen = (unsigned int)(der - fieldPointers->innerDER);

  /* SEQUENCE w/alg ID */
  if (gettaglen (&tag, &len, &der) < 0)
    return (DK_ERR_FORMAT);
  if (tag != DER_SEQ)
    return (DK_ERR_FORMAT);

  /* Make sure the signature algorithm is the same here as it was
       in the body */
  if (crl->digestAlgorithm == DA_MD2) {
    if (DERCheckData
        (&der, md2WithRSAEncryption,
         (unsigned int)sizeof(md2WithRSAEncryption)) < 0)
      return DK_ERR_ALG;
  }
  else if (crl->digestAlgorithm == DA_MD5) {
    if (DERCheckData
        (&der, md5WithRSAEncryption,
         (unsigned int)sizeof(md5WithRSAEncryption)) < 0)
      return DK_ERR_ALG;
  }
  else if (crl->digestAlgorithm == DA_SHA1) {
    if (DERCheckData
        (&der, sha1WithRSAEncryption,
         (unsigned int)sizeof(sha1WithRSAEncryption)) < 0)
      return DK_ERR_ALG;
  }

  if (gettaglen (&tag, &len, &der) < 0)
    return (DK_ERR_FORMAT);
  if (tag != DER_BITSTRING)
    return (DK_ERR_FORMAT);
  if (*der++ != 0)
    /* Bitstring must be a mult of 8 bits */
    return (DK_ERR_FORMAT);
  
  /* subtract one for pad bits. */
  crl->signatureLen = len - 1;
  if (getlargeunsignedbitstring
      (crl->signature, sizeof (crl->signature), &der, len - 1))
    return (DK_ERR_ALG);
  
  if (der != outerDEREnd)
    return (DK_ERR_ALG);
  
  return ((int)(der - derStart));
}

/* This searches the der for a CRL entry with the given serial number
     and sets found to whether it is found.
   der is typically crlEntriesDER in the CRLFieldPointers as returned
     by DERToCRL.
   The serialNumber is an array of serialNumberLen bytes, big endian.
   If der is NULL, such as when the CRL entries are omitted from the
     CRL encoding, this sets found to FALSE and returns 0.
   Returns length of CRL entries for OK, negative for error.
 */
int FindCRLEntry (found, der, serialNumber, serialNumberLen)
BOOL *found;
unsigned char *der;
unsigned char *serialNumber;
unsigned int serialNumberLen;
{
  UINT2 tag;
  unsigned int len;
  unsigned char decodedSerial[20], *derStart = der, *derEnd;

  /* Default to not found. */
  *found = FALSE;

  if (der == (unsigned char *)NULL)
    return (0);
  
  if (serialNumberLen > sizeof (decodedSerial))
    /* serial number is too big for our decoding buffer */
    return (DK_ERR_ALG);

  /* SEQUENCE for CRL entries */
  if (gettaglen (&tag, &len, &der) < 0)
    return (DK_ERR_FORMAT);  
  if (tag != DER_SEQ)
    return (DK_ERR_FORMAT);

  /* Position at end of entries. */
  derEnd = der + len;

  /* Loop through entries */
  while (der < derEnd) {
    /* SEQUENCE serial number and revocation time */
    if (gettaglen (&tag, &len, &der) < 0)
      return (DK_ERR_FORMAT);  
    if (tag != DER_SEQ)
      return (DK_ERR_FORMAT);

    /* Decode the serial number and pad out to the length of the one
         we're looking for. */
    if (getlargeunsigned (decodedSerial, serialNumberLen, &der) < 0)
      return (DK_ERR_FORMAT);

    if (R_memcmp ((POINTER)decodedSerial, (POINTER)serialNumber,
                  serialNumberLen) == 0) {
      /* Found the entry.  Set found and break to return the length */
      *found = TRUE;
      break;
    }

    /* Skip over the revocation time. */
    if (gettaglen (&tag, &len, &der) < 0)
      return (DK_ERR_FORMAT);
    der += len;
  }

  if (*found == FALSE) {
    /* We went through the entire CRL entires.  Make sure the end
         matches the length of the SEQUENCE. */
    if (der != derEnd)
      return (DK_ERR_FORMAT);
  }
  
  return ((int)(derEnd - derStart));
}

/* Decode the preferences in der as a RIPEMPreferences and set the appropriate
     fields in ripemInfo.

   RIPEMPreferences ::= SIGNED SEQUENCE {
     signatureAlgorithm   AlgorithmIdentifier,
     chainLengthsAllowed  SEQUENCE OF ChainLengthAllowedInfo
              -- sequence of zero entries if no chain length allowed info
     currentCRLLastUpdate UTCTime OPTIONAL }

   ChainLengthAllowedInfo ::= SEQUENCE {
     publickeyDigest OCTET STRING (16),
     chainLengthAllowed INTEGER }

   NOTES: signatureAlgorithm is a digest algorithm identifier because
     the "signature" is computed as the digest of the RIPEMPreferences
     concatenated with a password digest.  chainLengthsAllowed may have zero
     entries.  publicKeyDigest is the MD5 digest of the DER encoding of the
     public key.

   This calls RIPEMResetPreferences to clear any previous values.
   If currentCRLLastUpdate is omitted, this sets
     ripemInfo->z.currentCRLLastUpdate to zero.
   This requires the digest algorithm to be MD5.
   This also returns the signature and the innerDER and innerDERLen so
     that the signature can be checked.  This assumes the signature buffer
     is MD5_LEN bytes long.
   Returns NULL for success, otherwise error.  Error return may
     be ERR_PREFERENCES_CORRUPT for bad encoding or ERR_MALLOC if
     the result can't be added to ripemInfo.
 */
char *DERToPreferences (der, ripemInfo, signature, innerDER, innerDERLen)
unsigned char *der;
RIPEMInfo *ripemInfo;
unsigned char *signature;
unsigned char **innerDER;
unsigned int *innerDERLen;
{
  UINT2 tag;
  char *errorMessage;
  unsigned int len, chainLenAllowed;
  unsigned char *outerDEREnd, *entriesDEREnd, *innerDEREnd,
    publicKeyDigest[MD5_LEN];

  /* Clear any previous values. */
  RIPEMResetPreferences (ripemInfo);

  /* SEQUENCE of inner info, sig alg, signature */
  if (gettaglen (&tag, &len, &der) < 0)
    return (ERR_PREFERENCES_CORRUPT);
  
  if (tag != DER_SEQ)
    return (ERR_PREFERENCES_CORRUPT);
  /* Position of end of entire encoding */
  outerDEREnd = der + len;
   
  *innerDER = der;
  
  if (gettaglen (&tag, &len, &der) < 0)
    return (ERR_PREFERENCES_CORRUPT);
  if (tag != DER_SEQ)
    return (ERR_PREFERENCES_CORRUPT);

  /* Position at end of inner DER. */
  innerDEREnd = der + len;

  if (gettaglen(&tag,&len,&der) < 0)                    /* SEQUENCE w/alg ID */
    return (ERR_PREFERENCES_CORRUPT);
  if (tag != DER_SEQ)
    return (ERR_PREFERENCES_CORRUPT);

  /* Simply ensure that we're using MD5. */
  if (DERCheckData (&der, MD5_ALGORITHM_ID, sizeof (MD5_ALGORITHM_ID)) < 0)
    return (ERR_PREFERENCES_CORRUPT);
  
  /* Sequence of ChainLengthAllowedInfo */
  if (gettaglen (&tag, &len, &der) < 0)
    return (ERR_PREFERENCES_CORRUPT);  
  if (tag != DER_SEQ)
    return (ERR_PREFERENCES_CORRUPT);

  /* Position at end of entries. */
  entriesDEREnd = der + len;

  /* Loop through entries */
  while (der < entriesDEREnd) {
    /* SEQUENCE publicKeyDigest and chainLengthAllowed */
    if (gettaglen (&tag, &len, &der) < 0)
      return (ERR_PREFERENCES_CORRUPT);  
    if (tag != DER_SEQ)
      return (ERR_PREFERENCES_CORRUPT);

    /* Decode the public key digest.  Expect a MD5_LEN byte octet string. 
     */
    if (gettaglen (&tag, &len, &der) < 0)
      return (ERR_PREFERENCES_CORRUPT);
    if (tag != DER_OCTETSTRING || len != MD5_LEN)
      return (ERR_PREFERENCES_CORRUPT);
    R_memcpy ((POINTER)publicKeyDigest, (POINTER)der, len);
    der += len;
    
    /* Decode the chainLengthAllowed */
    if (getsmallint (&chainLenAllowed, &der) < 0)
      return (ERR_PREFERENCES_CORRUPT);

    /* Use UpdateChainLensAllowed instead of the API function
         SetChainLenAllowed because we don't want to save the preferences
         we are now reading. */
    if ((errorMessage = UpdateChainLensAllowed
         (ripemInfo, publicKeyDigest, chainLenAllowed)) != (char *)NULL)
      return (errorMessage);
  }

  if (der < innerDEREnd) {
    /* The optional currentCRLLastUpdate is supplied, so decode it.
       (Note, if omitted, ripemInfo->z.currentCRLLastUpdate was already
        set to zero by RIPEMResetPreferences. */
    if (DERToUTC (&der, &ripemInfo->z.currentCRLLastUpdate) != 0)
      return (ERR_PREFERENCES_CORRUPT);
  }

  /* Make sure the end of the sequence is as expected. */
  if (der != innerDEREnd)
    return (ERR_PREFERENCES_CORRUPT);

  *innerDERLen = (unsigned int )(der - *innerDER);
  
  if (gettaglen(&tag,&len,&der) < 0)                    /* SEQUENCE w/alg ID */
    return (ERR_PREFERENCES_CORRUPT);
  if (tag != DER_SEQ)
    return (ERR_PREFERENCES_CORRUPT);

  /* Make sure the signature algorithm is MD5 as it was in the body. */
  if (DERCheckData (&der, MD5_ALGORITHM_ID, sizeof (MD5_ALGORITHM_ID)) < 0)
    return (ERR_PREFERENCES_CORRUPT);

  if (gettaglen(&tag, &len, &der) < 0)
    return (ERR_PREFERENCES_CORRUPT);
  if (tag != DER_BITSTRING)
    return (ERR_PREFERENCES_CORRUPT);
  if (*der++ != 0)                 /* Bitstring must be a multiple of 8 bits */
    return (ERR_PREFERENCES_CORRUPT);

  /* Require the signature to be MD5_LEN bytes. Remember to account for the
       1 byte for pad bits. */
  if (len != (MD5_LEN + 1))
    return (ERR_PREFERENCES_CORRUPT);
  if (getlargeunsignedbitstring (signature, MD5_LEN, &der, len-1))
    return (ERR_PREFERENCES_CORRUPT);
  
  if (der != outerDEREnd)
    return (ERR_PREFERENCES_CORRUPT);
  
  return ((char *)NULL);
}

/* Clear existing preference info in ripemInfo like chainLenAllowed.
 */
void RIPEMResetPreferences (ripemInfo)
RIPEMInfo *ripemInfo;
{
  free (ripemInfo->z.chainLensAllowed);
  ripemInfo->z.chainLensAllowed = (ChainLenAllowedInfo *)NULL;
  ripemInfo->z.chainLensAllowedCount = 0;
  ripemInfo->z.currentCRLLastUpdate = (UINT4)0;
}

