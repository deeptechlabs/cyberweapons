/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "bfstream.h"
#include "certder.h"
#include "keyderpr.h"
#include "derkeypr.h"
#include "keyfield.h"
#include "pubinfop.h"
#include "certutil.h"
#include "keymanpr.h"
#include "headers.h"
#include "rdwrmsgp.h"
#include "p.h"

/* For a Macintosh, where time is returned in seconds since
     1/1/1904 12:00:00 AM, YEAR_BASE should be defined as 1904.
   For Microsoft C 7.0, YEAR_BASE should be defined as 1900.
   The following defines YEAR_BASE as 1970 if it has not already been
     defined as something else with C compiler flags.
 */
#ifndef YEAR_BASE
#define YEAR_BASE 1970
#endif

/* Calculate the time adjustment the number of seconds between the year
     base and 1970. */

#ifdef MACTC
extern long GMTTimeshift(void);
#else
#define TIME_ADJUSTMENT \
  ((UINT4)(365 * (1970 - YEAR_BASE) + ((1970 - YEAR_BASE) + 2) / 4) * \
   (UINT4)24 * (UINT4)3600)

/* If the time() function returns local time, define GMT_OFFSET to be
     the number of hours that local time is EARLIER than GMT.
*/
#ifndef GMT_OFFSET
#define GMT_OFFSET 0
#endif
#endif  /* MACTC */

#define SECONDS_IN_MONTH \
  ((UINT4)((UINT4)365 * (UINT4)24 * (UINT4)3600) / (UINT4)12)

/* This struct is for ChainStruct. */
typedef struct {
  unsigned char *cert;
  int certLen;
  CertificateStruct *certStruct;
  CertFieldPointers fieldPointers;
  int certStatus;                                  /* Individual cert status */
} ChainCertInfo;

/* This is for use in CompleteCertChain. */
typedef struct {
  int chainStatus;
  unsigned int chainLen;                              /* number of certInfos */
  unsigned int maxChainLen;      /* Maximum length allowed. 1 = direct certs */
  ChainCertInfo certInfos[MAX_CERT_CHAIN_LEN];
} ChainStruct;

static void SignCert
  P((unsigned char *, unsigned int *, struct CertificateStruct *,
     R_RSA_PRIVATE_KEY *));
static char *CompleteCertChain
  P((RIPEMInfo *, ChainStruct *, DistinguishedNameStruct *, R_RSA_PUBLIC_KEY *,
     DistinguishedNameStruct *, RIPEMDatabase *));
static char *ComputeCertStatus
  P((int *, CertificateStruct *, R_RSA_PUBLIC_KEY *, RIPEMInfo *,
     RIPEMDatabase *));
static char *ComputeRevocationStatus
  P((int *, unsigned char *, unsigned int, UINT4, BOOL, R_RSA_PUBLIC_KEY *,
     RIPEMInfo *, RIPEMDatabase *));
static char *MaybeWriteCRL
  P((unsigned char *, unsigned int, UINT4, unsigned char *, RIPEMDatabase *));
static char *NormalizePublicKeyStruct P((R_RSA_PUBLIC_KEY *));
static char *NormalizeNameStruct P((DistinguishedNameStruct *));
static char *CheckAlreadyValidated
  P((RIPEMInfo *, BOOL *, DistinguishedNameStruct *, R_RSA_PUBLIC_KEY *, UINT4,
     RIPEMDatabase *));

/* Set theTime to the number of seconds since midnight 1/1/70 in GMT.
 */
void R_time (theTime)
UINT4 *theTime;
{
  time ((time_t *)theTime);
#ifdef MACTC
  (*theTime) += GMTTimeshift();
#else
  /* Correct for a year base different than 1970 */
  (*theTime) -= TIME_ADJUSTMENT;

  /* Correct for local time to GMT */
  (*theTime) += (UINT4)3600 * GMT_OFFSET;
#endif
}

/* Create a self-signed cert with the userDN and publicKey which are
     in ripemInfo and sign it with ripemInfo's private key using the
     given digestAlgorithm.  Write it
     to the first filename in ripemDatabase->pubKeySource.
   Set the userCertDER in ripemInfo to the new self-signed cert.
   An application would call this to upgrade from RIPEM 1.1.
 */
char *WriteSelfSignedCert
  (ripemInfo, validityMonths, digestAlgorithm, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned int validityMonths;
int digestAlgorithm;
RIPEMDatabase *ripemDatabase;
{
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  unsigned int digestLen, maxCertDERLen;
  char *errorMessage = (char *)NULL;

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* We are going to digest the struct to get a uniqe serial number, so
         pre-zerioze. */
    R_memset ((POINTER)certStruct, 0, sizeof (*certStruct));

    /* Normalize the name and public key so that bit-wise comparisons
         will work. */
    if ((errorMessage = NormalizePublicKeyStruct (&ripemInfo->publicKey))
        != (char *)NULL)
      break;
    if ((errorMessage = NormalizeNameStruct (&ripemInfo->userDN))
        != (char *)NULL)
      break;

    certStruct->digestAlgorithm = digestAlgorithm;

    /* Set validity to now to now plus validity months. */
    R_time (&certStruct->notBefore);
    certStruct->notAfter = certStruct->notBefore +
      ((UINT4)((UINT4)validityMonths * SECONDS_IN_MONTH));

    /* Set subject name and issuer name to the user's DN. */
    certStruct->issuer = ripemInfo->userDN;
    certStruct->subject = certStruct->issuer;

    certStruct->publicKey = ripemInfo->publicKey;

    /* Now set the serial number to the digest of the certStruct */
    R_DigestBlock
      (certStruct->serialNumber, &digestLen, (unsigned char *)certStruct,
       sizeof (*certStruct), certStruct->digestAlgorithm);

    /* Allocate buffer for certificate DER and sign it.
     */
    maxCertDERLen =
      len_certificate (certStruct, PubKeyToDERLen (&certStruct->publicKey)) +
      4 + MAX_UNSIGNED_TO_SIGNED_DELTA;

    if ((ripemInfo->z.userCertDER = (unsigned char *)malloc
         (maxCertDERLen)) == (unsigned char *)NULL)
      return (ERR_MALLOC);

    SignCert
      (ripemInfo->z.userCertDER, &ripemInfo->z.userCertDERLen, certStruct,
       &ripemInfo->privateKey);

    if ((errorMessage = WriteCert
         (ripemInfo->z.userCertDER, ripemDatabase)) != (char *)NULL)
      break;
  } while (0);

  free (certStruct);
  return (errorMessage);
}

/* Select the best certificate chain for the given distinguished name and
     returns the overall and individual certificate statuses.  A certificate
     status is one of the values CERT_VALID, CERT_EXPIRED, etc.
     (CERT_UNVALIDATED is not used by this routine.)
   The "best chain" is the one with the lowest numerical value for
     the overall chain status (since CERT_VALID's #defined value is lower
     than CERT_PENDING, etc.) If two overall chain statuses are the same,
     the best overall status is the shorter one.  The overall chain status
     is defined as the worst of the individual certificate statuses in the
     chain.  That is, if all certs in a chain are CERT_VALID, except one
     which is CERT_EXPIRED, the overall chain status is CERT_EXPIRED.
   If publicKey is not NULL, compare it to the public key in the selected user
     certificate to make sure it is the right one.  If publicKey is NULL,
     allow a certificate for the user with any public key.
   The calling routine must initialize the certChain list.
   On success, certChain contains the chain where each entry is the
     certificate DER. The "bottom" of the chain comes first in the list.
     The caller can use DERToCertificate to decode the certs in the chain.
     Note that DERToCertificate will not return an error since the
     certificate was already successfully decoded.
   Also, on success, the ChainStatusInfo pointed to by chainStatus has
     the overall and individual certificate statuses.  The array for
     chainStatus->individual corresponds to the certificates in certChain
     where chainStatus->individual[0] is the status for the certificate
     at the "bottom" of the chain, etc.  Note that usually, an application
     is only interested in the overall chain status.  The individual
     certificate statuses are provided only for extra detail.
   If directCertOnly is FALSE, chain lengths up to MAX_CERT_CHAIN_LEN
     will be allowed.  This is the usual case for finding senders and
     recipients of messages.  Setting directCertOnly limits the certificate
     chain to only one certificate issued directly by the logged-in RIPEM
     user.  This is useful for operations, such as revoking or setting chain
     length allowed, which are only meaningful on certificates issued
     directly by the logged-in user.
   If no chain can be found, this sets chainStatus->overall to 0,
     the certChain is empty, and values in chainStatus->individual are
     undefined.
   On success, the return value is NULL, otherwise it is an error string.
 */
char *SelectCertChain
  (ripemInfo, certChain, chainStatus, name, publicKey, directCertOnly,
   ripemDatabase)
RIPEMInfo *ripemInfo;
TypList *certChain;
ChainStatusInfo *chainStatus;
DistinguishedNameStruct *name;
R_RSA_PUBLIC_KEY *publicKey;
BOOL directCertOnly;
RIPEMDatabase *ripemDatabase;
{
  ChainStruct chainStruct;
  DistinguishedNameStruct *nameCopy = (DistinguishedNameStruct *)NULL;
  R_RSA_PUBLIC_KEY keyCopy;
  char *errorMessage;
  unsigned int i;

  /* For error, break to end of do while (0) block. */
  do {
    /* Free the incoming list first to make sure it is empty. */
    FreeList (certChain);

    /* Allocate on the heap since it is over 1000 bytes.
     */
    if ((nameCopy = (DistinguishedNameStruct *)malloc (sizeof (*nameCopy)))
        == (DistinguishedNameStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* Normalize the name and public key, if given, so that bit-wise
         compares in CompleteCertChain will work.
     */
    *nameCopy = *name;
    if ((errorMessage = NormalizeNameStruct (nameCopy)) != (char *)NULL)
      break;
    if (publicKey != (R_RSA_PUBLIC_KEY *)NULL) {
      keyCopy = *publicKey;
      if ((errorMessage = NormalizePublicKeyStruct (&keyCopy)) != (char *)NULL)
        break;
    }    

    /* Call CompleteCertChain with the initial conditions.  Allow any
         initial issuer name.
     */
    chainStruct.chainLen = 0;
    chainStruct.maxChainLen = directCertOnly ? 1 : MAX_CERT_CHAIN_LEN;
    if ((errorMessage = CompleteCertChain
         (ripemInfo, &chainStruct, nameCopy,
          publicKey == (R_RSA_PUBLIC_KEY *)NULL ? publicKey : &keyCopy,
          (DistinguishedNameStruct *)NULL, ripemDatabase)) != (char *)NULL)
      /* No certs are allocated in chainStruct so no need to freed */
      break;

    chainStatus->overall = chainStruct.chainStatus;
    if (chainStatus->overall == 0)
      /* Couldn't find a chain.  No certs are allocated in chainStruct so
           no need to free */
      break;

    /* We have a chain, so transfer the certs and certInfos from the
         chainStruct to the certChain list and chainStatus.
     */
    for (i = 0; i < chainStruct.chainLen; ++i) {
      if ((errorMessage = AddToList
           ((TypListEntry *)NULL, chainStruct.certInfos[i].cert,
            chainStruct.certInfos[i].certLen, certChain)) != (char *)NULL)
        /* Error, so break.  The cleanup after this for loop will free
             this and remaining certs in the chainStruct. */
        break;

      chainStatus->individual[i] = chainStruct.certInfos[i].certStatus;
    }

    /* If we broke on error, free the remaining certs which were not
         transferred to the certChain list. */
    for (; i < chainStruct.chainLen; ++i)
      free (chainStruct.certInfos[i].cert);
  } while (0);

  free (nameCopy);
  return (errorMessage);
}

/* On input, the certStruct has the name and public key to validate,
     and certStruct->notBefore and notAfter contain the validity
     period. For example, notBefore can be set to the result of R_time and
     notAfter set to notBefore plus the number of seconds in 2 years.
     It is an error if notAfter is less than notBefore.
   This sets the issuerName to the user in ripemInfo, and sets other fields
     to default values.  This then signs with ripemInfo's private key using
     the given digestAlgorithm and inserts the certificate into the public
     key database.
   This is useful for validating the sender of a message after getting
     the self-signed certificate.
   This returns the error ERR_CERT_ALREADY_VALIDATED if the user in ripemInfo
     has already issued a certificate (even if it was revoked) and if the
     validity period in certStruct does not begin after the end of the
     already-issued certificate's validity period.  This prevents
     making a new certificate with an overlapping or earlier validity
     period.
   Returns NULL for success, otherwise an error message.
 */
char *ValidateAndWriteCert
  (ripemInfo, certStruct, digestAlgorithm, ripemDatabase)
RIPEMInfo *ripemInfo;
CertificateStruct *certStruct;
RIPEMDatabase *ripemDatabase;
{
  unsigned char *certDER = (unsigned char *)NULL;
  unsigned int digestLen, maxCertDERLen, certDERLen;
  char *errorMessage = (char *)NULL;
  BOOL alreadyValidated;

  /* For error, break to end of do while (0) block. */
  do {
    if ((errorMessage = CheckAlreadyValidated
         (ripemInfo, &alreadyValidated, &certStruct->subject,
          &certStruct->publicKey, certStruct->notBefore, ripemDatabase)) != 0)
      break;
    if (alreadyValidated) {
      errorMessage = ERR_CERT_ALREADY_VALIDATED;
      break;
    }
    
    if (certStruct->notAfter < certStruct->notBefore) {
      errorMessage =
        "End of certificate validity period is before the beginning.";
      break;
    }

    certStruct->digestAlgorithm = digestAlgorithm;
    certStruct->issuer = ripemInfo->userDN;

    /* Keep the same subject name and key. */

    /* Now set the serial number to the digest of the certStruct.
       It doesn't matter what this digest is, so long as it is unique. */
    R_DigestBlock
      (certStruct->serialNumber, &digestLen, (unsigned char *)certStruct,
       sizeof (*certStruct), certStruct->digestAlgorithm);

    /* Allocate buffer for certificate DER and sign it.
     */
    maxCertDERLen =
      len_certificate (certStruct, PubKeyToDERLen (&certStruct->publicKey)) +
      4 + MAX_UNSIGNED_TO_SIGNED_DELTA;

    if ((certDER = (unsigned char *)malloc
         (maxCertDERLen)) == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    SignCert (certDER, &certDERLen, certStruct, &ripemInfo->privateKey);

    if ((errorMessage = WriteCert (certDER, ripemDatabase)) != (char *)NULL)
      break;
  } while (0);

  free (certDER);
  return (errorMessage);
}

/* If the certificate issuer and subject are the same and the public
     key verifies the signature, set isSelfSigned to non-zero, otherwise
     set to zero.
 */
void CheckSelfSignedCert (isSelfSigned, certStruct, innerDER, innerDERLen)
int *isSelfSigned;
CertificateStruct *certStruct;
unsigned char *innerDER;
unsigned int innerDERLen;
{
  /* Default to not self-signed */
  *isSelfSigned = 0;

  if (R_memcmp ((POINTER)&certStruct->issuer, (POINTER)&certStruct->subject,
                sizeof (certStruct->issuer)) != 0)
    /* issuer != subject */
    return;

  if (R_VerifyBlockSignature
      (innerDER, innerDERLen, certStruct->signature,
       certStruct->signatureLen, certStruct->digestAlgorithm,
       &certStruct->publicKey) != 0)
    /* public key does not verify signature. */
    return;

  *isSelfSigned = 1;
}

/* Return the index in the name of the smart name.  This can be used to
     index into AVATag, AVAValues, AVATypes.
 */
unsigned int GetDNSmartNameIndex (name)
DistinguishedNameStruct *name;
{
  int typePriority = 0;
  unsigned int i, smartNameIndex;

  /* Go through the AVAs, setting nameIndex to the last common name, or
       to the last title if there are no common names.
   */
  for (i = 0; i < MAX_AVA; ++i) {
    if (name->AVATypes[i] == -1)
      /* There are no more AVAs */
      break;

    if (name->AVATypes[i] == ATTRTYPE_TITLE && typePriority <= 1) {
      smartNameIndex = i;
      typePriority = 1;
    }
    if (name->AVATypes[i] == ATTRTYPE_COMMONNAME && typePriority <= 2) {
      smartNameIndex = i;
      typePriority = 2;
    }
  }

  if (typePriority == 0)
    /* There are no common names or titles, so use the least significant AVA */
    smartNameIndex = i - 1;

  return (smartNameIndex);
}

/* Uses GetDNSmartNameIndex to return the values of the smart name.
 */
char *GetDNSmartNameValue (name)
DistinguishedNameStruct *name;
{
  return (name->AVAValues[GetDNSmartNameIndex (name)]);
}

/* For each cert in certList, first check if it is already in the
     database, and insert it if not.
   ripemInfo is only used for debug and debugStream.
 */
char *InsertCerts (certList, ripemInfo, ripemDatabase)
TypList *certList;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  TypListEntry *certListEntry;
  char *errorMessage;

  for (certListEntry = certList->firstptr;
       certListEntry != (TypListEntry *)NULL;
       certListEntry = certListEntry->nextptr) {
    if ((errorMessage = InsertUniqueCert
         ((unsigned char *)certListEntry->dataptr, ripemInfo, ripemDatabase))
        != (char *)NULL)
      return (errorMessage);
  }

  return ((char *)NULL);
}

/* First check if certDER is already in the database, and insert it if not.
   ripemInfo is only used for debug and debugStream.
 */
char *InsertUniqueCert (certDER, ripemInfo, ripemDatabase)
unsigned char *certDER;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  TypListEntry *selectedCertsEntry;
  TypList selectedCerts;
  char *errorMessage = (char *)NULL;
  int certLen;

  InitList (&selectedCerts);

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    if ((certLen = DERToCertificate
         (certDER, certStruct, (CertFieldPointers *)NULL)) < 0) {
      /* Can't decode, so just skip and try the next one. */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
                 "Can't decode certificate for inserting into database\n");
      continue;
    }

    /* Select certs from the database with a matching smart name.
     */
    if ((errorMessage = GetCertsBySmartname
         (ripemDatabase, &selectedCerts,
          GetDNSmartNameValue (&certStruct->subject), ripemInfo))
        != (char *)NULL)
      break;

    /* Now search for a matching DER.
     */
    for (selectedCertsEntry = selectedCerts.firstptr;
         selectedCertsEntry != (TypListEntry *)NULL;
         selectedCertsEntry = selectedCertsEntry->nextptr) {
      if (R_memcmp
          ((POINTER)certDER, (POINTER)selectedCertsEntry->dataptr, certLen)
          == 0)
        /* Found a match */
        break;
    }

    if (selectedCertsEntry != (TypListEntry *)NULL)
      /* Broke out of loop before ending because we found the cert already
           in the database, so do not insert it. */
      continue;

    if ((errorMessage = WriteCert (certDER, ripemDatabase)) != (char *)NULL)
      break;
  } while (0);

  FreeList (&selectedCerts);
  free (certStruct);
  return (errorMessage);
}

/* First select a chain for the CRL's issuer and verify its signature.
   Then check if the CRL is already in the database, and insert it if not.
   If this can't decode or verify the CRL, this does nothing.
   Return null for success or error string.
 */
char *VerifyAndInsertCRL (crlDER, ripemInfo, ripemDatabase)
unsigned char *crlDER;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  ChainStruct chainStruct;
  CRLStruct *crlStruct = (CRLStruct *)NULL;
  CRLFieldPointers fieldPointers;
  CertificateStruct *issuerCertStruct = (CertificateStruct *)NULL;
  char *errorMessage = (char *)NULL;
  int crlLen;
  unsigned char publicKeyDigest[MD5_LEN];
  unsigned int i;

  /* Set to NULL so we can free on error. */
  chainStruct.certInfos[0].certStruct = (CertificateStruct *)NULL;

  /* Setting to 1 means we won't try to free any certs returned by
       CompleteCertChain until there are some. */
  chainStruct.chainLen = 1;
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the crlStruct on the heap since it is so big. */
    if ((crlStruct = (CRLStruct *)malloc (sizeof (*crlStruct)))
        == (CRLStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* Allocate the certStruct on the heap since it is so big. */
    if ((issuerCertStruct = (CertificateStruct *)malloc
         (sizeof (*issuerCertStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* We are going to put CRL info in the "topmost" cert in the chainStruct,
         so allocate the certStruct now.  Also pre-zeroize it so fields
         will have a default value.
     */
    if ((chainStruct.certInfos[0].certStruct = (CertificateStruct *)malloc
         (sizeof (*chainStruct.certInfos[0].certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    R_memset ((POINTER)chainStruct.certInfos[0].certStruct, 0,
              sizeof (*chainStruct.certInfos[0].certStruct));

    if ((crlLen = DERToCRL (crlDER, crlStruct, &fieldPointers)) < 0) {
      /* Can't decode, so just skip and try the next one. */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
                 "Can't decode CRL for inserting into database\n");
      break;
    }

    /* Free any certs allocated by CompleteCertChain on previous
         iterations.  chainLen will be set to 1 below. */
    for (i = 1; i < chainStruct.chainLen; ++i)
      free (chainStruct.certInfos[i].cert);

    /* Initialize a ChainStruct to make the CRL look like the "topmost"
         cert so that CompleteCertChain will verify its signature
         and select the right public key for the issuer.
     */
    chainStruct.chainLen = 1;
    chainStruct.maxChainLen = MAX_CERT_CHAIN_LEN;
    chainStruct.certInfos[0].certStruct->issuer = crlStruct->issuer;
    chainStruct.certInfos[0].certStruct->digestAlgorithm =
      crlStruct->digestAlgorithm;
    R_memcpy
      ((POINTER)chainStruct.certInfos[0].certStruct->signature,
       (POINTER)crlStruct->signature, crlStruct->signatureLen);
    chainStruct.certInfos[0].certStruct->signatureLen =
      crlStruct->signatureLen;
    chainStruct.certInfos[0].fieldPointers.innerDER =
      fieldPointers.innerDER;
    chainStruct.certInfos[0].fieldPointers.innerDERLen =
      fieldPointers.innerDERLen;

    /* Find the issuer's cert.  If the CRL is already the logged-in user,
         this will not add a new certificate but will try to get the
         status of the CRL as if it were a certificate.  It may read
         arbitrary values for notBefore and notAfter, but we don't care. */
    if ((errorMessage = CompleteCertChain
         (ripemInfo, &chainStruct, (DistinguishedNameStruct *)NULL,
          (R_RSA_PUBLIC_KEY *)NULL, (DistinguishedNameStruct *)NULL,
          ripemDatabase)) != (char *)NULL) {
      /* Set to 1 since there are no allocated certs to free. */
      chainStruct.chainLen = 1;
      break;
    }

    if (chainStruct.chainStatus == 0) {
      /* Could not find the issuer's public key.  Try next CRL. */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
           "Can't find issuer public key for inserting CRL into database\n");

      /* Set to 1 since there are no allocated certs to free. */
      chainStruct.chainLen = 1;
      break;
    }

    /* Found a public chain for the issuer. */
    if (chainStruct.chainLen == 1) {
      /* No certificate for the CRL's issuer was added.  This means
           the logged-in user is the issuer, so get that public key
           digest. */
      if ((errorMessage = GetPublicKeyDigest
           (publicKeyDigest, &ripemInfo->publicKey)) != (char *)NULL)
        break;
    }
    else {
      /* Decode the issuer's cert to get the public key and use it to insert
           into  the database (if it isn't already in there).
         Don't check error on decoding the issuer cert since we know it is
           has already been decoded once.
       */
      DERToCertificate
        (chainStruct.certInfos[1].cert, issuerCertStruct,
         (CertFieldPointers *)NULL);
      if ((errorMessage = GetPublicKeyDigest
           (publicKeyDigest, &issuerCertStruct->publicKey)) != (char *)NULL)
        break;
    }

    /* Insert in the database if it isn't already there. */
    if ((errorMessage = MaybeWriteCRL
         (crlDER, (unsigned int)crlLen, crlStruct->lastUpdate, publicKeyDigest,
          ripemDatabase)) != (char *)NULL)
      break;
  } while (0);

  free (crlStruct);
  free (chainStruct.certInfos[0].certStruct);
  free (issuerCertStruct);

  /* Free any certs allocated by CompleteCertChain */
  for (i = 1; i < chainStruct.chainLen; ++i)
    free (chainStruct.certInfos[i].cert);
  return (errorMessage);
}

/* Set alias to the MD5 of name struct plus the serialNumber after leading
     zeroes have been stripped.
   serialNumberLen is the number of bytes in serialNumber.
 */
void ComputeIssuerSerialAlias (alias, name, serialNumber, serialNumberLen)
unsigned char *alias;
DistinguishedNameStruct *name;
unsigned char *serialNumber;
unsigned int serialNumberLen;
{
  R_DIGEST_CTX md5;
  unsigned int digestLen;

  /* Strip leading zeroes off serialNumber. */
  while ((serialNumberLen > 0) && (*serialNumber == 0)) {
    ++serialNumber;
    --serialNumberLen;
  }
  
  R_DigestInit (&md5, DA_MD5);
  R_DigestUpdate (&md5, (unsigned char *)name, sizeof (*name));
  R_DigestUpdate (&md5, serialNumber, serialNumberLen);
  R_DigestFinal (&md5, alias, &digestLen);
}

/* Return TRUE if alias is in the ripemInfo's issuerSerialAlias table,
     FALSE if not.
 */
BOOL IsIssuerSerialAlias (ripemInfo, alias)
RIPEMInfo *ripemInfo;
unsigned char *alias;
{
  unsigned int i;

  for (i = 0; i < ripemInfo->z.issuerSerialAliasCount; ++i) {
    if (R_memcmp
        ((POINTER)&ripemInfo->z.issuerSerialAliases[i * MD5_LEN],
         (POINTER)alias, MD5_LEN) == 0)
      return (TRUE);
  }

  return (FALSE);
}

/* Encode the publicKey struct in DER and return the MD5 digest.
   This is important because there are multiple algorithm identifiers
     for RSA, and we need a canonical one for public key digests, so
     use the one produced by PubKeyToDER.
   Returns NULL for success, otherwise error string.
 */
char *GetPublicKeyDigest (digest, publicKey)
unsigned char *digest;
R_RSA_PUBLIC_KEY *publicKey;
{
  unsigned char *der;
  unsigned int derLen, digestLen;

  /* Allocate a buffer big enough to hold the encoding. */
  if ((der = (unsigned char *)malloc (PubKeyToDERLen (publicKey)))
      == (unsigned char *)NULL)
    return (ERR_MALLOC);

  /* Encode and digest.  PubKeyToDER doesn't really return an error
       so don't check.
   */
  PubKeyToDER (publicKey, der, &derLen);
  R_DigestBlock (digest, &digestLen, der, derLen, DA_MD5);

  free (der);
  return ((char *)NULL);
}

/* Load the preferences into ripemInfo from ripemDatabase->preferencesFilename.
   If the filename is NULL or the entry for the RIPEM user doesn't exist,
     this returns ERR_PREFERENCES_NOT_FOUND.
   If the preferences decodes badly or the signature doesn't check, this
     returns ERR_PREFERENCES_CORRUPT.
 */
char *RIPEMLoadPreferences (ripemInfo, ripemDatabase)
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;
  unsigned char *preferencesDER = (unsigned char *)NULL,
    publicKeyDigest[MD5_LEN], signature[MD5_LEN], computedSignature[MD5_LEN],
    *innerDER;
  unsigned int innerDERLen, digestLen;
  R_DIGEST_CTX digestContext;
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Get the preferences DER for the RIPEM user.
     */
    if ((errorMessage = GetPublicKeyDigest
         (publicKeyDigest, &ripemInfo->publicKey)) != (char *)NULL)
      break;
    if ((errorMessage = GetPreferencesByDigest
         (ripemDatabase, &preferencesDER, publicKeyDigest, ripemInfo))
        != (char *)NULL)
      break;
    if (preferencesDER == (unsigned char *)NULL) {
      errorMessage = ERR_PREFERENCES_NOT_FOUND;
      break;
    }

    /* Decode the preferences and check the signature which is the
         digest of the inner DER concatenated with the passwordDigest.
     */
    if ((errorMessage = DERToPreferences
         (preferencesDER, ripemInfo, signature, &innerDER, &innerDERLen))
        != (char *)NULL)
      break;
    R_DigestInit (&digestContext, DA_MD5);
    R_DigestUpdate (&digestContext, innerDER, innerDERLen);
    R_DigestUpdate (&digestContext, ripemInfo->passwordDigest, MD5_LEN);
    R_DigestFinal (&digestContext, computedSignature, &digestLen);
    if (R_memcmp
        ((POINTER)computedSignature, (POINTER)signature, MD5_LEN) != 0) {
      /* Preferences in ripemInfo will be reset below. */
      errorMessage = ERR_PREFERENCES_CORRUPT;
      break;
    }
  } while (0);

  if (errorMessage != (char *)NULL)
    /* Reset preferences on any error */
    RIPEMResetPreferences (ripemInfo);

  free (preferencesDER);
  R_memset ((POINTER)&digestContext, 0, sizeof (digestContext));
  return (errorMessage);
}

/* Encode the preferences in ripemInfo, sign with ripemInfo's passwordDigest
     and write to ripemDatabase->preferencesFilename.
   It is an error if the ripemDatabase->preferencesFilename is NULL.
   Returns NULL for success, else an error string.
 */
char *RIPEMSavePreferences (ripemInfo, ripemDatabase)
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;
  R_DIGEST_CTX digestContext;
  unsigned char *der, signature[MD5_LEN], publicKeyDigest[MD5_LEN];
  unsigned int maxDERLen, derLen, digestLen;
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate buffer for the DER and encode the inner info.
     */
    maxDERLen = len_preferences (ripemInfo) + 4 + MAX_UNSIGNED_TO_SIGNED_DELTA;
    if ((der = (unsigned char *)malloc (maxDERLen)) == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    PreferencesToDer (ripemInfo, der, &derLen);

    /* Compute signature.
     */
    R_DigestInit (&digestContext, DA_MD5);
    R_DigestUpdate (&digestContext, der, derLen);
    R_DigestUpdate (&digestContext, ripemInfo->passwordDigest, MD5_LEN);
    R_DigestFinal (&digestContext, signature, &digestLen);

    /* Finish encoding and save.
     */
    DerUnsignedToDerSigned (der, &derLen, signature, MD5_LEN, DA_MD5, FALSE);
    if ((errorMessage = GetPublicKeyDigest
         (publicKeyDigest, &ripemInfo->publicKey)) != (char *)NULL)
      break;
    if ((errorMessage = WriteRIPEMPreferences
         (der, derLen, publicKeyDigest, ripemDatabase, ripemInfo))
        != (char *)NULL)
      break;
  } while (0);

  free (der);
  R_memset ((POINTER)&digestContext, 0, sizeof (digestContext));
  return (errorMessage);
}

/* Select the current CRL for the logged-in RIPEM user, set
     the last update time to now and the next update time to the
     supplied value, sign the CRL with the given digestAlgorithm
     and insert the updated CRL into the database.
     It is an error if nextUpdate is before now.
   This will create a new CRL if one does not exist in the database.
   If serialNumber is not NULL, then serialNumber and serialNumberLen
     give the serial number of a user to revoke.  The revocation time
     for the revoked user is set to now.
   If serialNumber is NULL, serialNumberLen is ignored and no new
     revocation entry is added.  This is useful for renewing the CRL
     when it expires.
   This also sets the current CRL last update time in the RIPEM preferences
     to the new value and saves the modified preferences.
   Note that this updates the CRL regardless of whether the CRL last update
     time in the RIPEM preferences doesn't match the actual latest CRL.
     Assume the application has already checked for CERT_CRL_OUT_OF_SEQUENCE
     status and warned the user if necessary.
 */
char *RIPEMUpdateCRL
  (ripemInfo, nextUpdate, serialNumber, serialNumberLen, digestAlgorithm,
   ripemDatabase)
RIPEMInfo *ripemInfo;
UINT4 nextUpdate;
unsigned char *serialNumber;
unsigned int serialNumberLen;
int digestAlgorithm;
RIPEMDatabase *ripemDatabase;
{
  CRLStruct *crlStruct = (CRLStruct *)NULL;
  CRLFieldPointers fieldPointers;
  char *errorMessage;
  unsigned char *selectedCRL = (unsigned char *)NULL, digest[MD5_LEN],
    *newCRL = (unsigned char *)NULL;
  unsigned int newCRLLen;
  int status;
  BOOL found;
  UINT4 now;
  
  /* For error, break to end of do while (0) block. */
  do {
    R_time (&now);
    if (nextUpdate < now) {
      errorMessage = "Next update time for CRL is earlier than now.";
      break;
    }

    /* Allocate the crlStruct on the heap because it's big. */
    if ((crlStruct = (CRLStruct *)malloc
         (sizeof (*crlStruct))) == (CRLStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    if ((errorMessage = GetPublicKeyDigest (digest, &ripemInfo->publicKey))
        != (char *)NULL)
      break;
    if ((errorMessage = GetLatestCRL
         (ripemDatabase, &selectedCRL, digest, now)) != (char *)NULL)
      break;

    if (selectedCRL == (unsigned char *)NULL) {
      /* We need to create a new CRL.  Set issuer name to the logged-
           in user and other fields to defaults.  Note that we must
           set fieldPointers.crlEntriesDER to NULL so CRLToDer will
           work correctly.
       */
      crlStruct->digestAlgorithm = digestAlgorithm;
      crlStruct->issuer = ripemInfo->userDN;
      fieldPointers.crlEntriesDER = (unsigned char *)NULL;
      /* last and next update are set below. */
    }
    else {
      /* We found the CRL. Decode it and check the signature.
       */
      if (DERToCRL (selectedCRL, crlStruct, &fieldPointers) < 0) {
        /* CRL in database is munged.  Maybe we should give an option to
             create a fresh CRL. */
        errorMessage = "Cannot decode CRL from database to update it.";
        break;
      }
      if ((status = R_VerifyBlockSignature
           (fieldPointers.innerDER, fieldPointers.innerDERLen,
            crlStruct->signature, crlStruct->signatureLen,
            crlStruct->digestAlgorithm, &ripemInfo->publicKey)) != 0) {
        sprintf (ripemInfo->errMsgTxt, "%s while checking signature on CRL.",
                 FormatRSAError (status));
        errorMessage = ripemInfo->errMsgTxt;
        break;
      }

      if (serialNumber != (unsigned char *)NULL) {
        /* Find out if the serial number to add is already in the CRL.
         */
        if (FindCRLEntry
            (&found, fieldPointers.crlEntriesDER, serialNumber,
             serialNumberLen) < 0) {
          errorMessage = "Cannot decode CRL from database to update it.";
          break;
        }
        if (found) {
          /* Serial number is already in the CRL, so set to NULL so it
               won't be added again. */
          if (ripemInfo->debug > 1)
            fprintf (ripemInfo->debugStream,
                     "Serial number to revoke is already in the CRL.\n");
          serialNumber = (unsigned char *)NULL;
        }
      }
    }

    /* Set last and next update times for new CRL. */
    crlStruct->lastUpdate = now;
    crlStruct->nextUpdate = nextUpdate;

    /* Allocate buffer for CRL, encode and sign it.
     */
    if ((newCRL = (unsigned char *)malloc
         (len_crl
          (crlStruct, fieldPointers.crlEntriesDER, serialNumber,
           serialNumberLen) + 4 + MAX_UNSIGNED_TO_SIGNED_DELTA))
        == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    CRLToDer
      (crlStruct, fieldPointers.crlEntriesDER, serialNumber, serialNumberLen,
       now, newCRL, &newCRLLen);
    R_SignBlock
      (crlStruct->signature, (unsigned int *)&crlStruct->signatureLen, newCRL,
       newCRLLen, crlStruct->digestAlgorithm, &ripemInfo->privateKey);
    DerUnsignedToDerSigned
      (newCRL, &newCRLLen, crlStruct->signature, crlStruct->signatureLen,
       crlStruct->digestAlgorithm, TRUE);

    /* Insert the new CRL in the database.
     */
    if ((errorMessage = WriteCRL (newCRL, digest, ripemDatabase))
        != (char *)NULL)
      break;

    /* Set the last update time in the preferences and save the preferences.
     */
    ripemInfo->z.currentCRLLastUpdate = crlStruct->lastUpdate;
    if ((errorMessage = RIPEMSavePreferences (ripemInfo, ripemDatabase))
        != (char *)NULL)
      break;
  } while (0);

  free (selectedCRL);
  free (newCRL);
  return (errorMessage);
}

/* Set the chain length allowed for a given user, replacing any
     chain length allowed info already in ripemInfo for that user.
   The user is indicated by the MD5 digest of their public key, which
     may be obtained with GetPublicKeyDigest.  chainLenAllowed is the
     maximum length of a certificate chain they are trusted to make.
     This is used to enable extended certification trust.
   A chainLenAllowed of zero is equivalent to reverting to
     "direct trust", which is the default.
   This also saves the updated preferences.
   Returns NULL for success, otherwise an error string.
 */
char *SetChainLenAllowed
  (ripemInfo, publicKeyDigest, chainLenAllowed, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char *publicKeyDigest;
unsigned int chainLenAllowed;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;

  if ((errorMessage = UpdateChainLensAllowed
       (ripemInfo, publicKeyDigest, chainLenAllowed)) != (char *)NULL)
    return (errorMessage);
  return (RIPEMSavePreferences (ripemInfo, ripemDatabase));
}

/* Set the chain length allowed for a given user, replacing any
     chain length allowed info already in ripemInfo for that user.
   The user is indicated by the MD5 digest of their public key, which
     may be obtained with GetPublicKeyDigest.  chainLenAllowed is the
     maximum length of a certificate chain they are trusted to make.
     This is used to enable extended certification trust.
   A chainLenAllowed of zero is equivalent to reverting to
     "direct trust", which is the default.
   Returns NULL for success, otherwise an error string.
 */
char *UpdateChainLensAllowed (ripemInfo, publicKeyDigest, chainLenAllowed)
RIPEMInfo *ripemInfo;
unsigned char *publicKeyDigest;
unsigned int chainLenAllowed;
{
  unsigned int i, count;

  for (i = 0; i < ripemInfo->z.chainLensAllowedCount; ++i) {
    if (R_memcmp ((POINTER)ripemInfo->z.chainLensAllowed[i].publicKeyDigest,
                  (POINTER)publicKeyDigest, MD5_LEN) == 0) {
      /* Found the extent info.  Simply set to the new value. */
      ripemInfo->z.chainLensAllowed[i].chainLenAllowed = chainLenAllowed;
      return ((char *)NULL);
    }
  }

  /* The publicKeyDigest is not already in the ripemInfo. */
  if (chainLenAllowed == 0)
    /* There is no need to put in a value of zero.  Do nothing. */
    return ((char *)NULL);

  /* Add a new entry.
   */
  count = ripemInfo->z.chainLensAllowedCount;
  if ((ripemInfo->z.chainLensAllowed = (ChainLenAllowedInfo *)R_realloc
       (ripemInfo->z.chainLensAllowed,
        (count + 1) * sizeof (*ripemInfo->z.chainLensAllowed)))
      == (ChainLenAllowedInfo *)NULL) {
    ripemInfo->z.chainLensAllowedCount = 0;
    return (ERR_MALLOC);
  }

  R_memcpy
    ((POINTER)ripemInfo->z.chainLensAllowed[count].publicKeyDigest,
     publicKeyDigest, MD5_LEN);
  ripemInfo->z.chainLensAllowed[count].chainLenAllowed = chainLenAllowed;
  ripemInfo->z.chainLensAllowedCount = count + 1;

  return ((char *)NULL);
}

/* For each name in issuerNames, select the best chain starting from
     a cert with that issuer name and the logged-in user's subject name
     and key, then add the issuer certs to ripemInfo->issuerCerts.
   For each chain successfully found, increment ripemInfo->z.issuerChainCount.
     (This initialized to zero by RipemInfoConstructor.)
   This does not add the "topmost" cert in the chain which is
     the one issued by the logged-in ripem user, since if someone already
     trusts that public key as a topmost issuer, there is no need for
     a certificate chain.
   This assumes there are no duplicate names in issuerNames.
 */
char *AddUserIssuerCerts (ripemInfo, issuerNames, ripemDatabase)
RIPEMInfo *ripemInfo;
TypList *issuerNames;
RIPEMDatabase *ripemDatabase;
{
  ChainStruct chainStruct;
  TypListEntry *entry;
  char *errorMessage = (char *)NULL;
  unsigned int i;

  /* Setting to 0 means we won't try to free any certs returned by
       CompleteCertChain until there are some. */
  chainStruct.chainLen = 0;

  /* For error, break to end of do while (0) block. */
  do {
    for (entry = issuerNames->firstptr; entry; entry = entry->nextptr) {
      /* Free any certs allocated by CompleteCertChain on previous
           iterations. */
      for (i = 0; i < chainStruct.chainLen; ++i)
        free (chainStruct.certInfos[i].cert);

      /* Call CompleteCertChain with the initial conditions.
       */
      chainStruct.chainLen = 0;
      chainStruct.maxChainLen = MAX_CERT_CHAIN_LEN;
      if ((errorMessage = CompleteCertChain
           (ripemInfo, &chainStruct, &ripemInfo->userDN, &ripemInfo->publicKey,
            (DistinguishedNameStruct *)entry->dataptr, ripemDatabase))
          != (char *)NULL) {
        /* Set to 0 since there are no allocated certs to free. */
        chainStruct.chainLen = 0;
        break;
      }

      if (chainStruct.chainStatus == 0) {
        /* Can't find a chain for this issuer. Try the next.
           Set to 0 since there are no allocated certs to free. */
        chainStruct.chainLen = 0;
        continue;
      }

      /* Add all certs in the chain except the last to issuer certs list.
         Also increment issuerChainCount.
         Assume chainStruct.chainLen is greater than zero.
       */
      ++ripemInfo->z.issuerChainCount;

      for (i = 0; i < (chainStruct.chainLen - 1); ++i) {
        if ((errorMessage = AddToList
             ((TypListEntry *)NULL, chainStruct.certInfos[i].cert,
              chainStruct.certInfos[i].certLen, &ripemInfo->issuerCerts))
            != (char *)NULL)
          break;

        /* The cert was successfully transferred, so set the pointer in
             chainStruct to NULL so it won't be freed when cleaning up. */
        chainStruct.certInfos[i].cert = (unsigned char *)NULL;
      }
      if (errorMessage != (char *)NULL)
        /* Broke loop because of error */
        break;
    }
    if (errorMessage != (char *)NULL)
      /* Broke loop because of error */
      break;
  } while (0);

  /* Free any certs allocated by CompleteCertChain */
  for (i = 0; i < chainStruct.chainLen; ++i)
    free (chainStruct.certInfos[i].cert);
  return (errorMessage);
}

/* Get the CRL for the user in ripemInfo, and also check its signature.
   This returns an error if the CRL cannot be found or the signature is
     corrupt.  Otherwise, if the CRL is expired, it is still used.
   *crlDER is set to an allocated buffer containing the CRL, and crlDERLen to
     its length.  On error return, *crlDER may or may not be set to an
     allocated buffer; the caller should free it anyway.
   Returns NULL for success, otherwise error string.
 */
char *GetLoggedInLatestCRL (crlDER, crlDERLen, ripemInfo, ripemDatabase)
unsigned char **crlDER;
int *crlDERLen;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  CRLStruct *crlStruct = (CRLStruct *)NULL;
  CRLFieldPointers fieldPointers;
  char *errorMessage;
  unsigned char issuerKeyDigest[MD5_LEN];
  int status;
  UINT4 now;
  
  *crlDER = (unsigned char *)NULL;

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the crlStruct on the heap because it's big. */
    if ((crlStruct = (CRLStruct *)malloc
         (sizeof (*crlStruct))) == (CRLStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    if ((errorMessage = GetPublicKeyDigest
         (issuerKeyDigest, &ripemInfo->publicKey)) != (char *)NULL)
      break;
    R_time (&now);
    if ((errorMessage = GetLatestCRL
         (ripemDatabase, crlDER, issuerKeyDigest, now)) != (char *)NULL)
      break;
    if (*crlDER == (unsigned char *)NULL) {
      errorMessage = "CRL for the logged-in user cannot be found.";
      break;
    }

    if ((*crlDERLen = DERToCRL (*crlDER, crlStruct, &fieldPointers)) < 0) {
      errorMessage = "CRL for the logged-in user cannot be decoded.";
      break;
    }
    if ((status = R_VerifyBlockSignature
         (fieldPointers.innerDER, fieldPointers.innerDERLen,
          crlStruct->signature, crlStruct->signatureLen,
          crlStruct->digestAlgorithm, &ripemInfo->publicKey)) != 0) {
      sprintf (ripemInfo->errMsgTxt, "%s while checking logged-in user's CRL signature.",
               FormatRSAError (status));
      errorMessage = ripemInfo->errMsgTxt;
      break;
    }
  } while (0);

  free (crlStruct);
  return (errorMessage);
}

/* certDER buffer is already allocated.  Encode and sign the info in certStruct
     with the privateKey and return the length in certDERLen.
   This leaves the signature in the certStruct buffer.
 */
static void SignCert (certDER, certDERLen, certStruct, privateKey)
unsigned char *certDER;
unsigned int *certDERLen;
CertificateStruct *certStruct;
R_RSA_PRIVATE_KEY *privateKey;
{
  CertificateToDer (certStruct, certDER, certDERLen);

  R_SignBlock
    (certStruct->signature, (unsigned int *)&certStruct->signatureLen, certDER,
     *certDERLen, certStruct->digestAlgorithm, privateKey);

  DerUnsignedToDerSigned
    (certDER, certDERLen, certStruct->signature, certStruct->signatureLen,
     certStruct->digestAlgorithm, TRUE);
}

/* This looks at the subject of the topmost cert in chainStruct and tries
     to complete the chain by adding issuer certs up to one issued by the
     RIPEM user in ripemInfo. (The "topmost" cert is defined as the cert at
     chainStruct->certInfos[chainStruct->chainLen - 1].)
   This routine calls itself recursively, increasing chainStruct->chainLen
     by one each time.  To initialize, this should be called for the first
     time with chainStruct->chainLen set to zero.  In this case, this selects
     certificates with initialName as the subject and finds the best chain.
     If initialKey and/or initialIssuerName is not null, this also ensures
     that the "bottommost" cert has that public key or issuer name.
     If initialIssuerName and initialKey are non-null, this only ensures
     the smart name match for the initialName (not the whole DN)
     presumably because the public key/issuer name match is strong
     enough and in this case we want to be more loose in accepting
     subject names since some issuers modify them.
     (initialIssuerName is only used such as when finding issuer certificates
     along a very particular chain path.) initialName, initialKey and
     initialIssuerName are ignored when chainLen is greater than 0.
   Alternatively, this can be used to select a public key for the issuer
     of a CRL and check the CRL signature by making the CRL look like
     the "topmost" certificate as follows.  Set the chainStruct's chainLen to
     1.  Set up the certStruct for the certInfo[0] with the issuer, signature
     and digestAlgorithm set to the values from the CRL.  Set up the
     fieldPointers with the innerDER and innerDERLen from the CRL.
     This will "complete" the chain and check the signature on the CRL
     in this "topmost" cert location.  This technique is better than
     just selecting a certificate chain for the issuer because it might
     not get the right public key.
   If a chain is found, chainStruct->chainStatus is non-zero, and allocated
     certs are returned in the chainStruct->certInfos for all issuer
     certs above the topmost cert.  The caller is responsible for
     transferring or freeing these certs.  The chainStruct->chainLen is also
     modified to the complete chain length.  The chainStruct->chainStatus
     applies to those certs starting at the topmost cert and above and
     chainStruct->certInfos.certStatus entries for the topmost cert and
     above contain the individual cert statuses.
   This uses the certStruct and fieldPointers in chainStruct->certInfos
     starting at the topmost cert and "below" (lower index numbers) to
     determine the issuer of to topmost cert, to verify the signature
     on the topmost cert and to make sure there are no closed loops
     within the chain.  Also, on return, the certStruct and fieldPointers
     in chainStruct->certInfos above the topmost cert are undefined and
     should be ignored.
   If a chain cannot be completed, chainStruct->chainStatus is set to zero
     and no allocated certs are returned (and so do not need to be freed).
     The causes of not completing are not finding an issuer whose public
     key verifies the signature on the topmost cert, or chain length
     exceeds chainStruct->maxChainLen.
   Note that if chainStruct->maxChainLen is set to 1, this will select
     the best direct certificate.
   In the case where the topmost cert's issuer is already the RIPEM user,
     this checks the chain length against the subject's chain len allowed
     (which was set by SetChainLensAllowed) and verifies the topmost cert's
     signature with the RIPEM user's public key.  On success,
     chainStruct->chainStatus is set to the cert status for the topmost cert,
     otherwise to 0. (chainStruct->chainLen is not modified.)
   On success, the return value is (char *)NULL, otherwise an error string.
     If this returns an error, it makes sure that any certs that were allocated
     in chainStruct->certInfos above the topmost cert are freed
     (and so do not need to be freed by the caller).
 */
static char *CompleteCertChain
  (ripemInfo, chainStruct, initialName, initialKey, initialIssuerName,
   ripemDatabase)
RIPEMInfo *ripemInfo;
ChainStruct *chainStruct;
DistinguishedNameStruct *initialName;
R_RSA_PUBLIC_KEY *initialKey;
DistinguishedNameStruct *initialIssuerName;
RIPEMDatabase *ripemDatabase;
{
  TypList selectedCerts;
  DistinguishedNameStruct *selectedCertsSubject;
  TypListEntry *entry;
  char *errorMessage = (char *)NULL;
  int status, certStatus;
  unsigned int currentChainLen, i;
  CertificateStruct *issuerCertStruct = (CertificateStruct *)NULL;
  ChainCertInfo *subjectInfo, *issuerInfo;
  ChainStruct bestChain;
  unsigned char digest[MD5_LEN];
  R_RSA_PUBLIC_KEY *bestKey = (R_RSA_PUBLIC_KEY *)NULL;
  BOOL better;

  InitList (&selectedCerts);

  /* Save current chain len since chainStruct->chainLen is modified */
  currentChainLen = chainStruct->chainLen;

  /* The "subject" cert is the top cert that comes in via chainStruct.
     The "issuer" cert is the one we need to select from the database.
   */
  if (currentChainLen > 0)
    subjectInfo = &chainStruct->certInfos[currentChainLen - 1];
  
  if (currentChainLen < chainStruct->maxChainLen) {
    /* This is where we will put the issuer info.
       Note that in the initial case where chainLen is zero, what we're
         calling the issuerInfo really pertains to the initial subject
         certificate.  Think of it this way:  the issuerInfo is for the
         cert that we are adding. */
    issuerInfo = &chainStruct->certInfos[currentChainLen];
    
    /* We may be assigning this to an allocated cert,
         so preset to NULL so that we may free it at any time. */
    issuerInfo->cert = (unsigned char *)NULL;
  }

  /* Preset to zero so on error cleanup we won't do anything initially. */
  bestChain.chainLen = 0;
  
  /* For error, break to end of do while (0) block. */
  do {
    /* If we have at least one cert in the chain, check if the cert at the
         top is the RIPEM user */
    if (currentChainLen > 0 && R_memcmp
        ((POINTER)&subjectInfo->certStruct->issuer,
         (POINTER)&ripemInfo->userDN, sizeof (ripemInfo->userDN)) == 0) {
      /* The issuer of the subject cert is the RIPEM user, so we have
           completed the chain.  Check that the chain length falls within
           the value in the chain length allowed for the subject.
         currentChainLen - 1 is the number of certs for which we need to
           trust the user.  A chain length allowed of 1 means they are trusted
           to certify one user, etc.
         Also, always allow a currentChainLen of 1 since this is direct trust.
       */
      if (currentChainLen > 1) {
        /* We are going to need the public key digest for the next step
             so get it now. */
        if ((errorMessage = GetPublicKeyDigest
             (digest, &subjectInfo->certStruct->publicKey)) != (char *)NULL)
          break;
      }
      if (currentChainLen == 1 ||
          GetChainLenAllowed (ripemInfo, digest) >= (currentChainLen - 1)) {
        /* Chain is within the allowed length, so set the chain status to
             the status of the cert. */
        if ((errorMessage = ComputeCertStatus
             (&chainStruct->chainStatus, subjectInfo->certStruct,
              &ripemInfo->publicKey, ripemInfo, ripemDatabase))
            != (char *)NULL)
          break;

        /* The individual cert status is the same as the chainStatus at this
             point. */
        subjectInfo->certStatus = chainStruct->chainStatus;
      }
      else {
        chainStruct->chainStatus = 0;

        /* We do not need to check the cert's signature, so break. */
        break;
      }

      if ((status = R_VerifyBlockSignature
           (subjectInfo->fieldPointers.innerDER,
            subjectInfo->fieldPointers.innerDERLen,
            subjectInfo->certStruct->signature,
            subjectInfo->certStruct->signatureLen,
            subjectInfo->certStruct->digestAlgorithm,
            &ripemInfo->publicKey)) != 0) {
        /* Can't verify the signature.  Just print a warning to the
             debug stream and set chain status to zero. */
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
                   "Warning: %s while checking signature on certificate.\n",
                   FormatRSAError (status));
        chainStruct->chainStatus = 0;
      }

      /* We are done */
      break;
    }

    if (currentChainLen >= chainStruct->maxChainLen) {
      /* We can't fit any more issuer certificates in the chain, so fail. */
      chainStruct->chainStatus = 0;
      break;
    }

    /* We are going to find the best of many possible chains, so
         initialize bestChain's chainStatus to zero so that
         the first chain found will become the best.
     */
    bestChain.chainStatus = 0;

    if (currentChainLen == 0)
      /* Select certs for the initial subject name. */
      selectedCertsSubject = initialName;
    else
      /* Select certs for the issuer of the topmost cert. */
      selectedCertsSubject = &subjectInfo->certStruct->issuer;

    /* Select all certs with the issuer as the subject smartname. */
    if ((errorMessage = GetCertsBySmartname
         (ripemDatabase, &selectedCerts,
          GetDNSmartNameValue (selectedCertsSubject), ripemInfo))
        != (char *)NULL)
      break;

    /* Allocate the the cert struct for this issuer and assign it.
       Keep a separate issuerCertStruct pointer since this is
         what we free at the end.  (issuerInfo->certStruct may change.) */
    if ((issuerCertStruct = (CertificateStruct *)malloc
         (sizeof (*issuerCertStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    issuerInfo->certStruct = issuerCertStruct;

    /* Allocate the bestKey on the heap to save stack space. */
    if ((bestKey = (R_RSA_PUBLIC_KEY *)malloc (sizeof (*bestKey)))
        == (R_RSA_PUBLIC_KEY *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
            
    /* Loop through all selected certs, finding the best one.
     */
    for (entry = selectedCerts.firstptr; entry; entry = entry->nextptr) {
      if ((issuerInfo->certLen = DERToCertificate
           ((unsigned char *)entry->dataptr, issuerInfo->certStruct,
            &issuerInfo->fieldPointers)) < 0) {
        /* Error decoding.  Just issue a warning to debug stream and try
             the next cert. */
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
                   "Warning: Cannot decode certificate from database.\n");
        continue;
      }

      /* Only ensure the subject DN if there is no initialKey or
           initialIssuerName. */
      if (!(currentChainLen == 0 && initialKey != (R_RSA_PUBLIC_KEY *)NULL &&
            initialIssuerName != (DistinguishedNameStruct *)NULL)) {
        if (R_memcmp
            ((POINTER)&issuerInfo->certStruct->subject,
             (POINTER)selectedCertsSubject, sizeof (*selectedCertsSubject))
            != 0)
          /* The subject DN of the selected certificate does not match the
               the one we are supposed to select (even though the smart name
               does). */
          continue;
      }

      /* Check to make sure the issuer name of the cert we just selected
           is not a subject name of any of the certs already in the chainStruct
           (including this one which would mean a self-signed cert).
           This prevents us getting in loops.  Note that we don't need
           to do this check if the issuer is the RIPEM user.  This
           also permits the RIPEM user to select a chain for their own
           self-signed certificate.
       */
      if (R_memcmp
          ((POINTER)&issuerInfo->certStruct->issuer,
           (POINTER)&ripemInfo->userDN, sizeof (ripemInfo->userDN)) != 0) {
        for (i = 0; i < currentChainLen; ++i) {
          if (R_memcmp
              ((POINTER)&issuerInfo->certStruct->issuer,
               (POINTER)&chainStruct->certInfos[i].certStruct->subject,
               sizeof (issuerInfo->certStruct->issuer)) == 0)
            break;
        }
        if (i < currentChainLen)
          /* We broke out of the for loop because we found a loop,
               so skip this selected cert and try the next. */
          continue;
      }
      
      if (currentChainLen == 0) {
        /* We are selecting the initial cert, so check if we are supposed
             to constrain the public key and/or issuer name to the given
           values. */
        if (initialKey != (R_RSA_PUBLIC_KEY *)NULL && R_memcmp
            ((POINTER)&issuerInfo->certStruct->publicKey, (POINTER)initialKey,
             sizeof (*initialKey)) != 0)
          /* The public key isn't the right one, so try the next cert. */
          continue;
        if (initialIssuerName != (DistinguishedNameStruct *)NULL && R_memcmp
            ((POINTER)&issuerInfo->certStruct->issuer,
             (POINTER)initialIssuerName, sizeof (*initialIssuerName)) != 0)
          /* The issuer name isn't the right one, so try the next cert. */
          continue;
      }
      else {
        /* There is already a subject certificate in the chain.
             Use the issuer's public key to verify the signature on the
             subject certificate. We do this now to make sure it is
             the right public key from the issuer. */
        if ((status = R_VerifyBlockSignature
             (subjectInfo->fieldPointers.innerDER,
              subjectInfo->fieldPointers.innerDERLen,
              subjectInfo->certStruct->signature,
              subjectInfo->certStruct->signatureLen,
              subjectInfo->certStruct->digestAlgorithm,
              &issuerInfo->certStruct->publicKey)) != 0) {
          /* Can't verify the signature.  Just print a warning to the
               debug stream and try more certs. */
          if (ripemInfo->debug > 1)
            fprintf (ripemInfo->debugStream,
                     "Warning: %s while checking signature on certificate.\n",
                     FormatRSAError (status));
          continue;
        }
      }

      /* This issuer cert is a good candidate, so transfer it to the
           ChainStruct by copying and setting the original pointer to NULL
           so that FreeList (&selectedCerts) won't try to free it.
         Note that issuerInfo->certLen, certStruct and fieldPointers are
           already set. */
      issuerInfo->cert = (unsigned char *)entry->dataptr;
      entry->dataptr = NULL;
      entry->datalen = 0;

      /* The issuer cert is now in ChainStruct, so the new chain length is
           the current length plus one.  (Don't just
           increment chainInfo->chainLen since it may already be modified.)
       */
      chainStruct->chainLen = currentChainLen + 1;

      /* Recursively call CompleteCertChain to find out it the issuer
           cert is validated.  Pass null for initialName, initialKey and
           initialIssuerName which will be ignored. */
      if ((errorMessage = CompleteCertChain
           (ripemInfo, chainStruct, (DistinguishedNameStruct *)NULL,
            (R_RSA_PUBLIC_KEY *)NULL, (DistinguishedNameStruct *)NULL,
            ripemDatabase)) != (char *)NULL)
        break;

      if (chainStruct->chainStatus == 0) {
        /* Couldn't complete the chain, so free the cert which was
             put in issuerInfo and continue with next issuer cert. */
        free (issuerInfo->cert);
        issuerInfo->cert = (unsigned char *)NULL;
        continue;
      }

      /* Determine if the chain we just selected is better than bestChain.
       */
      if (bestChain.chainStatus == 0)
        /* We have not found a chain yet, so make the first one the best. */
        better = TRUE;
      else {
        if (chainStruct->chainStatus < bestChain.chainStatus)
          better = TRUE;
        else if (chainStruct->chainStatus == bestChain.chainStatus)
          /* For equal chain statuses, the better chain is the shorter. */
          better = chainStruct->chainLen < bestChain.chainLen;
        else
          better = FALSE;
      }

      if (!better) {
        /* This chain isn't better.  Free the cert and try the next. */
        free (issuerInfo->cert);
        issuerInfo->cert = (unsigned char *)NULL;
        continue;
      }
      
      /* We need to transfer this chain to bestChain, so free certs in
           the current bestChain.  Then copy and set the issuerInfo->cert
           to NULL since it has been transferred.  Note that when this
           function returns, the certStructs in the certInfos will
           be ignored so it doesn't matter how we transfer them.
         Also save the bestKey for use in ComputeCertStatus after the loop.
       */
      for (i = currentChainLen; i < bestChain.chainLen; ++i)
        free (bestChain.certInfos[i].cert);
      bestChain = *chainStruct;
      issuerInfo->cert = (unsigned char *)NULL;
      *bestKey = issuerInfo->certStruct->publicKey;

      /* Continue with the next issuer cert */
    }
    if (errorMessage != (char *)NULL)
      /* Broke for loop because of error. */
      break;

    if (bestChain.chainStatus != 0) {
      /* We found a chain. */
      if (currentChainLen > 0) {
        /* There is a subject cert already in the chain, so determine its
             status and modify the chain status if needed. */
        if ((errorMessage = ComputeCertStatus
             (&certStatus, subjectInfo->certStruct, bestKey, ripemInfo,
              ripemDatabase)) != (char *)NULL)
          break;

        if (certStatus > bestChain.chainStatus)
          /* This cert's status is worse than any other (above it) in the
               chain we found, so modify the chainStatus. */
          bestChain.chainStatus = certStatus;
      }

      /* We found a chain, so transfer it back to the chainStruct to return.
         Also set the certStatus for the subject as just computed.
         Then set bestChain.chainLen to zero so we won't try freeing it. */
      *chainStruct = bestChain;
      if (currentChainLen > 0)
        subjectInfo->certStatus = certStatus;
      bestChain.chainLen = 0;
    }
    else
      /* No chain.  All certs from issuerInfo and above have been freed.  Just
           set the chainStatus to zero. */
      chainStruct->chainStatus = 0;
  } while (0);

  /* Free the allocated certs being held in bestChain. Note that if
       we successfully found a chain, chainLen was set to zero to
       prevent freeing. */
  for (i = currentChainLen; i < bestChain.chainLen; ++i)
    free (bestChain.certInfos[i].cert);

  if (errorMessage != (char *)NULL &&
      currentChainLen < chainStruct->maxChainLen)
    /* There may be a residual issuerCert, so make sure we free it. */
    free (issuerInfo->cert);

  FreeList (&selectedCerts);
  free (bestKey);
  return (errorMessage);
}

/* Return the chain len allowed for the user by looking in
     ripemInfo->chainLensAllowed for its publicKeyDigest.
   If the user has no entry, return zero.
 */
unsigned int GetChainLenAllowed (ripemInfo, publicKeyDigest)
RIPEMInfo *ripemInfo;
unsigned char *publicKeyDigest;
{
  unsigned int i;

  if (ripemInfo->z.chainLensAllowedCount == 0)
    /* No chain len allowed info, so don't bother digesting */
    return (0);

  for (i = 0; i < ripemInfo->z.chainLensAllowedCount; ++i) {
    if (R_memcmp ((POINTER)ripemInfo->z.chainLensAllowed[i].publicKeyDigest,
                  (POINTER)publicKeyDigest, MD5_LEN) == 0)
      /* Found the extent info. */
      return (ripemInfo->z.chainLensAllowed[i].chainLenAllowed);
  }

  /* not found */
  return (0);
}

/* Set certStatus to the status of certStruct, such as CERT_VALID,
     CERT_EXPIRED, etc.
   ripemInfo is used to log debug messages.  ripemDatabase is used
     to find the CRL.  issuerKey is used to check the signature on
     the CRL.  The digest of the issuerPublicKey is computed locally
     for looking up the CRL.
 */
static char *ComputeCertStatus
  (certStatus, certStruct, issuerKey, ripemInfo, ripemDatabase)
int *certStatus;
CertificateStruct *certStruct;
R_RSA_PUBLIC_KEY *issuerKey;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  UINT4 now;
  char *errorMessage;

  R_time (&now);

  if (now < certStruct->notBefore)
    /* Note that PENDING overrides REVOKED. */
    *certStatus = CERT_PENDING;
  else if (certStruct->notAfter < now) {
    /* Cert is expired.  Find out if it was revoked at the time of
         expiration.  Don't check the CRL sequence for older CRLs. */
    if ((errorMessage = ComputeRevocationStatus
         (certStatus, certStruct->serialNumber,
          sizeof (certStruct->serialNumber), certStruct->notAfter, FALSE,
          issuerKey, ripemInfo, ripemDatabase)) != (char *)NULL)
      return (errorMessage);

    if (*certStatus != CERT_REVOKED)
      /* Convert all but revoked status back to expired. */
      *certStatus = CERT_EXPIRED;
  }
  else {
    /* Not pending or expired, so set to revocation status.  Note that this
         will set certStatus to CERT_VALID if all goes will with the CRL. */
    if ((errorMessage = ComputeRevocationStatus
         (certStatus, certStruct->serialNumber,
          sizeof (certStruct->serialNumber), now, TRUE, issuerKey, ripemInfo,
          ripemDatabase)) != (char *)NULL)
      return (errorMessage);
  }

  return ((char *)NULL);
}

/* Use the digest of the issuerKey to look up the latest CRL for the issuer
     with a last update before time.  Use the issuerKey to verify the signature
     on the CRL.  Then search for a revocation entry with the given
     serial number.  (The digest of the issuerKey is computed locally.)
   revocationStatus is set to CERT_REVOCATION_UNKNOWN, CERT_REVOKED,
     CRL_CRL_OUT_OF_SEQUENCE, CERT_CRL_EXPIRED, or CERT_VALID.
   If the CRL cannot be decoded or the signature fails, this issues a
     warning to the debug stream and sets revocationStatus to
     CERT_REVOCATION_UNKNOWN.
   If the serial number is in the CRL, this returns CRL_REVOKED.
     CERT_REVOKED overrides CERT_CRL_OUT_OF_SEQUENCE and CERT_CRL_EXPIRED.
   If checkCRLSequence is TRUE and issuerKey is ripemInfo->publicKey, this
     uses currentCRLLastUpdate in ripemInfo (if it isn't zero) to make sure
     the last update of the selected CRL matches.  If not, this returns
     CERT_CRL_OUT_OF_SEQUENCE (which overrides CERT_CRL_EXPIRED).
   Lastly, the CRL's next update time and this returns CERT_CRL_EXPIRED
     if it is expired.
   CERT_VALID means a current CRL is found and the serial number is not
     in the CRL entries, and the currendCRLLastUpdate matches if required.
   time is seconds since 1/1/70. Typically, it is set to now, but may
     also be set to a certificate's expiration time to see if it was
     revoked at that time.  If set to an earlier date, checkCRLSequence
     should be set to FALSE.
   Returns value is NULL for OK, else an error string.
 */
static char *ComputeRevocationStatus
  (revocationStatus, serialNumber, serialNumberLen, time, checkCRLSequence,
   issuerKey, ripemInfo, ripemDatabase)
int *revocationStatus;
unsigned char *serialNumber;
unsigned int serialNumberLen;
UINT4 time;
BOOL checkCRLSequence;
R_RSA_PUBLIC_KEY *issuerKey;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  BOOL found;
  CRLStruct *crlStruct = (CRLStruct *)NULL;
  CRLFieldPointers fieldPointers;
  UINT4 now;
  char *errorMessage = (char *)NULL;
  int status;
  unsigned char *crlDER = (unsigned char *)NULL, issuerKeyDigest[MD5_LEN];

  /* Default to revocation unknown */
  *revocationStatus = CERT_REVOCATION_UNKNOWN;
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the crlStruct on the heap because it's big. */
    if ((crlStruct = (CRLStruct *)malloc
         (sizeof (*crlStruct))) == (CRLStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    if ((errorMessage = GetPublicKeyDigest (issuerKeyDigest, issuerKey))
        != (char *)NULL)
      break;
    if ((errorMessage = GetLatestCRL
         (ripemDatabase, &crlDER, issuerKeyDigest, time)) != (char *)NULL)
      break;
    if (crlDER == (unsigned char *)NULL)
      /* No CRL. Status is already revocation unknown. */
      break;

    if (DERToCRL (crlDER, crlStruct, &fieldPointers) < 0) {
      /* Error decoding.  Just issue a warning to debug stream and
           return with revocation unknown */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
                 "Warning: Cannot decode CRL from database.\n");
      break;
    }

    if (crlStruct->lastUpdate > time) {
      /* Somehow GetLatestCRL didn't really find a CRL before time.
         This probably means the LastUpdate: field in the CRL file
           is messed up.  Just print a warning to the
           debug stream and return with revocation unknown. */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
                 "Warning: last update field wrong in CRL file.\n");
      break;
    }
    if ((status = R_VerifyBlockSignature
         (fieldPointers.innerDER, fieldPointers.innerDERLen,
          crlStruct->signature, crlStruct->signatureLen,
          crlStruct->digestAlgorithm, issuerKey)) != 0) {
      /* Can't verify the signature.  Just print a warning to the
           debug stream and return with revocation unknown. */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
                 "Warning: %s while checking signature on CRL.\n",
                 FormatRSAError (status));
      break;
    }

    if (FindCRLEntry
        (&found, fieldPointers.crlEntriesDER, serialNumber, serialNumberLen)
        < 0) {
      /* Error decoding.  Just issue a warning to debug stream and
           return with revocation unknown */
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream,
                 "Warning: Cannot decode entries in CRL from database.\n");
      break;
    }

    if (found) {
      /* Revoked status overrides CRL expired status */
      *revocationStatus = CERT_REVOKED;
      break;
    }

    if (checkCRLSequence && ripemInfo->z.currentCRLLastUpdate != (UINT4)0 &&
        R_memcmp ((POINTER)&ripemInfo->publicKey, (POINTER)issuerKey,
                  sizeof (*issuerKey)) == 0) {
      /* Make sure the last update time is as expected. */
            
      if (crlStruct->lastUpdate != ripemInfo->z.currentCRLLastUpdate) {
        *revocationStatus = CERT_CRL_OUT_OF_SEQUENCE;
        break;
      }
    }

    /* Check for expired CRL */
    R_time (&now);
    if (crlStruct->nextUpdate < now) {
      *revocationStatus = CERT_CRL_EXPIRED;
      break;
    }

    *revocationStatus = CERT_VALID;
  } while (0);

  free (crlStruct);
  free (crlDER);
  return (errorMessage);
}

/* Use the lastUpdate and publicKeyDigest to check if the CRL is already
     in the database, and call WriteCRL if it isn't
 */
static char *MaybeWriteCRL
  (crlDER, crlDERLen, lastUpdate, publicKeyDigest, ripemDatabase)
unsigned char *crlDER;
unsigned int crlDERLen;
UINT4 lastUpdate;
unsigned char *publicKeyDigest;
RIPEMDatabase *ripemDatabase;
{
  unsigned char *selectedCRL = (unsigned char *)NULL;
  char *errorMessage = (char *)NULL;

  /* For error, break to end of do while (0) block. */
  do {
    /* Get the latest CRL with last update equal to or less than
         the CRL to insert.  If no CRL is found, selectedCRL will be NULL. */
    if ((errorMessage = GetLatestCRL
         (ripemDatabase, &selectedCRL, publicKeyDigest, lastUpdate))
        != (char *)NULL)
      break;

    if (selectedCRL == (unsigned char *)NULL || R_memcmp
        ((POINTER)crlDER, (POINTER)selectedCRL, crlDERLen) != 0) {
      /* The latest CRL is absent or is different, so insert this one. */
      if ((errorMessage = WriteCRL (crlDER, publicKeyDigest, ripemDatabase))
          != (char *)NULL)
        break;
    }
  } while (0);

  free (selectedCRL);
  return (errorMessage);
}

/* Encode and re-decode key in place so that it will bit-wise match
     other decoded keys of the same value.  This is useful if key might
     have been constructed, rather than coming from a decoded cert.
 */
static char *NormalizePublicKeyStruct (key)
R_RSA_PUBLIC_KEY *key;
{
  unsigned char *der;
  unsigned int derLen;

  if ((der = (unsigned char *)malloc (PubKeyToDERLen (key)))
      == (unsigned char *)NULL)
    return (ERR_MALLOC);

  PubKeyToDER (key, der, &derLen);
  DERToPubKey (der, key);

  free (der);
  return ((char *)NULL);
}

/* Encode and re-decode name in place so that it will bit-wise match
     other decoded names of the same value.  This is useful if name might
     have been constructed, rather than coming from a decoded cert.
 */
static char *NormalizeNameStruct (name)
DistinguishedNameStruct *name;
{
  unsigned char *der, *derPointer;

  if ((der = (unsigned char *)malloc (len_distinguishedname (name) + 4))
      == (unsigned char *)NULL)
    return (ERR_MALLOC);

  derPointer = der;
  DistinguishedNameToDER (name, &derPointer);
  derPointer = der;
  DERToDistinguishedName (&derPointer, name);

  free (der);
  return ((char *)NULL);
}

/* Look for the most recent direct certificate for the user with the given
     name and public key (even if it is revoked).  If there is no such
     certificate, or if its validity ends before the given notBefore, then
     set *alreadyValidated FALSE.  Otherwise, set it TRUE which indicates
     there is already a certificate with overlapping validity period
     (or notBefore is part of a validity which is prior to the already-
     issued certificate).
 */
static char *CheckAlreadyValidated
  (ripemInfo, alreadyValidated, name, publicKey, notBefore, ripemDatabase)
RIPEMInfo *ripemInfo;
BOOL *alreadyValidated;
DistinguishedNameStruct *name;
R_RSA_PUBLIC_KEY *publicKey;
UINT4 notBefore;
RIPEMDatabase *ripemDatabase;
{
  TypList certs;
  TypListEntry *entry;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  char *errorMessage;
  UINT4 latestNotAfter;

  InitList (&certs);
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Default to false */
    *alreadyValidated = FALSE;
    
    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* Select all certs for this username. */
    if ((errorMessage = GetCertsBySmartname
         (ripemDatabase, &certs, GetDNSmartNameValue (name), ripemInfo))
	!= (char *)NULL)
      break;

    /* Find the latest "notAfter".
     */
    latestNotAfter = (UINT4)0;
    
    for (entry = certs.firstptr; entry; entry = entry->nextptr) { 
      if (DERToCertificate
          ((unsigned char *)entry->dataptr, certStruct, &fieldPointers) < 0)
        /* Error decoding.  Just try the next cert. */
        continue;

      if (certStruct->notAfter <= latestNotAfter)
        /* This is not a later certificate, so don't even bother checking
	     anything else in this cert.  Just try the next one. */
        continue;

      if (R_memcmp ((POINTER)&certStruct->publicKey, (POINTER)publicKey,
                    sizeof (certStruct->publicKey)) != 0)
        /* Doesn't have the same public key */
        continue;

      /* Don't check the name because if it is the same public key,
           that's what matters. */

      if (R_VerifyBlockSignature
          (fieldPointers.innerDER, fieldPointers.innerDERLen,
           certStruct->signature, certStruct->signatureLen,
           certStruct->digestAlgorithm, &ripemInfo->publicKey) != 0)
        /* Can't verify the signature.  Perhaps it was not issued by
	     the logged it user.  Just try the next one. */
        continue;

      /* We already know this is a later notAfter */
      latestNotAfter = certStruct->notAfter;
    }

    if (latestNotAfter == (UINT4)0)
      /* Didn't find any existing certificate */
      break;

    if (notBefore <= latestNotAfter)
      *alreadyValidated = TRUE;
  } while (0);

  FreeList (&certs);
  free (certStruct);
  return (errorMessage);
}

