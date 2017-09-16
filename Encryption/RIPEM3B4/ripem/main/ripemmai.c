/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- ripemmai.c --  Main program for RIPEM
 *
 *   RIPEM -- Riordan's Internet Privacy Enhanced Mail
 *
 *            (aka RSAREF-based Internet Privacy Enhanced Mail)
 *
 *   RIPEM is a public key encryption package.
 *
 *   This program implements a subset of RFC 1421-1424 Privacy
 *   Enhanced Mail.  It uses RSA Data Security's RSAREF cryptographic
 *   toolkit for the encryption/decryption/verification of messages.
 *
 *   "ripem" is meant to be called to pre-process a mail message
 *   prior to being sent.  The recipient runs the encrypted
 *   message through "ripem" to get the plaintext back.
 *
 *   For the calling sequence, see the usagemsg.c file.
 *   For more information, see the accompanying files
 *   in this distribution.
 *
 *   Mark Riordan   May - September 1992
 *   (After RPEM, March - May 1991.)
 *
 *   This code is hereby placed in the public domain.
 *   RSAREF, however, is not in the public domain.
 *   Therefore, use of this program must be governed by RSA DSI's
 *   RSAREF Program License.  This license basically allows free
 *   non-commercial use within the United States and Canada.
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef SVRV32
#include <sys/types.h>
#endif /* SVRV32 */
#include "global.h"
#include "rsaref.h"
#include "ripem.h"

#ifdef MSDOS
#include <io.h>
#include <time.h>
#ifndef __TURBOC__
#include <malloc.h>
#else
#include <alloc.h>
#endif
#endif

#ifndef IBMRT
#include <stdlib.h>
#endif
#include <errno.h>

#if !defined (__convexc__) && !defined(apollo) && !defined(__TURBOC__)
#include <memory.h>
#endif

#include <string.h>

#include "headers.h"
#include "keyfield.h"
#include "strutilp.h"
#include "keyderpr.h"
#include "derkeypr.h"
#include "keymanpr.h"
#include "bemparse.h"
#include "hexbinpr.h"
#include "bfstream.h"
#include "certder.h"
#include "certutil.h"
#include "rdwrmsgp.h"
#include "p.h"

#ifdef UNIX
#ifdef __MACH__
#include <libc.h>
#endif
#include <pwd.h>
#endif

#ifdef MACTC
#include <stdlib.h>
#include <console.h>
#include <time.h>
#endif

static char *AddIssuerSerialAlias P((RIPEMInfo *, CertificateStruct *));
static char *EncryptAndWritePrivateKey
  P ((RIPEMInfo *, unsigned char *, unsigned int, RIPEMDatabase *));
static char *AddNameToList P((TypList *, DistinguishedNameStruct *));

/* VERSION is defined in version.h.
   Note that we define a varibale instead of just putting #define VERSION
     in ripem.h so that just re-linking to a new library will ensure that
     the application gets the new version. */
#include "version.h"
char *RIPEM_VERSION = VERSION;

char *FieldNames[] = { DEF_FIELDS(MAKE_TEXT) };
char *IDNames[] = { DEF_IDS(MAKE_IDS) };
char *ERR_MALLOC = "Cannot allocate memory";
char *ERR_SELF_SIGNED_CERT_NOT_FOUND =
  "Couldn't find user's self-signed certificate";
char *ERR_PREFERENCES_NOT_FOUND = "Preferences not found";
char *ERR_PREFERENCES_CORRUPT = "Preference information is corrupt";
char *ERR_CERT_ALREADY_VALIDATED =
  "There is already a direct certificate with a current validity period for this user";
char *ERR_NO_PEM_HEADER_BEGIN =
  "Could not find BEGIN PRIVACY-ENHANCED MESSAGE boundary";

/* Set ripemInfo to its initial state.
 */
void RIPEMInfoConstructor (ripemInfo)
RIPEMInfo *ripemInfo;
{
  R_RandomInit (&ripemInfo->randomStruct);
  InitList (&ripemInfo->issuerCerts);
  R_memset ((POINTER)&ripemInfo->z, 0, sizeof (ripemInfo->z));
  ripemInfo->debug = 0;
  ripemInfo->debugStream = (FILE *)NULL;
}

/* Finalize the ripemInfo, zeroizing sensitive information and freeing
    memory.
 */
void RIPEMInfoDestructor (ripemInfo)
RIPEMInfo *ripemInfo;
{
  R_RandomFinal (&ripemInfo->randomStruct);
  FreeList (&ripemInfo->issuerCerts);
  R_memset
    ((POINTER)&ripemInfo->privateKey, 0, sizeof (ripemInfo->privateKey));
  R_memset
    ((POINTER)ripemInfo->passwordDigest, 0,
     sizeof (ripemInfo->passwordDigest));
  free (ripemInfo->z.userCertDER);
  RIPEMResetPreferences (ripemInfo);

  /* Use the "virtual" destructors.
   */
  if (ripemInfo->z.encipherFrame != (RIPEMEncipherFrame *)NULL) {
    (*ripemInfo->z.encipherFrame->Destructor) (ripemInfo->z.encipherFrame);
    free (ripemInfo->z.encipherFrame);
  }
  if (ripemInfo->z.decipherFrame != (RIPEMDecipherFrame *)NULL) {
    (*ripemInfo->z.decipherFrame->Destructor) (ripemInfo->z.decipherFrame);
    free (ripemInfo->z.decipherFrame);
  }
  if (ripemInfo->z.crlsFrame != (RIPEM_CRLsFrame *)NULL) {
    (*ripemInfo->z.crlsFrame->Destructor) (ripemInfo->z.crlsFrame);
    free (ripemInfo->z.crlsFrame);
  }
}

/* Generate a public/private keypair with the given bits and create a
     self-signed cert with the given validityMonths.
   The userDN in ripemInfo must already be set.  This creates a self-signed
     cert using the given digestAlgorithm and writes it to the
     first filename in ripemDatabase->pubKeySource and
     encrypts the private key with the password, writing it to
     the first filename in ripemDatabase->privKeySource.
   The smart name from ripemInfo->userDN is used as the User: field in
     the public and private key files.  If z.usernameAliases in ripemInfo
     is not NULL, then it is a list of strings which are written as
     User: fields also in the private key file.
   This also creates an initial CRL for the user, signing it with
     digestAlgorithm and writes it to first entry in
     ripemDatabase->crlSource.
   The randomStruct in ripemInfo must already be initialized.
   This sets ripemInfo's publicKey, privateKey and userCertDER
     (which is the user's self-signed cert).
 */
char *RIPEMGenerateKeys
  (ripemInfo, bits, validityMonths, digestAlgorithm, password, passwordLen,
   ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned int bits;
unsigned int validityMonths;
int digestAlgorithm;
unsigned char *password;
unsigned int passwordLen;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage = NULL;
  int retcode;
  unsigned int digestLen;
  R_RSA_PROTO_KEY proto_key;
  UINT4 now;

  /* Set up the desired properties of the key to generate. */
  proto_key.bits = bits;
  /* Always use Fermat # F4 as public exponent. */
  proto_key.useFermat4 = 1;

  R_memset((POINTER)&ripemInfo->publicKey, 0, sizeof (ripemInfo->publicKey));
  R_memset
    ((POINTER)&ripemInfo->privateKey, 0, sizeof (ripemInfo->privateKey));
  retcode = R_GeneratePEMKeys
    (&ripemInfo->publicKey, &ripemInfo->privateKey, &proto_key,
     &ripemInfo->randomStruct);

  if(retcode != 0)
    return (FormatRSAError(retcode));

  /* The key generation worked.  Now for each key component
       (public and private), translate the key to DER format,
       encode it in RFC1113 format, and write it out in an
       appropriately-formated file.
   */
  if ((errorMessage = WriteSelfSignedCert
       (ripemInfo, validityMonths, digestAlgorithm, ripemDatabase))
      != (char *)NULL)
    return (errorMessage);

  /* Now encode, encrypt, and write out the private key. */
  if ((errorMessage = EncryptAndWritePrivateKey
       (ripemInfo, password, passwordLen, ripemDatabase)) != (char *)NULL)
    return (errorMessage);

  /* Set the password digest for use in authenticating preferences.
       The preferences will be saved by RIPEMUpdateCRL. */
  R_DigestBlock
    (ripemInfo->passwordDigest, &digestLen, password, passwordLen, DA_MD5);

  /* Now write out a new CRL.  RIPEMUpdateCRL should create a new one
       because it's not already in the database.  Set serialNumber
       to NULL so there are no entries and default to 30 day
       validity period.
   */
  R_time (&now);
  return (RIPEMUpdateCRL
          (ripemInfo, (UINT4)(now + (UINT4)30 * (UINT4)24 * (UINT4)3600),
           (unsigned char *)NULL, 0, digestAlgorithm, ripemDatabase));
}

/* Re-encrypt the user's private key with newPassword and rewrites it
     to the first private key file listed in ripemDatabase.
   The calling routine must already have called RIPEMLoginUser.
   The smart name from ripemInfo->userDN is used as the User: field in
     the private key file.  If z.usernameAliases in ripemInfo
     is not NULL, then it is a list of strings which are written as
     User: fields also in the private key file.
   This also calls RIPEMSavePreferences so that it is re-authenticated
     under the new password.  Therefore, this will return an error if
     ripemDatabase->preferencesFilename cannot be opened.
 */
char *RIPEMChangePassword
  (ripemInfo, newPassword, newPasswordLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char *newPassword;
unsigned int newPasswordLen;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;
  unsigned int digestLen;
  
  if ((errorMessage = EncryptAndWritePrivateKey
       (ripemInfo, newPassword, newPasswordLen, ripemDatabase))
      != (char *)NULL)
    return (errorMessage);

  /* Recompute the passwordDigest */
  R_DigestBlock
    (ripemInfo->passwordDigest, &digestLen, newPassword, newPasswordLen,
     DA_MD5);

  return (RIPEMSavePreferences (ripemInfo, ripemDatabase));
}

/*--- function FormatRSAError -----------------------------------------
 * Return a string corresponding to the RSAREF errorCode.
 */
char *FormatRSAError(errorCode)
int errorCode;
{
  char *errorMessage;

  switch(errorCode) {
  case RE_CONTENT_ENCODING:
    errorMessage = "(Encrypted) content has RFC 1421 encoding error";
    break;
  case RE_DATA:
    errorMessage = "General data error";
    break;
  case RE_DIGEST_ALGORITHM:
    errorMessage = "Message-digest algorithm is invalid";
    break;
  case RE_ENCODING:
    errorMessage = "encoded data has RFC 1421 encoding error";
    break;
  case RE_KEY:
    errorMessage =
      "Recovered data encryption key can't decrypt encrypted content/encrypt signature";
    break;
  case RE_KEY_ENCODING:
    errorMessage = "Encrypted key has RFC 1113 encoding error";
    break;
  case RE_LEN:
    errorMessage = "Encrypted key length or signature length out of range";
    break;
  case RE_MODULUS_LEN:
    errorMessage = "Modulus length is invalid";
    break;
  case RE_NEED_RANDOM:
    errorMessage = "Random structure is not seeded";
    break;
  case RE_PRIVATE_KEY:
    errorMessage =
      "Private key cannot encrypt message digest, or cannot decrypt encrypted key";
    break;
  case RE_PUBLIC_KEY:
    errorMessage = "Public key cannot encrypt data encryption key, or cannot decrypt signature";
    break;
  case RE_SIGNATURE:
    errorMessage = "Signature on content or block is incorrect";
    break;
  case RE_SIGNATURE_ENCODING:
    errorMessage = "(Encrypted) signature has RFC 1113 encoding error";
    break;
  case RE_ENCRYPTION_ALGORITHM:
    errorMessage = "Encryption algorithm is invalid or unsupported";
    break;
  default:
    errorMessage = "Unknown error returned from RSAREF routines";
    break;
  }
  return errorMessage;
}

/* Use the username to select the user's private key and self-signed cert.
     The password is used to decrypt the private key.
   This sets ripemInfo's publicKey, privateKey, userDN and userCertDER
     (which is the user's self-signed cert).
   This also updates ripemInfo's issuerSerialAlises table with the
     issuer/serial aliases for all certs which match the user's public key.
   If this returns the error string ERR_SELF_SIGNED_CERT_NOT_FOUND,
     the public and private keys have already been set, but couldn't
     find the user's self-signed certificate.  This should only be used
     if the application wants to do an "upgrade" from RIPEM 1.1 by calling
     CreateSelfSignedCert.
   This also loads the RIPEM preferences from
     ripemDatabase->preferencesFilename.
   If this returns error ERR_PREFERENCES_NOT_FOUND, then the user has been
     successfully logged in but ripemDatabase->preferencesFilename
     is NULL or the entry for the RIPEM user doesn't exist.  In this case,
     the user should be alerted that default preferences will be used.
     The preferences will be saved at the next call to RIPEMSavePreferences
     or other functions like SetChainLenAllowed which save the preferences.
   If this returns ERR_PREFERENCES_CORRPUT, then the user has been successfully
     logged in but the preferences decodes badly or the signature doesn't
     check.  In this case, the user should be alerted that default values
     are now in use and that any previous preferences must be set again.
     The preferences will be saved at the next call to RIPEMSavePreferences
     or other functions like SetChainLenAllowed that save the preferences.
 */
char *RIPEMLoginUser
  (ripemInfo, username, ripemDatabase, password, passwordLen)
RIPEMInfo *ripemInfo;
char *username;
RIPEMDatabase *ripemDatabase;
unsigned char *password;
unsigned int passwordLen;
{
  BOOL gotSelfSignedCert;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  TypList certs, issuerNames;
  TypListEntry *entry;
  char *errorMessage = (char *)NULL;
  int certDERLen, status;
  unsigned int digestLen;

  InitList (&certs);
  InitList (&issuerNames);

  /* For error, break to end of do while (0) block. */
  do {
    /* Set the password digest for use in authenticating preferences. */
    R_DigestBlock
      (ripemInfo->passwordDigest, &digestLen, password, passwordLen, DA_MD5);

    if ((errorMessage = GetPrivateKey
         (username, &ripemDatabase->privKeySource, &ripemInfo->privateKey,
          password, passwordLen, ripemInfo)) != (char *)NULL)
      break;

    if (ripemInfo->debug > 2)
      DumpPrivKey (&ripemInfo->privateKey, ripemInfo->debugStream);

    /* Pre-zeroize key struct so byte-wise comparison of two
         structs for the same public key will be the same. */
    R_memset ((POINTER)&ripemInfo->publicKey, 0, sizeof (ripemInfo->publicKey));

    /* Construct the public key from the private key.
     */
    ripemInfo->publicKey.bits = ripemInfo->privateKey.bits;
    R_memcpy
      ((POINTER)ripemInfo->publicKey.modulus,
       (POINTER)ripemInfo->privateKey.modulus,
       sizeof (ripemInfo->publicKey.modulus));
    R_memcpy
      ((POINTER)ripemInfo->publicKey.exponent,
       (POINTER)ripemInfo->privateKey.publicExponent,
       sizeof (ripemInfo->publicKey.modulus));

    /* Select all certs for this username. */
    if ((errorMessage = GetCertsBySmartname
         (ripemDatabase, &certs, username, ripemInfo)) != (char *)NULL)
      break;

    /* Allocate the certStruct on the heap because it's big. */
    if ((certStruct = (CertificateStruct *)malloc
         (sizeof (*certStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    
    /* Find the first cert with the user's public key and the same
         subject name and issuer name.  Also, use the public key to
         check the signature on the self-signed cert.
       We are also going to record the digest of issuer name and serial
         number for all certificates with the user's public key which
         will be used later for finding the issuer/serial based recipient
         info when receiving an encrypted mesage.
     */
    gotSelfSignedCert = FALSE;

    for (entry = certs.firstptr; entry; entry = entry->nextptr) { 
      if ((certDERLen = DERToCertificate
           ((unsigned char *)entry->dataptr, certStruct, &fieldPointers))
          < 0) {
        /* Error decoding.  Just issue a warning to debug stream and try
             the next cert. */
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
                   "Warning: Cannot decode certificate from database.\n");
        continue;
      }

      if (R_memcmp ((POINTER)&certStruct->publicKey,
                    (POINTER)&ripemInfo->publicKey,
                    sizeof (ripemInfo->publicKey)) != 0)
        /* Doesn't have the user's public key */
        continue;

      if ((errorMessage = AddIssuerSerialAlias (ripemInfo, certStruct))
          != (char *)NULL)
        break;

      if (R_memcmp ((POINTER)&certStruct->issuer,
                    (POINTER)&certStruct->subject,
                    sizeof (certStruct->issuer)) != 0) {
        /* This is not a self-signed cert.  Add the issuer name in this cert
             to the issuerName list if not already there so we can find
             Issuer-Cert chains later. */
        if ((errorMessage = AddNameToList (&issuerNames, &certStruct->issuer))
            != (char *)NULL)
          break;
      }

      if (gotSelfSignedCert)
        /* We have already copied the issuer/serial and we already found
             the user's self-signed cert, so skip to the next cert. */
        continue;

      if (R_memcmp ((POINTER)&certStruct->issuer,
                    (POINTER)&certStruct->subject,
                    sizeof (certStruct->issuer)) != 0)
        /* Doesn't have the same issuer and subject name */
        continue;

      if ((status = R_VerifyBlockSignature
           (fieldPointers.innerDER, fieldPointers.innerDERLen,
            certStruct->signature, certStruct->signatureLen,
            certStruct->digestAlgorithm, &ripemInfo->publicKey)) != 0) {
        /* Can't verify the signature.  Just print an error to the
             debug stream and try more certs. */
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
          "Warning: %s while checking signature on self-signed certificate.\n",
                   FormatRSAError (status));
        continue;
      }

      /* We have the correct self-signed certificate, so copy info.
       */
      ripemInfo->userDN = certStruct->subject;

      /* malloc and copy the cert DER.  Allocate an extra space as required
           by CodeAndWriteBytes.
       */
      if ((ripemInfo->z.userCertDER = (unsigned char *)malloc
           (certDERLen + 1)) == (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      R_memcpy
        ((POINTER)ripemInfo->z.userCertDER, (POINTER)entry->dataptr,
         certDERLen);
      ripemInfo->z.userCertDERLen = certDERLen;

      /* Found the self-signed cert */
      gotSelfSignedCert = TRUE;
    }
    if (errorMessage != (char *)NULL)
      break;

    if (!gotSelfSignedCert) {
      errorMessage = ERR_SELF_SIGNED_CERT_NOT_FOUND;
      break;
    }

    /* Load the preferences as the last thing we do so that its
         meaningful errors like ERR_PREFERENCES_NOT_FOUND will be returned
         only after the user is successfully logged in. */
    if ((errorMessage = RIPEMLoadPreferences (ripemInfo, ripemDatabase))
        != (char *)NULL)
      break;

    /* Add certs to use as Issuer-Certicificates.  Note that if
         RIPEMLoadPreferences failed to load the preferences, there is
         no point in trying to add issuer certs since there are no
         chain length allowed entries to allow extended certificate
         chains. */
    if ((errorMessage = AddUserIssuerCerts
         (ripemInfo, &issuerNames, ripemDatabase)) != (char *)NULL)
      break;
  } while (0);

  FreeList (&certs);
  FreeList (&issuerNames);
  free (certStruct);
  return (errorMessage);
}

/* This is just like realloc, except frees the original pointer if realloc
     fails.
   This also returns a non-NULL value if size is zero, as opposed to some
     implementations which may return NULL for a block of size zero.
   Returns the reallocated pointer on success, or NULL on failure.
 */
void *R_realloc (pointer, size)
void *pointer;
unsigned int size;
{
  void *result;

  if (size == 0)
    /* Prevent allocating a block of size zero which may return NULL. */
    size = 1;

  if (pointer == NULL)
    /* Explicitly call malloc, because some realloc implementations
         don't like to realloc a NULL pointer. */
    return ((void *)malloc (size));

  if ((result = (void *)realloc (pointer, size)) == NULL)
    /* Explicitly free the old pointer, which is unchanged by realloc. */
    free (pointer);

  return (result);
}

/* MD5 digest the issuer name and serial number in the certStruct, and add
     it to ripemInfo's issuerSerialAliases if not already there.
   Returns NULL for OK, otherwise error message.
 */
static char *AddIssuerSerialAlias (ripemInfo, certStruct)
RIPEMInfo *ripemInfo;
CertificateStruct *certStruct;
{
  unsigned char alias[MD5_LEN];
  unsigned int count;

  ComputeIssuerSerialAlias
    (alias, &certStruct->issuer, certStruct->serialNumber,
     sizeof (certStruct->serialNumber));

  if (!IsIssuerSerialAlias (ripemInfo, alias)) {
    /* Alias is not already in the ripemInfo, so realloc room in the
         table and add it. */
    count = ripemInfo->z.issuerSerialAliasCount;
    if ((ripemInfo->z.issuerSerialAliases = (unsigned char *)R_realloc
         (ripemInfo->z.issuerSerialAliases, MD5_LEN * (count + 1)))
        == (unsigned char *)NULL)
      return (ERR_MALLOC);

    R_memcpy
      ((POINTER)&ripemInfo->z.issuerSerialAliases[MD5_LEN * count],
       (POINTER)alias, MD5_LEN);
    ripemInfo->z.issuerSerialAliasCount = count + 1;
  }

  return ((char *)NULL);
}

/* This closes the first private key file in ripemDatabase and writes
     the encrypted private key.  Then it re-opens the file for read.
   The smart name from ripemInfo->userDN is used as the User: field in
     the private key file.  This replaces the private key in an entry
     with the same smart name if it exists. If z.usernameAliases in ripemInfo
     is not NULL, then it is a list of strings which are written as
     User: fields also in the private key file.
 */
static char *EncryptAndWritePrivateKey
  (ripemInfo, password, passwordLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char *password;
unsigned int passwordLen;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage = NULL;
  unsigned char *der = (unsigned char *)NULL,
    *der_enc_priv = (unsigned char *)NULL, salt[MD5_LEN];
  unsigned int derlen, iter_count=100, enc_priv_len, der_enc_priv_len,
    digestLen;
  size_t numDERBytes;
  TypListEntry *entry;
  TypFile *typFile;
  FILE *privOutStream = (FILE *)NULL;
  BOOL foundEntry;
  R_DIGEST_CTX digestContext;
  int status;

  /* For error, break to end of do while (0) block. */
  do {
    /* Now process the private key.
     */
    numDERBytes = PrivKeyToDERLen(&ripemInfo->privateKey)+DES_BLOCK_SIZE;
    der = (unsigned char *) malloc(numDERBytes);
    if (der == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* DER encode the private key */
    PrivKeyToDER (&ripemInfo->privateKey, der, &derlen);

    /* Encrypt the private key.  Generate a salt by digesting the
         password with the private key.
     */
    if ((status = R_DigestInit (&digestContext, DA_MD5)) != 0) {
      errorMessage = FormatRSAError (status);
      break;
    }
    R_DigestUpdate (&digestContext, password, passwordLen);
    R_DigestUpdate (&digestContext, der, derlen);
    R_DigestFinal (&digestContext, salt, &digestLen);

    /* Encrypt in place. */
    if (pbeWithMDAndDESWithCBC
        (TRUE,DA_MD5,der,derlen,password, passwordLen,salt,iter_count,
         &enc_priv_len) != 0) {
      errorMessage = "Can't encrypt private key.";
      break;
    }

    /* DER-encode the encrypted private key. */
    der_enc_priv = (unsigned char *) 
      malloc(EncryptedPrivKeyToDERLen(iter_count,enc_priv_len));
    if(!der_enc_priv) {
      errorMessage = ERR_MALLOC;
      break;
    }

    EncryptedPrivKeyToDER
      (salt, iter_count, der, enc_priv_len, der_enc_priv, &der_enc_priv_len);

    if(ripemInfo->debug>1) {
      fprintf
        (ripemInfo->debugStream,"DER encoding of encrypted private key:\n");
      BEMParse(der_enc_priv,ripemInfo->debugStream);
    }

    if(ripemInfo->debug>1)
      DumpPubKey(&ripemInfo->publicKey, ripemInfo->debugStream);

    if (!ripemDatabase->privKeySource.filelist.firstptr)
      /* No private key source entries. */
      break;

    /* Close the private key input stream since we must overwrite */
    typFile =
      (TypFile *)ripemDatabase->privKeySource.filelist.firstptr->dataptr;
    if (typFile->stream != (FILE *)NULL) {
      fclose (typFile->stream);
      typFile->stream = (FILE *)NULL;
    }

    /* First try to update the private key field value if it already exists.
     */
    if ((errorMessage = RIPEMUpdateFieldValue
         (&foundEntry, typFile->filename, USER_FIELD,
          GetDNSmartNameValue (&ripemInfo->userDN),
          PRIVATE_KEY_FIELD, der_enc_priv, der_enc_priv_len, ripemInfo))
        != (char *)NULL)
      break;

    if (!foundEntry) {
      /* There was not already an entry for this user, so open the private
           key output file and append the header, the list of usernames
           for this user and the encrypted private key.
       */
      if ((privOutStream = fopen (typFile->filename, "a")) == (FILE *)NULL) {
        /* We don't really expect this error since it has already been
             checked in OpenKeySource. */
        sprintf(ripemInfo->errMsgTxt,"Can't open private key output file %s.",
                typFile->filename);
        errorMessage = ripemInfo->errMsgTxt;
        break;
      }

      /* Print separating blank.  Only check for write error here. */
      if (fprintf (privOutStream, "\n") < 0) {
        errorMessage = "Error writing to private key file.";
        break;
      }

      fprintf (privOutStream, "%s %s\n",
               USER_FIELD, GetDNSmartNameValue (&ripemInfo->userDN));

      /* Write out the username aliases if the pointer to the list is
           not NULL. */
      if (ripemInfo->z.usernameAliases != (TypList *)NULL) {
        for (entry = ripemInfo->z.usernameAliases->firstptr; entry;
             entry = entry->nextptr)
          fprintf
            (privOutStream, "%s %s\n", USER_FIELD, (char *)entry->dataptr);
      }

      fprintf (privOutStream, "%s\n", PRIVATE_KEY_FIELD);
      CodeAndWriteBytes(der_enc_priv,der_enc_priv_len," ",privOutStream);

      fclose (privOutStream);
      privOutStream = (FILE *)NULL;
    }

    /* Re-open for read. */
    if ((typFile->stream = fopen (typFile->filename, "r")) == (FILE *)NULL) {
      sprintf(ripemInfo->errMsgTxt,
              "Can't open key file %s for read", typFile->filename);
      errorMessage = ripemInfo->errMsgTxt;
      break;
    }
  } while (0);

  R_memset ((POINTER)&digestContext, 0, sizeof (digestContext));
  free(der_enc_priv);
  if (der != (unsigned char *)NULL) {
    /* der contains the private key, so zeroize. */
    R_memset ((POINTER)der, 0, numDERBytes);
    free (der);
  }
  if (privOutStream != (FILE *)NULL)
    fclose (privOutStream);

  return (errorMessage);
}

/* Add name to nameList if it is not already there.
 */
static char *AddNameToList (nameList, name)
TypList *nameList;
DistinguishedNameStruct *name;
{
  TypListEntry *entry;
  DistinguishedNameStruct *nameCopy;

  for (entry = nameList->firstptr; entry; entry = entry->nextptr) {
    if (R_memcmp
        ((POINTER)entry->dataptr, (POINTER)name, sizeof (*name)) == 0)
      /* name is already in the list. */
      return ((char *)NULL);
  }

  /* Allocate a copy of the name and add it to the list.
   */
  if ((nameCopy = (DistinguishedNameStruct *)malloc (sizeof (*nameCopy)))
      == (DistinguishedNameStruct *)NULL)
    return (ERR_MALLOC);
  *nameCopy = *name;
  return (AddToList
          ((TypListEntry *)NULL, nameCopy, sizeof (*nameCopy), nameList));
}

