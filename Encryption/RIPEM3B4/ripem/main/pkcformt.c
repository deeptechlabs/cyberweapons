/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
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

#define IV_SIZE 8
#define MAX_TAG_AND_LEN_BYTES 6

/* BER class/tag codes */
#define BER_CONSTRUCTED 0x20
#define BER_CONTEXT_SPECIFIC 0x80
#define BER_INTEGER 2
#define BER_BIT_STRING 3
#define BER_OCTET_STRING 4
#define BER_NULL 5
#define BER_OBJECT_ID 6
#define BER_SEQUENCE (16 | BER_CONSTRUCTED)
#define BER_SET (17 | BER_CONSTRUCTED)

/* This is used in RIPEMDecipherPKCSUpdate */
#define ADVANCE_INPUT(len) {input += (len); inputLen -= (len);}

typedef enum {
  DS_CONTENT_INFO_START,
  DS_CONTENT_TYPE,
  DS_CONTENT_INFO_CONTENT,
  DS_X_DATA_START,
  DS_X_DATA_VERSION,
  DS_CHECK_X_DATA_VERSION,
  DS_RECIPIENT_INFOS_START,
  DS_CHECK_RECIPIENT_INFOS_END,
  DS_RECIPIENT_INFO,
  DS_DIGEST_ALGORITHMS_START,
  DS_CHECK_DIGEST_ALGORITHMS_END,
  DS_GET_DIGEST_ALGORITHM,
  DS_CONTENT_INFO_DATA_START,
  DS_CONTENT_INFO_DATA_TYPE,
  DS_ENCRYPTION_ALGORITHM_START,
  DS_ENCRYPTION_ALGORITHM,
  DS_EXPLICIT_DATA_CONTENT,
  DS_EXPLICIT_OCTET_STRING,
  DS_IMPLICIT_OCTET_STRING,
  DS_CHECK_OCTET_STRING_END,
  DS_OCTET_STRING_PART,
  DS_END_EXPLICIT_DATA_CONTENT,
  DS_CONTENT_INFO_DATA_END,
  DS_CHECK_CERTIFICATES_SET,
  DS_CHECK_CERTIFICATES_SET_END,
  DS_CERTIFICATE,
  DS_CHECK_CRLS_SET,
  DS_CHECK_CRLS_SET_END,
  DS_CRL,
  DS_SIGNER_INFOS_START,
  DS_CHECK_SIGNER_INFOS_END,
  DS_SIGNER_INFO,
  DS_X_DATA_END,
  DS_CONTENT_INFO_CONTENT_END,
  DS_CONTENT_INFO_END,
  DS_FINISHED
} DECODE_STATE; 

/* Flags for the decode state. */
#define DS_BYTES_NEEDED_ONLY 0x100
#define DS_ALLOW_INDEFINITE 0x200

typedef struct {
  UINT4 saveFlushedInput;
  UINT4 endPoint;   /* End point of constructed type in original inputBuffer */
} RIPEMConstructedInfo;

typedef struct {
  RIPEMEncipherFrame ripemEncipherFrame;                      /* "base class */
  BufferStream outStream;     /* This holds the value returned to the caller */
  BOOL startNewOctetString;
  int pkcsMode;
  int digestAlgorithm;
  TypList issuerNames;
  R_ENVELOPE_CTX sealContext;
  R_SIGNATURE_CTX signatureContext;
} RIPEMEncipherPKCSFrame;

typedef struct {
  RIPEMDecipherFrame ripemDecipherFrame;                      /* "base class */
  BufferStream outStream;     /* This holds the value returned to the caller */
  BufferStream input;                    /* Used to accumulate during Update */
  int pkcsMode;
  int detached;
  int digestAlgorithm;
  int expectedDigestAlgorithm;                    /* Used only with detached */
  TypList certs;
  R_ENVELOPE_CTX envelopeContext;
  R_SIGNATURE_CTX signatureContext;
  R_RSA_PUBLIC_KEY senderKey;                /* used to execute final verify */
  TypList certChain;                              /* Local copy of certChain */
  ChainStatusInfo chainStatus;
  RIPEMAttributes authenticatedAttributes;
  TypList attributesBuffers;                    /* buffers attributes values */

  /* These are used to track the state during Update */
  DECODE_STATE decodeState;       /* Used to keep track of where in decoding */
  UINT4 bytesNeeded;    /* See RIPEMDecipherPKCSUpdate for why this is UINT4 */
  /* Make this array of size DS_FINISHED so we are sure an entry is
       available for every state. */
  RIPEMConstructedInfo constructedInfo[DS_FINISHED];
  UINT4 flushedInput;             /* How much BufferStreamFlushBytes flushed */
  int checkEndConstructed;
  BOOL foundRecipient, foundSigner;
  int constructedOctetString;
  unsigned int octetStringContentLen;

  /* Put these in the frame since they will be allocated and freed correctly */
  DistinguishedNameStruct issuerName;
  unsigned char serialNumber[MAX_SERIAL_NUMBER_LEN];
  unsigned char signature[MAX_SIGNATURE_LEN];
  unsigned char encryptedKey[MAX_ENCRYPTED_KEY_LEN];
  unsigned int encryptedKeyLen;
} RIPEMDecipherPKCSFrame;

static char *ERR_PKCS_ENCODING = "Invalid encoding of input PKCS message";

static unsigned char END_INDEFINITE_LEN[] = {0, 0};

/* Following are chunks for a PKCS #7 ContentInfo including a SignedData,
     SignedAndEnvelopedData, etc.
  */
static unsigned char CONTENT_INFO_START[] = {
  BER_SEQUENCE, 0x80 /* Indefinite length */
};

static unsigned char CONTENT_TYPE_DATA[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1
};
static unsigned char CONTENT_TYPE_SIGNED_DATA[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2
};
static unsigned char CONTENT_TYPE_ENVELOPED_DATA[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 3
};
static unsigned char CONTENT_TYPE_SIGNED_ENVELOPED_DATA[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 4
};

/* This outputs up to the version but does not include the actual
   0 or 1 for the version.  It includes the [0] EXPLICIT at the end of the
     ContentInfo. */
static unsigned char DATA_VERSION[] = {
  BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0, 0x80, /* Indefinite length */
  BER_SEQUENCE, 0x80, /* Indefinite length */
  BER_INTEGER, 1 /* Must put a 0 or 1 here for the version! */
};

/* Must put out END_INDEFINITE_LEN after the recipient infos. */
static unsigned char RECIPIENT_INFOS_START[] = {
  BER_SET, 0x80 /* Indefinite length */
};

/* DigestAlgorithmIdentifiers set with no members (for certs only message) */
static unsigned char EMPTY_DIGEST_ALGORITHMS[] = {
  BER_SET, 0
};

/* Start of DigestAlgorithmIdentifiers set the right size for
     containing one MD2 or MD5 */
static unsigned char DIGEST_ALGORITHMS_START[] = {
  BER_SET, 14
};

/* Start of DigestAlgorithmIdentifiers set the right size for
     containing one SHA1 */
static unsigned char DIGEST_ALGORITHMS_SHA1_START[] = {
  BER_SET, 11
};

/* Start of ContentInfo or EncryptedContentInfo. */
static unsigned char CONTENT_INFO_DATA_START[] = {
  BER_SEQUENCE, 0x80 /* Indefinite length */
};

static unsigned char DES_CBC_ID[] = {
  BER_OBJECT_ID, 5, 0x2b, 0x0e, 0x03, 0x02, 0x07,
};

static unsigned char DES_EDE3_CBC_ID[] = {
  BER_OBJECT_ID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07,
};

static unsigned char RC2_CBC_ID[] = {
  BER_OBJECT_ID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x02,
};

/* [0] EXPLICIT start for a constructed octet string.  Used for
     ContentInfo inside SignedInfo. */
static unsigned char EXPLICIT_OCTET_STRING_START[] = {
  BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0, 0x80, /* Indefinite length */
    BER_OCTET_STRING | BER_CONSTRUCTED, 0x80 /* Indefinite length */
};

/* [0] IMPLICIT start for a constructed octet string.  Used for
     EncryptedContentInfo. */
static unsigned char IMPLICIT_OCTET_STRING_START[] = {
  BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0, 0x80 /* Indefinite length */
};

/* Must put out END_INDEFINITE_LEN after the certs. */
static unsigned char CERTIFICATES_SET[] = {
  /* [0] IMPLICIT */
  BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0, 0x80 /* Indefinite length */
};

/* Must put out END_INDEFINITE_LEN after the CRLs. */
static unsigned char CRLS_SET[] = {
  /* [1] IMPLICIT */
  BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 1, 0x80 /* Indefinite length */
};

/* Must put out END_INDEFINITE_LEN after the signer infos. */
static unsigned char SIGNER_INFOS_START[] = {
  BER_SET, 0x80 /* Indefinite length */
};

/* algorithm identifier for MD2 */
static unsigned char ALG_ID_MD2[] = {
  BER_SEQUENCE, 12,
    BER_OBJECT_ID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02,
    BER_NULL, 0     
};

/* algorithm identifier for MD5 */
static unsigned char ALG_ID_MD5[] = {
  BER_SEQUENCE, 12,
    BER_OBJECT_ID, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
    BER_NULL, 0     
};

/* algorithm identifier for SHA-1 */
static unsigned char ALG_ID_SHA1[] = {
  BER_SEQUENCE, 9,
    BER_OBJECT_ID, 5, 0x2b, 0x0e, 0x03, 0x02, 26,
    BER_NULL, 0     
};

/* algorithm identifier for rsaEncryption */
static unsigned char ALG_ID_RSA_ENCRYPTION[] = {
  BER_SEQUENCE, 13,
    BER_OBJECT_ID, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1,
    BER_NULL, 0     
};

/* algorithm identifier for md5WithRSAEncryption */
static unsigned char ALG_ID_MD5_WITH_RSA_ENCRYPTION[] = {
  BER_SEQUENCE, 13,
    BER_OBJECT_ID, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 4,
    BER_NULL, 0     
};

/* Close out the SignedData/EnvelopedData/SignedAndEnvelopedData type
     and [0] EXPLICIT from the ContentInfo containing it, and also the
     outermost ContentInfo. */
static unsigned char END_DATA_EXPLICIT_AND_CONTENT_INFO[] = {
  0, 0, 0, 0, 0, 0
};

static unsigned char SIGNING_TIME_ID[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 5
};
static unsigned char SIGNING_DESCRIPTION_ID[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 13
};
static unsigned char CHALLENGE_PASSWORD_ID[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 7
};
static unsigned char UNSTRUCTURED_NAME_ID[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 2
};
static unsigned char CONTENT_TYPE_ID[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 3
};
static unsigned char MESSAGE_DIGEST_ID[] = {
  BER_OBJECT_ID, 9, 1*40+2, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 4
};

/* If the RC2 effective bits is 32, then the parameters in the algorithm
     ID is just the IV octet string.  (Some backwards compatibility thing.)
   Otherwise, for an effective bits < 256, the parameters is:
      RC2-CBC parameter ::=  SEQUENCE {
        rc2ParameterVersion  INTEGER,
        iv                   OCTET STRING (8)
      }
   If the effective bits >= 256, then the parameters is:
     RC2-CBC parameter ::=  SEQUENCE {
       effectiveKeyBits INTEGER,
       iv               OCTET STRING (8)
     }
 */
static int RC2_VERSIONS[256] = {
/* 0x00 */ 0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
/* 0x10 */ 0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
/* 0x20 */ 0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
/* 0x30 */ 0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
/* 0x40 */ 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
/* 0x50 */ 0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
/* 0x60 */ 0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
/* 0x70 */ 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
/* 0x80 */ 0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
/* 0x90 */ 0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
/* 0xa0 */ 0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
/* 0xb0 */ 0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
/* 0xc0 */ 0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
/* 0xd0 */ 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
/* 0xe0 */ 0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
/* 0xf0 */ 0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab
};

void RIPEMEncipherPKCSFrameConstructor P((RIPEMEncipherPKCSFrame *));
void RIPEMEncipherPKCSFrameDestructor P((RIPEMEncipherPKCSFrame *));
void RIPEMDecipherPKCSFrameConstructor P((RIPEMDecipherPKCSFrame *));
void RIPEMDecipherPKCSFrameDestructor P((RIPEMDecipherPKCSFrame *));
static char *WriteSignerInfo
  P((BufferStream *, unsigned char *, unsigned int, unsigned char *,
     unsigned int, unsigned char *, unsigned int, int));
static char *WriteCertifyRequestInfo
  P((BufferStream *, DistinguishedNameStruct *, R_RSA_PUBLIC_KEY *,
     RIPEMAttributes *));
#ifndef RIPEMSIG
static char *WriteRecipientInfo
  P((BufferStream *, unsigned char *, unsigned int, unsigned char *,
     unsigned int, unsigned char *, unsigned int));
static char *DecodeRecipientInfo
  P((unsigned char *, DistinguishedNameStruct *, unsigned char *,
     unsigned char **, unsigned int *));
static char *WriteEncryptionAlgorithmID
  P((BufferStream *, int, unsigned char *));
static char *DecodeEncryptionAlgorithmID
  P((unsigned char *, int *, unsigned char **));
#endif
static char *DecodeSignerInfo
  P((unsigned char *, DistinguishedNameStruct *, unsigned char *,
     int, R_SIGNATURE_CTX *, unsigned char **, unsigned int *,
     RIPEMAttributes *, TypList *));
static char *ProcessAuthenticatedAttributes
  P((unsigned char *, unsigned int, int, R_SIGNATURE_CTX *,
     RIPEMAttributes *, TypList *));
static char *DecodeAuthenticatedAttributes
  P((unsigned char *, unsigned char *, RIPEMAttributes *, TypList *));
static int DecodeContentType P((unsigned char *));
static char *GetSignerPublicKey
  P ((RIPEMDecipherPKCSFrame *, RIPEMInfo *, R_RSA_PUBLIC_KEY *,
      RIPEMDatabase *));
static char *FindMatchingSelfSignedCert
  P ((RIPEMInfo *, DistinguishedNameStruct *, R_RSA_PUBLIC_KEY *));
static void GetEncipherUpdateOutput
  P ((unsigned char **, unsigned int *, BufferStream *));
static char *WriteCertsAndSigner P ((RIPEMInfo *));
static void EncodePKCS10Attribute
  P ((unsigned char **, RIPEMAttributes *, unsigned int));

/* Initialize for preparing a PKCS message according to enhanceMode.
   The calling routine must already have called RIPEMLoginUser.
   pkcsMode should be PKCS_SIGNED, PKCS_ENVELOPED or
     PKCS_SIGNED | PKCS_ENVELOPED.  If pkcsMode has MODE_ENVELOPED set,
     then encryptionAlgorithm must be EA_DES_CBC, EA_DES_EDE3_CBC or
     EA_RX2_CBC(effectiveBits). Also,
     recipientKeys is an array of recipientKeyCount RecipientKeyInfo structs.
     These give the public keys and usernames of the recipients.  The username
     is used for looking up the user's issuer name and serial number
     The randomStruct in ripemInfo must already be initialized.
   If pkcsMode had MODE_SIGNED set, then digestAlgorithm must be
     DA_MD2, DA_MD5 or DA_SHA1.
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   The output is "as is": no translation of '\n' to <CR><LF> is done because
     this message format can support binary data.  The calling routine must
     do end-of-line character translation if necessary.
   ripemDatabase is used for selecting certificates to find issuer names
     and serial numbers of recipients.
   After this, call RIPEMEncipherPKCSUpdate to enhance the text by parts,
     and call RIPEMEncipherPKCSFinal to finish.
   Return NULL for success or error string.
 */
char *RIPEMEncipherPKCSInit
  (ripemInfo, partOut, partOutLen, pkcsMode, digestAlgorithm,
   encryptionAlgorithm, recipientKeys, recipientKeyCount, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
int pkcsMode;
int digestAlgorithm;
int encryptionAlgorithm;
RecipientKeyInfo *recipientKeys;
unsigned int recipientKeyCount;
RIPEMDatabase *ripemDatabase;
{
  RIPEMEncipherPKCSFrame *frame;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  TypListEntry *entry;
  TypList certList;
  BufferStream *stream, nameDER;
  int status;
  char *errorMessage = (char *)NULL;
  unsigned char iv[IV_SIZE];
  unsigned char *encryptedKeysBuffer = (unsigned char *)NULL, *derPointer;
  unsigned int i, *encryptedKeyLens = (unsigned int *)NULL;
  
#ifdef RIPEMSIG
UNUSED_ARG (encryptionAlgorithm)
UNUSED_ARG (recipientKeys)
UNUSED_ARG (recipientKeyCount)
UNUSED_ARG (ripemDatabase)
#endif
  
  InitList (&certList);
  BufferStreamConstructor (&nameDER);
  
  /* For error, break to end of do while (0) block. */
  do {
    if (pkcsMode != PKCS_SIGNED && pkcsMode != PKCS_ENVELOPED &&
        pkcsMode != (PKCS_SIGNED | PKCS_ENVELOPED)) {
      errorMessage = "Invalid encipher mode.";
      break;
    }
    if (pkcsMode & PKCS_ENVELOPED) {
#ifdef RIPEMSIG
      errorMessage = "RIPEM/SIG cannot prepare encrypted messages. You may prepare signed messages.";
      break;
#else

      /* We will check the encryptionAlgorithm in WriteEncryptionAlgorithmID */
#endif
    }

    /* Make sure any old frame is deleted and make a new one.
     */
    if (ripemInfo->z.encipherFrame != (RIPEMEncipherFrame *)NULL) {
      /* Be sure to call the "virtual" destructor */
      (*ripemInfo->z.encipherFrame->Destructor) (ripemInfo->z.encipherFrame);
      free (ripemInfo->z.encipherFrame);
    }
    /* Be sure to malloc for the size of an entire RIPEMEncipherPKCSFrame */
    if ((ripemInfo->z.encipherFrame = (RIPEMEncipherFrame *)malloc
         (sizeof (*frame))) == (RIPEMEncipherFrame *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    RIPEMEncipherPKCSFrameConstructor
      ((RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame);

    /* Get stream for quick access. */
    frame = (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
    stream = &frame->outStream;

    /* Get ready to write to the output. */
    BufferStreamRewind (stream);

    frame->pkcsMode = pkcsMode;

    /* For use in RIPEMEncipherPKCSFinal. */
    frame->digestAlgorithm = digestAlgorithm;

    if (pkcsMode & PKCS_SIGNED) {
      /* Initialize signature. */
      if ((status = R_SignInit
           (&frame->signatureContext, digestAlgorithm)) != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
    }
    
#ifndef RIPEMSIG
    if (pkcsMode & PKCS_ENVELOPED) {
      if (recipientKeyCount == 0) {
        errorMessage = "You must specify at least one recipient";
        break;
      }

      /* Allocate arrays for the encrypted key pointers.
       */
      if ((encryptedKeysBuffer = (unsigned char *)malloc
           (recipientKeyCount * MAX_ENCRYPTED_KEY_LEN)) ==
          (unsigned char *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }
      if ((encryptedKeyLens = (unsigned int *)malloc
           (recipientKeyCount * sizeof (*encryptedKeyLens))) ==
          (unsigned int *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      /* Create all of the recipient key info blocks and generate the iv.
         We can't output now because the signature comes before the
           encrypted keys.
       */
      if ((errorMessage = RIPEMSealInit
           (ripemInfo, &frame->sealContext, iv, encryptedKeysBuffer,
            encryptedKeyLens, recipientKeys, recipientKeyCount,
            encryptionAlgorithm)) != (char *)NULL)
        break;
    }
#endif

    /* Write the PKCS #7 ContentInfo to the output stream.
     */
    if ((errorMessage = BufferStreamWrite
         (CONTENT_INFO_START, sizeof (CONTENT_INFO_START), stream))
        != (char *)NULL)
      break;

    if (pkcsMode == PKCS_SIGNED) {
      if ((errorMessage = BufferStreamWrite
           (CONTENT_TYPE_SIGNED_DATA, sizeof (CONTENT_TYPE_SIGNED_DATA),
            stream)) != (char *)NULL)
        break;
    }
    else if (pkcsMode == PKCS_ENVELOPED) {
      if ((errorMessage = BufferStreamWrite
           (CONTENT_TYPE_ENVELOPED_DATA, sizeof (CONTENT_TYPE_ENVELOPED_DATA),
            stream)) != (char *)NULL)
        break;
    }
    else if (pkcsMode == (PKCS_SIGNED | PKCS_ENVELOPED)) {
      if ((errorMessage = BufferStreamWrite
           (CONTENT_TYPE_SIGNED_ENVELOPED_DATA,
            sizeof (CONTENT_TYPE_SIGNED_ENVELOPED_DATA), stream))
          != (char *)NULL)
        break;
    }

    if ((errorMessage = BufferStreamWrite
         (DATA_VERSION, sizeof (DATA_VERSION), stream)) != (char *)NULL)
      break;

    /* Must explicitly put the version byte. */
    if (pkcsMode & PKCS_SIGNED) {
      /* SignedData and SigneAndEnvelopedData have version 1 */
      if ((errorMessage = BufferStreamPutc (1, stream)) != (char *)NULL)
        break;
    }
    else {
      /* EnvelopedData have version 0 */
      if ((errorMessage = BufferStreamPutc (0, stream)) != (char *)NULL)
        break;
    }

#ifndef RIPEMSIG
    if (pkcsMode & PKCS_ENVELOPED) {
      /* Output the RecipientInfos.
       */
      if ((errorMessage = BufferStreamWrite
           (RECIPIENT_INFOS_START, sizeof (RECIPIENT_INFOS_START), stream))
          != (char *)NULL)
        break;

      /* Allocate the certStruct on the heap because it's big. */
      if ((certStruct = (CertificateStruct *)malloc
           (sizeof (*certStruct))) == (CertificateStruct *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }
      
      /* For each recipient, write out the RecipientInfo
       */
      for (i = 0; i < recipientKeyCount; ++i) {
        /* For every certificate we can find with a matching
             username and public key, write its issuer name and serial
             number.
         */

        /* Free any previous contents of certList */
        FreeList (&certList);

        if ((errorMessage = GetCertsBySmartname
             (ripemDatabase, &certList, recipientKeys[i].username,
              ripemInfo)) != (char *)NULL)
          break;
        for (entry = certList.firstptr; entry; entry = entry->nextptr) {
          /* Decode the certificate.  On failure, just warn and continue.
           */
          if (DERToCertificate
              ((unsigned char *)entry->dataptr, certStruct,
               (CertFieldPointers *)NULL) < 0) {
            /* Error decoding.  Just issue a warning to debug stream and try
               the next cert. */
            if (ripemInfo->debug > 1)
              fprintf (ripemInfo->debugStream,
"Warning: Cannot decode certificate from database for writing RecipientInfo.\n");
            continue;
          }

          if (R_memcmp
              ((POINTER)&recipientKeys[i].publicKey,
               (POINTER)&certStruct->publicKey,
               sizeof (certStruct->publicKey)) != 0)
            /* Not the same public key.  Try the next */
            continue;

          /* Use nameDER repeatedly for storing the encoded name.
             First rewind and allocate enough space.
           */
          BufferStreamRewind (&nameDER);
          if ((errorMessage = BufferStreamWrite
               ((unsigned char *)NULL,
                len_distinguishedname (&certStruct->issuer) + 4,
                &nameDER)) != (char *)NULL)
            break;
          derPointer = nameDER.buffer;
          DistinguishedNameToDER (&certStruct->issuer, &derPointer);

          if ((errorMessage = WriteRecipientInfo
               (stream, encryptedKeysBuffer + i * MAX_ENCRYPTED_KEY_LEN,
                encryptedKeyLens[i], nameDER.buffer,
                derPointer - nameDER.buffer, certStruct->serialNumber,
                sizeof (certStruct->serialNumber))) != (char *)NULL)
            break;
        }
      }
      if (errorMessage != (char *)NULL)
        /* Broke loop because of error. */
        break;

      /* End the RecipientInfos */
      if ((errorMessage = BufferStreamWrite
           (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
          != (char *)NULL)
        break;
    }
#endif

    if (pkcsMode & PKCS_SIGNED) {
      if (digestAlgorithm == DA_SHA1) {
        if ((errorMessage = BufferStreamWrite
             (DIGEST_ALGORITHMS_SHA1_START,
	      sizeof (DIGEST_ALGORITHMS_SHA1_START), stream)) != (char *)NULL)
          break;
        if ((errorMessage = BufferStreamWrite
             (ALG_ID_SHA1, sizeof (ALG_ID_SHA1), stream)) != (char *)NULL)
          break;
      }
      else {
        /* MD2 or MD5 */
        if ((errorMessage = BufferStreamWrite
             (DIGEST_ALGORITHMS_START, sizeof (DIGEST_ALGORITHMS_START), stream))
            != (char *)NULL)
          break;
        if (digestAlgorithm == DA_MD2) {
          if ((errorMessage = BufferStreamWrite
               (ALG_ID_MD2, sizeof (ALG_ID_MD2), stream)) != (char *)NULL)
            break;
        }
        else if (digestAlgorithm == DA_MD5) {
          if ((errorMessage = BufferStreamWrite
               (ALG_ID_MD5, sizeof (ALG_ID_MD5), stream)) != (char *)NULL)
            break;
        }
	else {
          errorMessage = "Unsupported digest algorithm";
	  break;
	}
      }
    }

    if ((errorMessage = BufferStreamWrite
         (CONTENT_INFO_DATA_START, sizeof (CONTENT_INFO_DATA_START), stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamWrite
         (CONTENT_TYPE_DATA, sizeof (CONTENT_TYPE_DATA), stream))
        != (char *)NULL)
      break;

#ifndef RIPEMSIG
    if (pkcsMode & PKCS_ENVELOPED) {
      if ((errorMessage = WriteEncryptionAlgorithmID
           (stream, encryptionAlgorithm, iv)) != (char *)NULL)
        break;

      /* We are inside an EncryptedContentInfo which has an IMPLICIT
           OCTET STRING. */
      if ((errorMessage = BufferStreamWrite
           (IMPLICIT_OCTET_STRING_START, sizeof (IMPLICIT_OCTET_STRING_START),
            stream)) != (char *)NULL)
        break;
    }
    else
#endif
    {
      /* Not inside EncryptedContentInfo */
      if ((errorMessage = BufferStreamWrite
           (EXPLICIT_OCTET_STRING_START, sizeof (EXPLICIT_OCTET_STRING_START),
            stream)) != (char *)NULL)
        break;
    }

    /* Get ready to output the content */
    frame->startNewOctetString = TRUE;
    
    /* Set the output. */
    *partOut = frame->outStream.buffer;
    *partOutLen = frame->outStream.point;
  } while (0);
  
  FreeList (&certList);
  free (certStruct);
  free (encryptedKeysBuffer);
  free (encryptedKeyLens);
  BufferStreamDestructor (&nameDER);
  return (errorMessage);
}

/* Before this is called for the first time, the caller should have called
     RIPEMEncipherPKCSInit.  This is repeatedly called so supply the
     data to enhance.
   The data to enhance is in partIn with length partInLen.
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   The input and output are "as is": no translation of '\n' to <CR><LF> is
     done because this message format can support binary data.  The
     calling routine must do end-of-line character translation if necessary.
   After this, call RIPEMEncipherPKCSFinal to finalize.
   Return NULL for success or error string.
 */
char *RIPEMEncipherPKCSUpdate
  (ripemInfo, partOut, partOutLen, partIn, partInLen)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
unsigned char *partIn;
unsigned int partInLen;
{
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  char *errorMessage;
  int status;
  unsigned int localPartOutLen;

  if (frame == (RIPEMEncipherPKCSFrame *)NULL)
    return ("Encipher not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor)
    return ("Encipher frame was not initialized by RIPEMEncipherPKCSInit");

  /* Get stream for quick access. */
  stream = &frame->outStream;

  if (frame->pkcsMode & PKCS_SIGNED) {
    if ((status = R_SignUpdate
         (&frame->signatureContext, partIn, partInLen)) != 0)
      return (FormatRSAError (status));
  }

  if (frame->startNewOctetString) {
    /* Get ready to write to the output. */
    BufferStreamRewind (stream);

    /* Reserve enough bytes at the beginning of the buffer for us to
         put the der tag and length bytes there later. */
    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)NULL, MAX_TAG_AND_LEN_BYTES, stream))
        != (char *)NULL)
      return (errorMessage);

    frame->startNewOctetString = FALSE;
  }

  if (frame->pkcsMode == PKCS_SIGNED) {
    /* All we have to do is copy the input to the output. */
    if ((errorMessage = BufferStreamWrite (partIn, partInLen, stream))
        != (char *)NULL)
      return (errorMessage);
  }
#ifndef RIPEMSIG
  else {
    /* We must encrypt.  We need at least partInLen + 7 bytes of space
         in the output.  This space begins after the MAX_TAG_AND_LEN_BYTES
         which we already reserved. */
    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)NULL, partInLen + 7, stream)) != (char *)NULL)
      return (errorMessage);

    /* Now there is enough space to encrypt. We may have just reallocated
         the output buffer, so count back from the end of the buffer
         to find the place to encrypt to. */
    if ((status = R_SealUpdate
         (&frame->sealContext,
          (stream->buffer + stream->point) - (partInLen + 7),
          &localPartOutLen, partIn, partInLen)) != 0)
      return (FormatRSAError (status));

    /* Unput bytes in case we pre-allocated too many bytes. */
    BufferStreamUnput (stream, (partInLen + 7) - localPartOutLen);
  }
#endif

  /* Make sure we have accumulated enough bytes to make a reasonably-sized
       octet string. */
  if (stream->point < 512) {
    /* Wait to accumulate more */
    *partOut = stream->buffer;
    *partOutLen = 0;
  }
  else {
    /* Set the output and get ready to make new one. */
    GetEncipherUpdateOutput (partOut, partOutLen, stream);
    frame->startNewOctetString = TRUE;
  }
  
  return ((char *)NULL);
}

/* Call this after all text has been fed to RIPEMEncipherPKCSUpdate.  This
     flushes the output and writes the final bytes.  See
     RIPEMEncipherPKCSUpdate for a description of partOut and partOutLen.
   authenticatedAttributes is for future compatibility.  You should pass
     (RIPEMAttributes *)NULL.
   Return NULL for success or error string.
 */
char *RIPEMEncipherPKCSFinal
  (ripemInfo, partOut, partOutLen, authenticatedAttributes)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
RIPEMAttributes *authenticatedAttributes;
{
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  char *errorMessage;
  int status;
  unsigned char finalBlock[8];
  unsigned int localPartOutLen, partOutOffset;

UNUSED_ARG (authenticatedAttributes)

  if (frame == (RIPEMEncipherPKCSFrame *)NULL)
    return ("Encipher not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor)
    return ("Encipher frame was not initialized by RIPEMEncipherPKCSInit");

  /* Get stream for quick access. */
  stream = &frame->outStream;

#ifndef RIPEMSIG
  if (frame->pkcsMode & PKCS_ENVELOPED) {
    /* We need to put the final encryption block in the output. */

    if (frame->startNewOctetString) {
      /* Get ready to write a new octet string which just contains the
           final encryption block. */
      BufferStreamRewind (stream);

      /* Reserve enough bytes at the beginning of the buffer for us to
           put the der tag and length bytes there later. */
      if ((errorMessage = BufferStreamWrite
           ((unsigned char *)NULL, MAX_TAG_AND_LEN_BYTES, stream))
          != (char *)NULL)
        return (errorMessage);

      frame->startNewOctetString = FALSE;
    }

    /* Flush the encryption.  The final block is 8 bytes long. */
    if ((status = R_SealFinal
         (&frame->sealContext, finalBlock, &localPartOutLen)) != 0)
      return (FormatRSAError (status));

    if ((errorMessage = BufferStreamWrite
         (finalBlock, localPartOutLen, stream)) != (char *)NULL)
      return (errorMessage);
  }
#endif

  if (frame->startNewOctetString) {
    /* We are supposed to start a new octet string.  If this message
         were encrypted, then we would have set this to FALSE above,
         so we are in a signed message.  There is nothing to put in
         the output, so skip this octet string. */
    BufferStreamRewind (stream);
    partOutOffset = 0;
  }
  else {
    /* Note that the last sub-encoding of the indefinite-length octet
         string goes at the beginning of this buffer before all the rest. */
    GetEncipherUpdateOutput (partOut, &localPartOutLen, stream);
    /* partOut will be set again below, but find out how far into
         the output it is. */
    partOutOffset = *partOut - stream->buffer;
  }

  /* Close out the indefinite length constructed OCTET */
  if ((errorMessage = BufferStreamWrite
       (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
      != (char *)NULL)
    return (errorMessage);

  if (! (frame->pkcsMode & PKCS_ENVELOPED)) {
    /* Close out the [0] EXPLICIT from the ContentInfo.
       (The EncryptedContentInfo has IMPLICIT and doesn't need this). */
    if ((errorMessage = BufferStreamWrite
         (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
        != (char *)NULL)
      return (errorMessage);
  }

  /* Close out the ContentInfo. */
  if ((errorMessage = BufferStreamWrite
       (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
      != (char *)NULL)
    return (errorMessage);

  if (frame->pkcsMode & PKCS_SIGNED) {
    if ((errorMessage = WriteCertsAndSigner (ripemInfo)) != (char *)NULL)
      return (errorMessage);
  }

  if ((errorMessage = BufferStreamWrite
       (END_DATA_EXPLICIT_AND_CONTENT_INFO,
        sizeof (END_DATA_EXPLICIT_AND_CONTENT_INFO), stream))
      != (char *)NULL)
    return (errorMessage);

  /* Set the output.  Include the offset that may have been set
       while encoding the last octet string of the data content. */
  *partOut = stream->buffer + partOutOffset;
  *partOutLen = stream->point - partOutOffset;
  
  return ((char *)NULL);
}

/* Initialize ripemInfo for deciphering a PKCS message.
   After this, call RIPEMDecipherPKCSUpdate to supply the enhanced message
     by parts and call RIPEMDecipherPKCSFinal to finish and obtain the
     sender information.
   Return NULL for success or error string.
 */
char *RIPEMDecipherPKCSInit (ripemInfo)
RIPEMInfo *ripemInfo;
{
  RIPEMDecipherPKCSFrame *frame;

  /* Make sure any old frame is deleted and make a new one.
   */
  if (ripemInfo->z.decipherFrame != (RIPEMDecipherFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.decipherFrame->Destructor) (ripemInfo->z.decipherFrame);
    free (ripemInfo->z.decipherFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEMDecipherPKCSFrame */
  if ((ripemInfo->z.decipherFrame = (RIPEMDecipherFrame *)malloc
       (sizeof (RIPEMDecipherPKCSFrame))) == (RIPEMDecipherFrame *)NULL)
    return (ERR_MALLOC);
  RIPEMDecipherPKCSFrameConstructor
    ((RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame);

  frame = (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;

  /* Pre-set to not finding any attributes. */
  InitRIPEMAttributes (&frame->authenticatedAttributes);
  frame->foundRecipient = FALSE;
  frame->foundSigner = FALSE;

  /* Set up for the first decoding state. */
  frame->decodeState = DS_CONTENT_INFO_START | DS_ALLOW_INDEFINITE;

  return ((char *)NULL);
}

/* Call this after the decipher operation has been initialized with
     RIPEMDecipherPKCSInit.
   This deciphers the message in partIn of length partInLen, which contains the
     enhanced message.  partIn may contain any number of bytes.  This
     may be called multiple times.
  This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   The input and output are "as is": no translation of '\n' to <CR><LF> is
     done because this message format can support binary data.  The
     calling routine must do end-of-line character translation if necessary.
   After calling this to supply the enhanced message, call
     RIPEMDecipherPKCSFinal to finalize.
   Return NULL for success or error string.
 */
char *RIPEMDecipherPKCSUpdate
  (ripemInfo, partOut, partOutLen, partIn, partInLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
unsigned char *partIn;
unsigned int partInLen;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;
  int status, encryptionAlgorithm, tag;
  RIPEMDecipherPKCSFrame *frame =
    (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;
  unsigned char *input, *iv, *toVerify, *signature, *alloced,
    *encryptedKey, issuerSerialAlias[MD5_LEN];
  unsigned int octetPartInLen, toVerifyLen, localPartOutLen, signatureLen,
    encryptedKeyLen, inputLen, tagAndLenSize, i;
  R_RSA_PUBLIC_KEY publicKey;
  BOOL endConstructed;
  UINT4 contentLen, compensatedInputPoint;

  if (frame == (RIPEMDecipherPKCSFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPKCSFrameDestructor)
    return ("Decipher frame was not initialized by RIPEMDecipherPKCSInit");

  /* Get ready to write to the output. */
  BufferStreamRewind (&frame->outStream);

  if ((frame->decodeState & 0x7f) == DS_FINISHED)
    /* Ignore input past the end of the message */
    return ((char *)NULL);

  /* Accumulate all of partIn into the input buffer. */
  if ((errorMessage = BufferStreamWrite (partIn, partInLen, &frame->input))
      != (char *)NULL)
    return (errorMessage);

  /* Use local input to point to the bytes we are decoding. */
  input = frame->input.buffer;
  
  /* Go while the input has not reached the end of the buffer
   */
  while (input < (frame->input.buffer + frame->input.point)) {
    /* We process the state machine for decoding here.  The frame->decodeState,
         such as DS_CONTENT_TYPE, can be ored with flags such as
         DS_BYTES_NEEDED_ONLY.  (The case statement ignores these flags
         when switching.)  Before entering the case statement we do
         the following:
       - Set inputLen to the number of bytes remaining in the buffer
         starting at 'input'.
       - If frame->checkEndConstructed is not -1, then it is the
         decode state which corresponds to the beginning of the constructed
         type. (See below for what happens when a constructed type begins.)
         This will use the information at
         frame->constructedInfo[frame->checkEndConstructed] to determine
         whether the we are at the end of the constructed type and set
         endConstructed appropriately.  If we are at the end of the constructed
         type, the checks for DS_BYTES_NEEDED_ONLY or getting the tag
         and contentLen are ignored, tag and contentLen are undefined, and
         tagAndLenSize is 2 for the end of an indefinite length construct
         and 0 for a definite length construct.  (The case statement must
         advance input by tagAndLenSize.)  If we are not at the end of
         the constructed type, processing proceeds to check
         DS_BYTES_NEEDED_ONLY as below. In either case,
         frame->checkEndConstructed is reset to -1 so
         that it is not left with an arbitrary value.
       - If DS_BYTES_NEEDED_ONLY is set in frame->decodeState, then make sure
         inputLen is at least frame->bytesNeeded.  In this case,
         frame->bytesNeeded is not changed before entering the case statement.
         'tag' and 'contentLen' are undefined and the bytes at input must be
         interpreted by the case statement.
       - If DS_BYTES_NEEDED_ONLY is not set, then interpret the bytes at
         input as BER tag and content length octets, and set 'tag' and
         'contentLen'. (This may involve exiting to
         wait for more input to be passed into this routine
         so that all the tag and content length octets can be read.)
         If DS_ALLOW_INDEFINITE is set, then a content len octet of 0x80
         is allowed and contentLen is zero.  (A state which sets this flag
         can check input[1] to see if it is 0x80.) Otherwise, an indefinite
         length  causes an error.  Do not advance 'input' here.  (Only the
         case statements can advance 'input'.)  Rather, set tagAndLenSize
         to the number of bytes used for the tag and length octets.
         The content of the BER encoding starts at input + tagAndLenSize.
         If the tag indicates a constructed they then this stores information
         in frame->constructedInfo for the present frame->decodeState so that
         it can be used later if frame->checkEndConstructed is set to this
         decode state.  (For frame->checkEndConstructed to work properly
         later, the constructed type must be entered here without the
         DS_BYTES_NEEDED_ONLY flag set.)
         NOTE: In this case where DS_BYTES_NEEDED_ONLY is not set, this
         automatically resets frame->bytesNeeded to zero so that it doesn't
         have an arbitrary value.
     */
    inputLen = frame->input.point - (input - frame->input.buffer);

    /* Preset to FALSE */
    endConstructed = FALSE;

    if (frame->checkEndConstructed != -1) {
      if (frame->constructedInfo[frame->checkEndConstructed].endPoint == 0) {
        /* Look for 00 00 at the end of indefinite length */
        if (inputLen < 2)
          /* We can't even read a tag and a single content length octet,
               so wait for more input */
          break;

        if (input[0] == 0 && input[1] == 0) {
          endConstructed = TRUE;
          tagAndLenSize = 2;
        }
      }
      else {
        /* See if the input is at where endPoint was set to, compensating
             for the amount that the buffer has been flushed. */
        compensatedInputPoint = (UINT4)(input - frame->input.buffer) +
         (frame->flushedInput -
          frame->constructedInfo[frame->checkEndConstructed].saveFlushedInput);

        if (compensatedInputPoint >
            frame->constructedInfo[frame->checkEndConstructed].endPoint)
          /* We ran past the expected end of the constructed type. */
          return (ERR_PKCS_ENCODING);
        else if (compensatedInputPoint ==
                 frame->constructedInfo[frame->checkEndConstructed].endPoint) {
          endConstructed = TRUE;
          tagAndLenSize = 0;
        }
      }

      /* Reset to -1 so it doesn't have an arbitrary value */
      frame->checkEndConstructed = -1;
    }

    /* Only check DS_GET_TAG_AND_LEN or bytesNeeded if not endConstructed */
    if (!endConstructed) {
      if (frame->decodeState & DS_BYTES_NEEDED_ONLY) {
        /* Just make sure we have accumulated at least frame->bytesNeeded
             bytes before going to the case statement.
           Note that bytesNeeded is a UINT4.  On machines with a 2 byte
             unsigned int this is okay because BufferStreamWrite (which is
             accumulating the bytes) will make sure the buffer won't
             overflow the size given by unsigned int. */
        if (inputLen < frame->bytesNeeded)
          break;
      }
      else {
        /* Get the tag and content length */

        if (inputLen < 2)
          /* We can't even read a tag and a single content length octet,
               so wait for more input */
          break;
        /* Set tagAndLenSize and make sure inputLen is enough. */
        if (input[1] & 0x80)
          tagAndLenSize = 2 + (input[1] & 0x7f);
        else
          tagAndLenSize = 2;

        /* Make sure that the contentLen will not be an unreasonably large
             number. */
        if (tagAndLenSize > (2 + sizeof (contentLen)))
          return (ERR_PKCS_ENCODING);

        if (inputLen < tagAndLenSize)
          /* We need more input to even read the content length octets */
          break;

        tag = input[0];
        /* Assume tag is not zero since this would be handled in the
             checkEndConstructed section. */

        if (input[1] == 0x80) {
          /* Indefinite length */
          if (!(frame->decodeState & DS_ALLOW_INDEFINITE))
            return (ERR_PKCS_ENCODING);

          if (!(tag & BER_CONSTRUCTED))
            /* Indefinite length only allowed on constructed types */
            return (ERR_PKCS_ENCODING);

          tagAndLenSize = 2;
          /* Assume the case statement will check for indefinite length */
          contentLen = 0;
        }
        else {
          /* Read the contentLen.  Note that the contentLen is
               a UINT4.  This is so that, on machines with 2 byte
               unsigned int, we can still handle constructed definite-length
               encodings which are more that 65536 bytes.  (This should be
               okay as long as the subtypes - like a certificate - are
               small enough.)
           */
          if (input[1] & 0x80) {
            /* (We already handled the case where input[1] == 0x80) */
            contentLen = 0;
            for (i = 2; i < tagAndLenSize; ++i)
              contentLen = (contentLen << 8) + input[i];
          }
          else
            contentLen = (UINT4)(input[1] & 0x7f);
        }

        if (tag & BER_CONSTRUCTED) {
          /* Save the constructed info in the constructedInfo array
               element for this decode state.  (Make sure we strip off
               flags using & 0x7f .) */
          if (input[1] == 0x80)
            /* Indefinite length, so set endPoint to zero and forget the
                 flushedInput value */
            frame->constructedInfo[frame->decodeState & 0x7f].endPoint = 0;
          else {
            frame->constructedInfo[frame->decodeState & 0x7f].saveFlushedInput=
              frame->flushedInput;
            /* Calculate where the end point would be in the present
                 inputBuffer.
               We can check this later minus how much has been flushed. */
            frame->constructedInfo[frame->decodeState & 0x7f].endPoint =
              (UINT4)(input - frame->input.buffer) + contentLen +tagAndLenSize;
          }
        }

        /* Reset bytesNeeded so it doesn't have an arbitrary value. */
        frame->bytesNeeded = 0;
      }
    }

    /* Ignore flags when switching on the decode state */
    switch (frame->decodeState & 0xff) {
    case DS_CONTENT_INFO_START:
      if (tag != BER_SEQUENCE)
        return ("Invalid encoding at start of message");
      input += tagAndLenSize;

      frame->decodeState = DS_CONTENT_TYPE | DS_BYTES_NEEDED_ONLY;
      /* All content type identifiers are the same length, so use the
           length of one of them. */
      frame->bytesNeeded = sizeof (CONTENT_TYPE_SIGNED_DATA);
      break;

    case DS_CONTENT_TYPE:
      if ((frame->pkcsMode = DecodeContentType (input)) == 0)
        return ("Unrecognized content type");

#ifdef RIPEMSIG
      if (frame->pkcsMode & PKCS_ENVELOPED)
        return ("RIPEM/SIG cannot process ENCRYPTED messages. You may process signed messages.");
#endif

      if (frame->detached && frame->pkcsMode != PKCS_SIGNED)
        return ("The detached PKCS information is not of type SIGNED");

      /* All identifiers are the same length */
      input += sizeof (CONTENT_TYPE_SIGNED_DATA);

      frame->decodeState = DS_CONTENT_INFO_CONTENT | DS_ALLOW_INDEFINITE;
      break;

    case DS_CONTENT_INFO_CONTENT:
      if (tag != (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0))
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;
              
      frame->decodeState = DS_X_DATA_START | DS_ALLOW_INDEFINITE;
      break;

    case DS_X_DATA_START:
      /* This is the start of a SignedData or similar type */
      if (tag != BER_SEQUENCE)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;
              
      frame->decodeState = DS_X_DATA_VERSION;
      break;

    case DS_X_DATA_VERSION:
      /* Require a one byte integer */
      if (tag != BER_INTEGER || contentLen != 1)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      frame->decodeState = DS_CHECK_X_DATA_VERSION | DS_BYTES_NEEDED_ONLY;
      frame->bytesNeeded = 1;
      break;

    case DS_CHECK_X_DATA_VERSION:
      if (frame->pkcsMode & PKCS_SIGNED) {
        if (input[0] != 1)
          return ("Invalid version for content type");
      }
      else {
        if (input[0] != 0)
          return ("Invalid version for content type");
      }
      input += 1;

      if (frame->pkcsMode & PKCS_ENVELOPED)
        /* Get ready for recipientsInfos. */
        frame->decodeState = DS_RECIPIENT_INFOS_START | DS_ALLOW_INDEFINITE;
      else
        /* This is signed only */
        frame->decodeState = DS_DIGEST_ALGORITHMS_START | DS_ALLOW_INDEFINITE;

      break;

    case DS_RECIPIENT_INFOS_START:
#ifndef RIPEMSIG
      if (tag != BER_SET)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      frame->decodeState = DS_CHECK_RECIPIENT_INFOS_END;
      frame->checkEndConstructed = DS_RECIPIENT_INFOS_START;
#endif
      break;

    case DS_CHECK_RECIPIENT_INFOS_END:
#ifndef RIPEMSIG
      /* This case may get executed multiple times.  We need to see
           if we are at the end of the recipient infos yet. */
      if (endConstructed) {
        /* We are finished with recipient infos. */
        input += tagAndLenSize;

        if (!frame->foundRecipient)
          return ("You are not listed as a recipient in this message.");

        if (frame->pkcsMode & PKCS_SIGNED)
          frame->decodeState =DS_DIGEST_ALGORITHMS_START | DS_ALLOW_INDEFINITE;
        else
          /* This is enveloped only, so skip over digest algorithms. */
          frame->decodeState =DS_CONTENT_INFO_DATA_START | DS_ALLOW_INDEFINITE;
      }
      else {
        /* We will need the entire encoding including tag and length
             octets, so set bytesNeeded without advancing input. */
        frame->decodeState = DS_RECIPIENT_INFO | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = tagAndLenSize + contentLen;
      }
#endif
      break;

    case DS_RECIPIENT_INFO:
#ifndef RIPEMSIG
      /* Only decode the RecipientInfo if we haven't found one yet. */
      if (!frame->foundRecipient) {
        /* Note that we can use frame->issuerName here, and that we will
             be done with it in time to use it for DecodeSignerInfo
             below. */
        if ((errorMessage = DecodeRecipientInfo
             (input, &frame->issuerName, frame->serialNumber,
              &encryptedKey, &encryptedKeyLen)) != (char *)NULL)
          return (errorMessage);

        /* Compute the alias and check if it is in the ripemInfo.
         */
        ComputeIssuerSerialAlias
          (issuerSerialAlias, &frame->issuerName, frame->serialNumber,
           sizeof (frame->serialNumber));
        if (IsIssuerSerialAlias (ripemInfo, issuerSerialAlias)) {
          /* This RecipientInfo is for the recipient, so copy the
               encryptedKey which will be used below in R_OpenInit.
           */
          frame->foundRecipient = TRUE;

          R_memcpy
            ((POINTER)frame->encryptedKey, (POINTER)encryptedKey,
             encryptedKeyLen);
          frame->encryptedKeyLen = encryptedKeyLen;
        }
      }

      /* bytesNeeded is still set to the total length of the RecipientInfo */
      input += frame->bytesNeeded;

      /* Go back to check for more recipients */
      frame->decodeState = DS_CHECK_RECIPIENT_INFOS_END;
      frame->checkEndConstructed = DS_RECIPIENT_INFOS_START;
#endif
      break;
      
    case DS_DIGEST_ALGORITHMS_START:
      if (tag != BER_SET)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      /* Preset to zero */
      frame->digestAlgorithm = 0;

      frame->decodeState = DS_CHECK_DIGEST_ALGORITHMS_END;
      frame->checkEndConstructed = DS_DIGEST_ALGORITHMS_START;
      break;

    case DS_CHECK_DIGEST_ALGORITHMS_END:
      if (endConstructed) {
        /* Note that we are requiring that there only be zero or one digest
             algorithm. */
        if (frame->digestAlgorithm == 0) {
          /* There are no digest algorithms.  This is supposedly a
               certs-and-crls-only message. */
          if (frame->pkcsMode != PKCS_SIGNED)
            return ("Empty digest algorithm set only allowed in PKCS message type SignedData.");
          if (frame->detached)
            return ("Detached signature has an empty digest algorithm set.");

          /* Don't initialize the signatureContext */
        }
        input += tagAndLenSize;

        frame->decodeState =DS_CONTENT_INFO_DATA_START | DS_ALLOW_INDEFINITE;
      }
      else {
        /* There are more digest algorithms */
        if (frame->digestAlgorithm != 0)
          /* Already have one */
          return("Only one digest algorithm may be specified in PKCS message");

        /* Do not advance input */
        frame->decodeState = DS_GET_DIGEST_ALGORITHM | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = tagAndLenSize + contentLen;
      }

      break;

    case DS_GET_DIGEST_ALGORITHM:
      if (R_memcmp
          ((POINTER)input, (POINTER)ALG_ID_MD2, sizeof (ALG_ID_MD2)) == 0)
        frame->digestAlgorithm = DA_MD2;
      else if (R_memcmp
          ((POINTER)input, (POINTER)ALG_ID_MD5, sizeof (ALG_ID_MD5)) == 0)
        frame->digestAlgorithm = DA_MD5;
      else if (R_memcmp
          ((POINTER)input, (POINTER)ALG_ID_SHA1, sizeof (ALG_ID_SHA1)) == 0)
        frame->digestAlgorithm = DA_SHA1;
      else
        return ("Unrecognized digest algorithm");

      input += frame->bytesNeeded;

      if (frame->detached) {
        /* For detached signatures, we have already used R_VerifyInit and
             R_VerifyUpdate. Just make sure that the digest algorithm we
             used is what was expected */
        if (frame->digestAlgorithm != frame->expectedDigestAlgorithm)
          return ("Unexpected digest algorithm specified in detached PKCS signature.");
      }
      else {
        if ((status = R_VerifyInit
             (&frame->signatureContext, frame->digestAlgorithm)) != 0)
          return (FormatRSAError (status));
      }

      frame->decodeState = DS_CHECK_DIGEST_ALGORITHMS_END;
      frame->checkEndConstructed = DS_DIGEST_ALGORITHMS_START;
      break;

    case DS_CONTENT_INFO_DATA_START:
      if (tag != BER_SEQUENCE)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      /* Expect only CONTENT_TYPE_DATA at this point */
      frame->decodeState = DS_CONTENT_INFO_DATA_TYPE | DS_BYTES_NEEDED_ONLY;
      frame->bytesNeeded = sizeof (CONTENT_TYPE_DATA);
      break;

    case DS_CONTENT_INFO_DATA_TYPE:
      if (R_memcmp
          ((POINTER)input, (POINTER)CONTENT_TYPE_DATA,
           sizeof (CONTENT_TYPE_DATA)) != 0)
        return (ERR_PKCS_ENCODING);
      input += sizeof (CONTENT_TYPE_DATA);

      if (frame->pkcsMode & PKCS_ENVELOPED)
        frame->decodeState = DS_ENCRYPTION_ALGORITHM_START;
      else {
        frame->decodeState = DS_EXPLICIT_DATA_CONTENT | DS_ALLOW_INDEFINITE;
        /* The data content may be omitted so check for end encoding */
        frame->checkEndConstructed = DS_CONTENT_INFO_DATA_START;
      }
      break;

    case DS_ENCRYPTION_ALGORITHM_START:
      /* Do not advance input */
      frame->decodeState = DS_ENCRYPTION_ALGORITHM | DS_BYTES_NEEDED_ONLY;
      frame->bytesNeeded = tagAndLenSize + contentLen;
      break;

    case DS_ENCRYPTION_ALGORITHM:
#ifndef RIPEMSIG
      if ((errorMessage = DecodeEncryptionAlgorithmID
           (input, &encryptionAlgorithm, &iv)) != (char *)NULL)
        return (errorMessage);

      /* bytesNeeded is still set to the total length of the CRL. */
      input += frame->bytesNeeded;

      /* Decrypt the encryptedKey.  We have already made sure that
           foundRecipient is TRUE. */
      if ((status = R_OpenInit
           (&frame->envelopeContext, encryptionAlgorithm, frame->encryptedKey,
            frame->encryptedKeyLen, iv, &ripemInfo->privateKey)) != 0)
        return (FormatRSAError (status));

      frame->decodeState = DS_IMPLICIT_OCTET_STRING | DS_ALLOW_INDEFINITE;
#endif
      break;

    case DS_EXPLICIT_DATA_CONTENT:
      /* We know this is only called for a PKCS_SIGNED message */
      if (endConstructed) {
        if (frame->digestAlgorithm == 0 || frame->detached) {
          /* This could be a good thing.  For certs-and-CRLs only or
               detached signatures, we expect the optional content to be
               omitted.  Skip past the octet string.  Set checkEndConstructed
               again since DS_CONTENT_INFO_DATA_END expects it, and don't
               advance input. */
          frame->decodeState = DS_CONTENT_INFO_DATA_END;
          frame->checkEndConstructed = DS_CONTENT_INFO_DATA_START;
        }
        else
          return (ERR_PKCS_ENCODING);
      }
      else {
        if (tag != (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0))
          return (ERR_PKCS_ENCODING);
        input += tagAndLenSize;

        if (frame->digestAlgorithm == 0)
          /* This effectively ensures that there is no content if there
               are no digest algorithms (certs-and-CRLs only message).*/
          return("No digest algorithm is specified for digesting the content");
        if (frame->detached)
          return ("The detached PKCS information must not contain message content.");

        frame->decodeState = DS_EXPLICIT_OCTET_STRING | DS_ALLOW_INDEFINITE;
      }
      break;

    case DS_EXPLICIT_OCTET_STRING:
      /* We know this is only called for a PKCS_SIGNED message */
      if (tag == (BER_OCTET_STRING | BER_CONSTRUCTED)) {
        frame->constructedOctetString = 1;
        frame->decodeState = DS_CHECK_OCTET_STRING_END;
        frame->checkEndConstructed = DS_EXPLICIT_OCTET_STRING;
      }
      else if (tag == BER_OCTET_STRING) {
        frame->constructedOctetString = 0;

        /* Set up for processing the octet string as we would have in
             DS_CHECK_OCTET_STRING_END.  When DS_OCTET_STRING_PART is
             finished with the whole octet string it will go to the
             next state based on constructedOctetString. */
        frame->octetStringContentLen = contentLen;
        frame->decodeState = DS_OCTET_STRING_PART | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = 0;
      }
      else
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      break;

    case DS_IMPLICIT_OCTET_STRING:
      /* We know this message is enveloped.  For enveloped messages we
           don't allow omitted content. */
      if (tag == (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0)) {
        /* constructed octet string */
        frame->constructedOctetString = 1;
        frame->decodeState = DS_CHECK_OCTET_STRING_END;
        frame->checkEndConstructed = DS_IMPLICIT_OCTET_STRING;
      }
      else if (tag == (BER_CONTEXT_SPECIFIC | 0)) {
        /* non-constructed octet string. */
        frame->constructedOctetString = 0;

        /* Set up for processing the octet string as we would have in
             DS_CHECK_OCTET_STRING_END.  When DS_OCTET_STRING_PART is
             finished with the whole octet string it will go to the
             next state based on constructedOctetString. */
        frame->octetStringContentLen = contentLen;
        frame->decodeState = DS_OCTET_STRING_PART | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = 0;
      }
      else
        return (ERR_PKCS_ENCODING);

      input += tagAndLenSize;
      break;

    case DS_CHECK_OCTET_STRING_END:
      /* This case may get executed multiple times.  It is only called for
           a constructed octet string and we need to see if we are at the end.
         Depending on whether this is PKCS_SIGNED or not, the state
           which put us here had already set checkEndConstructed to
           the decode state which began the EXPLICIT constructed octet string
           (for PKCS_SIGNED) or the IMPLICIT octet string (if there is
           an envelope).
       */
      if (endConstructed) {
        /* We are finished with octet string. */
        input += tagAndLenSize;

        if (frame->pkcsMode & PKCS_ENVELOPED) {
          /* For an encrypted content, we have already just closed out the
               content, so go straight to closing the EncryptedContentInfo,
               which is the same for closing the ContentInfo. */
          frame->decodeState = DS_CONTENT_INFO_DATA_END;
          frame->checkEndConstructed = DS_CONTENT_INFO_DATA_START;
        }
        else {
          frame->decodeState = DS_END_EXPLICIT_DATA_CONTENT;
          frame->checkEndConstructed = DS_EXPLICIT_DATA_CONTENT;
        }
      }
      else {
        /* Set up for reading the part of the constructed octet string */
        if (tag != BER_OCTET_STRING)
          return (ERR_PKCS_ENCODING);
        input += tagAndLenSize;
        frame->octetStringContentLen = contentLen;

        frame->decodeState = DS_OCTET_STRING_PART | DS_BYTES_NEEDED_ONLY;
        /* Set to zero since we will work with whatever we get instead of
             requiring all of the octet string sub-encoding to be accumulated
             into frame->input.  This allows it to be longer than we would
             want to accumulate. */
        frame->bytesNeeded = 0;
      }
      break;

    case DS_OCTET_STRING_PART:
      /* First set octetPartInLen to the number of remaining bytes in
           the input buffer */
      octetPartInLen = inputLen;
      if (octetPartInLen > frame->octetStringContentLen)
        /* There are more bytes in the input than we need, so limit
             octetPartInLen to the end of the octet string part. */
        octetPartInLen = frame->octetStringContentLen;

#ifndef RIPEMSIG
      if (frame->pkcsMode & PKCS_ENVELOPED) {
        /* We want to decrypt to the output stream's buffer, so reserve
             enough length as specified by R_OpenUpdate. */
        if ((errorMessage = BufferStreamWrite
             ((unsigned char *)NULL, octetPartInLen + 7,
              &frame->outStream)) != (char *)NULL)
          return (errorMessage);
        /* We have to set toVerify after BufferStreamWrite since if we
             set it before, BufferStreamWrite may reallocate the buffer. */
        toVerify = (frame->outStream.buffer + frame->outStream.point) -
          (octetPartInLen + 7);

        if ((status = R_OpenUpdate
             (&frame->envelopeContext, toVerify, &toVerifyLen, input,
              octetPartInLen)) != 0)
          return (FormatRSAError (status));

        /* Now, readjust the buffer length to how much R_OpenUpdate put
             out in case we allocated too much space. */
        BufferStreamUnput
          (&frame->outStream, (octetPartInLen + 7) - toVerifyLen);
      }
      else
#endif
      {
        /* Signed only, so just copy to the output. */
        if ((errorMessage = BufferStreamWrite
             (input, octetPartInLen, &frame->outStream)) != (char *)NULL)
          return (errorMessage);
        /* We have to set toVerify after BufferStreamWrite since if we
             set it before, BufferStreamWrite may reallocate the buffer. */
        toVerify = (frame->outStream.buffer + frame->outStream.point) -
          octetPartInLen;
        toVerifyLen = octetPartInLen;
      }

      if (frame->pkcsMode & PKCS_SIGNED) {
        /* toVerify and toVerifyLen have been set above. */
        if ((status = R_VerifyUpdate
             (&frame->signatureContext, toVerify, toVerifyLen)) != 0)
          return (FormatRSAError (status));
      }

      input += octetPartInLen;
      frame->octetStringContentLen -= octetPartInLen;
      if (frame->octetStringContentLen == 0) {
        /* We have finished processing this octet string sub-encoding */
        if (frame->constructedOctetString) {
          /* Depending on whether we are inside an EXPLICIT or IMPLICIT
               octet string, we must set checkEndConstructed appropriately. */
          frame->decodeState = DS_CHECK_OCTET_STRING_END;
          if (frame->pkcsMode & PKCS_ENVELOPED)
            frame->checkEndConstructed = DS_IMPLICIT_OCTET_STRING;
          else
            frame->checkEndConstructed = DS_EXPLICIT_OCTET_STRING;
        }
        else {
          /* non-constructed octet string */
          if (frame->pkcsMode & PKCS_ENVELOPED) {
            /* Go straight to closing the EncryptedContentInfo,
                 which is the same for closing the ContentInfo. */
            frame->decodeState = DS_CONTENT_INFO_DATA_END;
            frame->checkEndConstructed = DS_CONTENT_INFO_DATA_START;
          }
          else {
            frame->decodeState = DS_END_EXPLICIT_DATA_CONTENT;
            frame->checkEndConstructed = DS_EXPLICIT_DATA_CONTENT;
          }
        }
      }
      else
        /* Keep the decodeState here so we can get some more bytes */
        frame->bytesNeeded = 0;

      break;
      
    case DS_END_EXPLICIT_DATA_CONTENT:
      /* This is called for non-encrypted content */
      if (!endConstructed)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      frame->decodeState = DS_CONTENT_INFO_DATA_END;
      frame->checkEndConstructed = DS_CONTENT_INFO_DATA_START;
      break;

    case DS_CONTENT_INFO_DATA_END:
      if (!endConstructed)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

#ifndef RIPEMSIG
      if (frame->pkcsMode & PKCS_ENVELOPED) {
        /* We need to call R_OpenFinal (and maybe R_VerifyUpdate again), so
             reserve as many bytes as it  may write out. */
        if ((errorMessage = BufferStreamWrite
             ((unsigned char *)NULL, 7, &frame->outStream)) != (char *)NULL)
          return (errorMessage);
        /* We have to set toVerify after BufferStreamWrite since if we
             set it before, BufferStreamWrite may reallocate the buffer. */
        toVerify = (frame->outStream.buffer + frame->outStream.point) - 7;

        if ((status = R_OpenFinal
             (&frame->envelopeContext, toVerify, &toVerifyLen)) != 0)
          return (FormatRSAError (status));

        /* Now, readjust the buffer length to how much R_OpenFinal put
             out in case we allocated too much space. */
        BufferStreamUnput (&frame->outStream, 7 - toVerifyLen);

        if (frame->pkcsMode & PKCS_SIGNED) {
          if ((status = R_VerifyUpdate
               (&frame->signatureContext, toVerify, toVerifyLen)) != 0)
            return (FormatRSAError (status));
        }
      }
#endif

      if (frame->pkcsMode & PKCS_SIGNED)
        frame->decodeState = DS_CHECK_CERTIFICATES_SET | DS_ALLOW_INDEFINITE;
      else {
        frame->decodeState = DS_X_DATA_END;
        frame->checkEndConstructed = DS_X_DATA_START;
      }
      break;

    case DS_CHECK_CERTIFICATES_SET:
      /* [0] IMPLICIT */
      if (tag == (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0)) {
        input += tagAndLenSize;

        frame->decodeState =DS_CHECK_CERTIFICATES_SET_END;
        frame->checkEndConstructed = DS_CHECK_CERTIFICATES_SET;
      }
      else
        /* This certificates set seems to be omitted, so look for CRLs */
        frame->decodeState = DS_CHECK_CRLS_SET | DS_ALLOW_INDEFINITE;
      break;

    case DS_CHECK_CERTIFICATES_SET_END:
      /* This case may get executed multiple times.  We need to see
           if we are at the end of the certificates set yet. */
      if (endConstructed) {
        /* We are finished with certificates. */
        input += tagAndLenSize;

        if (frame->digestAlgorithm != 0) {
          /* For a non-certs-and-CRLs-only-message, we have cached the certs,
               so insert the certificates now in case there are CRLs below. */
          if ((errorMessage = InsertCerts
               (&frame->certs, ripemInfo, ripemDatabase)) != (char *)NULL)
            return (errorMessage);
        }

        frame->decodeState = DS_CHECK_CRLS_SET | DS_ALLOW_INDEFINITE;
      }
      else {
        /* We will need the entire encoding including tag and length
             octets, so set bytesNeeded without advancing input. */
        frame->decodeState = DS_CERTIFICATE | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = tagAndLenSize + contentLen;
      }
      break;
      
    case DS_CERTIFICATE:
      /* bytesNeeded is still set to the total length of the certificate */
      if (frame->digestAlgorithm == 0) {
        /* This is a certs-and-CRLs-only message.  There are no signers so
             there is no need to cache the certificates in frame->certs, so
             just try to insert this cert into the database.  This way, we can
             handle an arbitrarily large certs-and-CRLs-only message. */
        if ((errorMessage = InsertUniqueCert
             (input, ripemInfo, ripemDatabase)) != (char *)NULL)
          return (errorMessage);
      }
      else {
        /* We must cache the certs so that we can look for an issuer/serial
             match with the SignerInfo.  If the database could look up
             certificates by issuer/serial, then this would not be necessary.
         */
        if ((alloced = (unsigned char *)malloc (frame->bytesNeeded))
            == (unsigned char *)NULL)
          return (ERR_MALLOC);
        R_memcpy ((POINTER)alloced, (POINTER)input, frame->bytesNeeded);
        if ((errorMessage = AddToList
             ((TypListEntry *)NULL, alloced, frame->bytesNeeded,
              &frame->certs)) != (char *)NULL) {
          /* AddToList failed to incorporate the alloced data, so free it. */
          free (alloced);
          return (errorMessage);
        }
      }
      
      input += frame->bytesNeeded;

      /* Go back to check for more certificates */
      frame->decodeState = DS_CHECK_CERTIFICATES_SET_END;
      frame->checkEndConstructed = DS_CHECK_CERTIFICATES_SET;
      break;
      
    case DS_CHECK_CRLS_SET:
      /* [1] IMPLICIT */
      if (tag == (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 1)) {
        input += tagAndLenSize;

        frame->decodeState = DS_CHECK_CRLS_SET_END;
        frame->checkEndConstructed = DS_CHECK_CRLS_SET;
      }
      else
        /* This CRLs set seems to be omitted, so go to SignerInfos */
        frame->decodeState = DS_SIGNER_INFOS_START | DS_ALLOW_INDEFINITE;
      break;

    case DS_CHECK_CRLS_SET_END:
      /* This case may get executed multiple times.  We need to see
           if we are at the end of the CRLs set yet. */
      if (endConstructed) {
        /* We are finished with CRLs. */
        input += tagAndLenSize;

        frame->decodeState = DS_SIGNER_INFOS_START | DS_ALLOW_INDEFINITE;
      }
      else {
        /* We will need the entire encoding including tag and length
             octets, so set bytesNeeded without advancing input. */
        frame->decodeState = DS_CRL | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = tagAndLenSize + contentLen;
      }
      break;
      
    case DS_CRL:
      /* Try to insert the CRL now instead of saving it to insert
           later.  This is helpful if the CRL is large.
       */
      if ((errorMessage = VerifyAndInsertCRL (input, ripemInfo, ripemDatabase))
          != (char *)NULL)
        return (errorMessage);

      /* bytesNeeded is still set to the total length of the CRL. */
      input += frame->bytesNeeded;

      /* Go back to check for more CRLs */
      frame->decodeState = DS_CHECK_CRLS_SET_END;
      frame->checkEndConstructed = DS_CHECK_CRLS_SET;
      break;
      
    case DS_SIGNER_INFOS_START:
      if (tag != BER_SET)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      frame->decodeState = DS_CHECK_SIGNER_INFOS_END;
      frame->checkEndConstructed = DS_SIGNER_INFOS_START;
      break;

    case DS_CHECK_SIGNER_INFOS_END:
      /* This case may get executed multiple times.  We need to see
           if we are at the end of the signer infos yet. */
      if (endConstructed) {
        /* We are finished with signer infos. */
        input += tagAndLenSize;

        frame->decodeState = DS_X_DATA_END;
        frame->checkEndConstructed = DS_X_DATA_START;
      }
      else {
        if (frame->digestAlgorithm == 0)
          /* This should be a certs-and-CRLs-only message. */
          return ("A SignerInfo is supplied but there is no message content to be verified");

        if (frame->foundSigner)
          /* We already have one signer and we do not support multiples. */
          return ("Too many SignerInfos in message");

        /* We will need the entire encoding including tag and length
             octets, so set bytesNeeded without advancing input. */
        frame->decodeState = DS_SIGNER_INFO | DS_BYTES_NEEDED_ONLY;
        frame->bytesNeeded = tagAndLenSize + contentLen;
      }
      break;

    case DS_SIGNER_INFO:
      frame->foundSigner = TRUE;
      
      if ((errorMessage = DecodeSignerInfo
           (input, &frame->issuerName, frame->serialNumber,
            frame->digestAlgorithm, &frame->signatureContext, &signature,
            &signatureLen, &frame->authenticatedAttributes,
            &frame->attributesBuffers))
          != (char *)NULL)
        return (errorMessage);

      /* This also sets the certChain */
      if ((errorMessage = GetSignerPublicKey
           (frame, ripemInfo, &publicKey, ripemDatabase)) != (char *)NULL)
        return (errorMessage);

      /* If the chain status is zero, we couldn't find a public key.
           Perhaps there is a self-signed cert to validate, so copying the
           certChain later is important, but don't try to validate the message
           signature. */
      if (frame->chainStatus.overall != 0) {
#ifndef RIPEMSIG
        if (frame->pkcsMode & PKCS_ENVELOPED) {
          /* Must decrypt the signature.  Use the buffer in the frame for
               the result.
             The envelopeContext has already been finalized, so we can
               use it to decrypt again. */
          if ((status = R_OpenUpdate
               (&frame->envelopeContext, frame->signature, &signatureLen,
                signature, signatureLen)) != 0)
            return (FormatRSAError (status));
          if ((status = R_OpenFinal
               (&frame->envelopeContext, frame->signature + signatureLen,
                &localPartOutLen)) != 0)
            return (FormatRSAError (status));
          signatureLen += localPartOutLen;

          /* The result is now in the buffer, so point there. */
          signature = frame->signature;
        }
#endif

        if ((status = R_VerifyFinal
             (&frame->signatureContext, signature, signatureLen,
              &publicKey)) != 0)
          /* This will return a bad signature error if there is one */
          return (FormatRSAError (status));
      }

      /* bytesNeeded is still set to the total length of the SignerInfo */
      input += frame->bytesNeeded;

      /* Go back to check for more signers */
      frame->decodeState = DS_CHECK_SIGNER_INFOS_END;
      frame->checkEndConstructed = DS_SIGNER_INFOS_START;
      break;
      
    case DS_X_DATA_END:
      if (!endConstructed)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      frame->decodeState = DS_CONTENT_INFO_CONTENT_END;
      frame->checkEndConstructed = DS_CONTENT_INFO_CONTENT;
      break;

    case DS_CONTENT_INFO_CONTENT_END:
      if (!endConstructed)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      frame->decodeState = DS_CONTENT_INFO_END;
      frame->checkEndConstructed = DS_CONTENT_INFO_START;
      break;

    case DS_CONTENT_INFO_END:
      if (!endConstructed)
        return (ERR_PKCS_ENCODING);
      input += tagAndLenSize;

      /* Set DS_BYTES_NEEDED_ONLY to avoid interpreting bytes */
      frame->decodeState = DS_FINISHED | DS_BYTES_NEEDED_ONLY;
      frame->bytesNeeded = 0;
      break;

    default:
      /* This should never happen since we define the state. If it does, either
           we forgot to process a state, or the decodeState is corrupt. */
      return ("Internal error: invalid decode state");
    }
  }

  /* We have processed as much of the input as possible, so shift any
       remaining bytes to the front to get ready for the next Update.
     Track how much we flush in flushedInput. */
  frame->flushedInput += (UINT4)(input - frame->input.buffer);
  BufferStreamFlushBytes (&frame->input, input - frame->input.buffer);

  /* Set the output */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Call this after the entire enhanced message has been supplied to
     RIPEMDecipherPKCSUpdate.
   Return the sender's certChain and chainStatus. The calling routine must
     InitList certChain.  chainStatus is pointer to a ChainStatusInfo struct.
   If chainStatus->overall is 0, this could not find a valid public key for
     the sender and pkcsMode is undefined. In this case, if the message
     contained a self-signed certificate, the certChain contains one entry
     which is the self-signed cert.  The calling routine may decode it and
     present the self-signed cert digest, and use ValidateAndWriteCert to
     validate the user.
   For other values of chainStatus->overall, certChain and chainStatus
     contains values as described in SelectCertChain.  Note: the sender
     name is the subject of the cert at the "bottom" of the chain.
     Unlike RIPEMDecipherFinal (for PEM), this does not support a chain
     status of CERT_UNVALIDATED since PKCS identifies senders and recipients
     via certificates.
   pkcsMode is set to PKCS_SIGNED, PKCS_ENVELOPED,
     PKCS_SIGNED|PKCS_ENVELOPED, or PKCS_CERTS_AND_CRLS_ONLY.  If pkcsMode
     is set to PKCS_CERTS_AND_CRLS_ONLY or PKCS_ENVELOPED, then certChain is
     unmodified since there are no senders, and chainStatus->overall
     is set to zero.
   If authenticatedAttributes is not NULL, then it points to a
     RIPEMAttributes which receives the authenticated attributes in the
     message if any.  The "have" flag is set if the attributes is present.
     For example, if there was a signing time, haveSigningTime is set TRUE
     and signingTime contains the result.  The memory for the buffers such
     as signingDescription is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the value must be
     copied before a future call to RIPEM since RIPEM may modify it.
     authenticatedAttributes may be NULL, in which case it is ignored.
   Return NULL for success or error string.
 */
char *RIPEMDecipherPKCSFinal
  (ripemInfo, certChain, chainStatus, pkcsMode, authenticatedAttributes)
RIPEMInfo *ripemInfo;
TypList *certChain;
ChainStatusInfo *chainStatus;
int *pkcsMode;
RIPEMAttributes *authenticatedAttributes;
{
  RIPEMDecipherPKCSFrame *frame =
    (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;

  if (frame == (RIPEMDecipherPKCSFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPKCSFrameDestructor) 
    return ("Decipher frame was not initialized by RIPEMDecipherPKCSInit");

  if ((frame->decodeState & 0x7f) != DS_FINISHED)
    return ("End of input was signalled before reading all of the message");

  if (frame->pkcsMode == PKCS_SIGNED && frame->digestAlgorithm == 0) {
    /* Certs-and-CRLs-only message */
    *pkcsMode = PKCS_CERTS_AND_CRLS_ONLY;
    chainStatus->overall = 0;
    return ((char *)NULL);
  }

  *pkcsMode = frame->pkcsMode;

  if (frame->pkcsMode == PKCS_ENVELOPED) {
    /* There is no sender. */
    chainStatus->overall = 0;
    return ((char *)NULL);
  }
    
  /* Now return the sender's info to the caller.  Copy the chain's TypList
       which will transfer all the pointers to the caller.  Then re-initialize
       the frame's TypList so that the destructor won't try to free the memory.
   */
  *certChain = frame->certChain;
  InitList (&frame->certChain);
  /* This copies the entire ChainStatusInfo. */
  *chainStatus = frame->chainStatus;

  if (authenticatedAttributes != (RIPEMAttributes *)NULL)
    *authenticatedAttributes = frame->authenticatedAttributes;

  return ((char *)NULL);
}

/* Initialize for preparing a PKCS detached signature.
   The calling routine must already have called RIPEMLoginUser.
   digestAlgorithm must be DA_MD2, DA_MD5 or DA_SHA1.
   After this, call RIPEMSignDetachedPKCSDigestUpdate to digest the text by
     parts, and call RIPEMSignDetachedPKCSFinal to finish.
   Return NULL for success or error string.
 */
char *RIPEMSignDetachedPKCSInit (ripemInfo, digestAlgorithm)
RIPEMInfo *ripemInfo;
int digestAlgorithm;
{
  RIPEMEncipherPKCSFrame *frame;
  int status;
  char *errorMessage = (char *)NULL;
  
  /* For error, break to end of do while (0) block. */
  do {
    /* Make sure any old frame is deleted and make a new one.
     */
    if (ripemInfo->z.encipherFrame != (RIPEMEncipherFrame *)NULL) {
      /* Be sure to call the "virtual" destructor */
      (*ripemInfo->z.encipherFrame->Destructor) (ripemInfo->z.encipherFrame);
      free (ripemInfo->z.encipherFrame);
    }
    /* Be sure to malloc for the size of an entire RIPEMEncipherPKCSFrame */
    if ((ripemInfo->z.encipherFrame = (RIPEMEncipherFrame *)malloc
         (sizeof (*frame))) == (RIPEMEncipherFrame *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    RIPEMEncipherPKCSFrameConstructor
      ((RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame);

    frame = (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
    frame->pkcsMode = PKCS_SIGNED;
    frame->digestAlgorithm = digestAlgorithm;

    /* Initialize signature. */
    if ((status = R_SignInit
         (&frame->signatureContext, digestAlgorithm)) != 0) {
      errorMessage = FormatRSAError (status);
      break;
    }
  } while (0);
  
  return (errorMessage);
}

/* Before this is called for the first time, the caller should have called
     RIPEMSignDetachedPKCSInit.  This is repeatedly called to digest the
     data to sign.
   The data to digest is in partIn with length partInLen.
   The input is "as is": no translation of '\n' to <CR><LF> is
     done because this message format can support binary data.  The
     calling routine must do end-of-line character translation if necessary.
   After this, call RIPEMSignDetachedPKCSFinal to finalize.  (There is
     no RIPEMSignDetachedPKCSUpdate function since RIPEMSignDetachedPKCSFinal
     produces the entire output.)
   Return NULL for success or error string.
 */
char *RIPEMSignDetachedPKCSDigestUpdate (ripemInfo, partIn, partInLen)
RIPEMInfo *ripemInfo;
unsigned char *partIn;
unsigned int partInLen;
{
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  int status;

  if (frame == (RIPEMEncipherPKCSFrame *)NULL)
    return ("Sign detached not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor)
    return ("Signing frame was not initialized by RIPEMSignDetachedPKCSInit");

  if ((status = R_SignUpdate
       (&frame->signatureContext, partIn, partInLen)) != 0)
    return (FormatRSAError (status));

  return ((char *)NULL);
}

/* Call this after all text has been digested
     RIPEMSignDetachedPKCSDigestUpdate. This writes the entire PKCS detached
     signature data.
   This returns a pointer to the output in partOut and its length in
     partOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   The output is "as is": no translation of '\n' to <CR><LF> is
     done because this message format can support binary data.
   authenticatedAttributes is for future compatibility.  You should pass
     (RIPEMAttributes *)NULL.
   Return NULL for success or error string.
 */
char *RIPEMSignDetachedPKCSFinal
  (ripemInfo, partOut, partOutLen, authenticatedAttributes)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
RIPEMAttributes *authenticatedAttributes;
{
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  char *errorMessage;

UNUSED_ARG (authenticatedAttributes)

  if (frame == (RIPEMEncipherPKCSFrame *)NULL)
    return ("Encipher not initialized");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor)
    return ("Encipher frame was not initialized by RIPEMSignDetachedPKCSInit");

  /* Get stream for quick access. */
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  /* Write the PKCS #7 ContentInfo to the output stream.
   */
  if ((errorMessage = BufferStreamWrite
       (CONTENT_INFO_START, sizeof (CONTENT_INFO_START), stream))
      != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (CONTENT_TYPE_SIGNED_DATA, sizeof (CONTENT_TYPE_SIGNED_DATA),
        stream)) != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (DATA_VERSION, sizeof (DATA_VERSION), stream)) != (char *)NULL)
    return (errorMessage);

  /* Must explicitly put the version byte. */
  /* SignedData and SigneAndEnvelopedData have version 1 */
  if ((errorMessage = BufferStreamPutc (1, stream)) != (char *)NULL)
    return (errorMessage);

  if (frame->digestAlgorithm == DA_SHA1) {
    if ((errorMessage = BufferStreamWrite
	 (DIGEST_ALGORITHMS_SHA1_START,
	  sizeof (DIGEST_ALGORITHMS_SHA1_START), stream)) != (char *)NULL)
      return (errorMessage);
    if ((errorMessage = BufferStreamWrite
	 (ALG_ID_SHA1, sizeof (ALG_ID_SHA1), stream)) != (char *)NULL)
      return (errorMessage);
  }
  else {
    /* MD2 or MD5 */
    if ((errorMessage = BufferStreamWrite
	 (DIGEST_ALGORITHMS_START, sizeof (DIGEST_ALGORITHMS_START), stream))
	!= (char *)NULL)
      return (errorMessage);
    if (frame->digestAlgorithm == DA_MD2) {
      if ((errorMessage = BufferStreamWrite
	   (ALG_ID_MD2, sizeof (ALG_ID_MD2), stream)) != (char *)NULL)
        return (errorMessage);
    }
    else if (frame->digestAlgorithm == DA_MD5) {
      if ((errorMessage = BufferStreamWrite
	   (ALG_ID_MD5, sizeof (ALG_ID_MD5), stream)) != (char *)NULL)
        return (errorMessage);
    }
    else
      return ("Unsupported digest algorithm");
  }

  if ((errorMessage = BufferStreamWrite
       (CONTENT_INFO_DATA_START, sizeof (CONTENT_INFO_DATA_START), stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamWrite
       (CONTENT_TYPE_DATA, sizeof (CONTENT_TYPE_DATA), stream))
      != (char *)NULL)
    return (errorMessage);

  /* Omit the content for detached signature. */

  /* Close out the ContentInfo. */
  if ((errorMessage = BufferStreamWrite
       (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
      != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = WriteCertsAndSigner (ripemInfo)) != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (END_DATA_EXPLICIT_AND_CONTENT_INFO,
        sizeof (END_DATA_EXPLICIT_AND_CONTENT_INFO), stream))
      != (char *)NULL)
    return (errorMessage);

  /* Set the output.  Include the offset that may have been set
       while encoding the last octet string of the data content. */
  *partOut = stream->buffer;
  *partOutLen = stream->point;
  
  return ((char *)NULL);
}

/* Initialize ripemInfo for verifying a PKCS detached signature using
     the given digest algorithm.
   The digestAlgorithm is used by RIPEMVerifyDetachedDigestUpdate to digest
     the message and is also compared with the digest algorithm specified in
     the detached signature information.  digestAlgorithm should be one of
     DA_MD2, DA_MD5 or DA_SHA1.
   After this, call RIPEMVerifyDetachedPKCSDigestUpdate to digest the message
     text by parts, call RIPEMVerifyDetachedPKCSUpdate to supply the PKCS
     detached signature by parts and call RIPEMVerifyDetachedPKCSFinal to
     finish and obtain the sender information.
   Return NULL for success or error string.
 */
char *RIPEMVerifyDetachedPKCSInit (ripemInfo, digestAlgorithm)
RIPEMInfo *ripemInfo;
int digestAlgorithm;
{
  RIPEMDecipherPKCSFrame *frame;
  char *errorMessage;
  int status;

  if ((errorMessage = RIPEMDecipherPKCSInit (ripemInfo)) != (char *)NULL)
    return (errorMessage);

  /* RIPEMDecipherPKCSInit has created the frame. */
  frame = (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;
  frame->detached = 1;
  frame->expectedDigestAlgorithm = digestAlgorithm;

  if ((status = R_VerifyInit
       (&frame->signatureContext, digestAlgorithm)) != 0)
    return (FormatRSAError (status));

  return ((char *)NULL);
}

/* Call this after the verify operation has been initialized with
     RIPEMVerifyDetachedPKCSInit.
   This digests the message data in partIn of length partInLen.
     partIn may contain any number of bytes.  This may
     be called multiple times.
   The input is "as is": no translation of '\n' to <CR><LF> is
     done because this message format can support binary data.  The
     calling routine must do end-of-line character translation if necessary.
   After calling this to digest the message, call RIPEMVerifyDetachedPKCSUpdate
     to supply the detached signature and RIPEMVerifyDetachedPKCSFinal to
     finalize.
   Return NULL for success or error string.
 */
char *RIPEMVerifyDetachedPKCSDigestUpdate (ripemInfo, partIn, partInLen)
RIPEMInfo *ripemInfo;
unsigned char *partIn;
unsigned int partInLen;
{
  RIPEMDecipherPKCSFrame *frame =
    (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;
  int status;
  
  if (frame == (RIPEMDecipherPKCSFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPKCSFrameDestructor)
   return("Decipher frame was not initialized by RIPEMVerifyDetachedPKCSInit");

  if ((status = R_VerifyUpdate
       (&frame->signatureContext, partIn, partInLen)) != 0)
    return (FormatRSAError (status));

  return ((char *)NULL);
}

/* Call this after the verify operation has been initialized with
     RIPEMVerifyDetachedPKCSInit and the message has been digested with
     RIPEMVerifyDetachedPKCSDigestUpdate.
   This decodes the PKCS detached signature information in partIn of length
     partInLen.  partIn may contain any number of bytes.  This may
     be called multiple times.
   The input is "as is": no translation of '\n' to <CR><LF> is
     done because this message format can support binary data.
   After calling this to supply the detached signature, call
     RIPEMVerifyDetachedPKCSFinal to finalize.
   Return NULL for success or error string.
 */
char *RIPEMVerifyDetachedPKCSUpdate
  (ripemInfo, partIn, partInLen, ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char *partIn;
unsigned int partInLen;
RIPEMDatabase *ripemDatabase;
{
  RIPEMDecipherPKCSFrame *frame =
    (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;
  unsigned char *dummyPartOut;
  unsigned int dummyPartOutLen;

  if (frame == (RIPEMDecipherPKCSFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPKCSFrameDestructor)
   return("Decipher frame was not initialized by RIPEMVerifyDetachedPKCSInit");

  /* There is no output for a detached signature.
     Assume RIPEMVerifyDetachedInit has already set frame->detached. */
  return (RIPEMDecipherPKCSUpdate
          (ripemInfo, &dummyPartOut, &dummyPartOutLen, partIn, partInLen,
           ripemDatabase));
}

/* Call this after the entire detached signature has been supplied to
     RIPEMVerifyDetachedPKCSUpdate.
   See RIPEMDecipherPKCSFinal for the meaning of certChain, chainStatus
     and authenticatedAttributes.  The PKCS mode is not returned because
     it can only be PKCS_SIGNED.
   Return NULL for success or error string.
 */
char *RIPEMVerifyDetachedPKCSFinal
  (ripemInfo, certChain, chainStatus, authenticatedAttributes)
RIPEMInfo *ripemInfo;
TypList *certChain;
ChainStatusInfo *chainStatus;
RIPEMAttributes *authenticatedAttributes;
{
  RIPEMDecipherPKCSFrame *frame =
    (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;
  int dummyPKCSMode;

  if (frame == (RIPEMDecipherPKCSFrame *)NULL)
    return ("Decipher not initialized");
  if (frame->ripemDecipherFrame.Destructor != 
      (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPKCSFrameDestructor)
   return("Decipher frame was not initialized by RIPEMVerifyDetachedPKCSInit");

  /* PKCS mode can only be PKCS_SIGNED */
  return (RIPEMDecipherPKCSFinal
          (ripemInfo, certChain, chainStatus, &dummyPKCSMode,
           authenticatedAttributes));
}

/* Preset all "have attributes" to FALSE.
 */
void InitRIPEMAttributes (attributes)
RIPEMAttributes *attributes;
{
  R_memset ((POINTER)attributes, 0, sizeof (*attributes));
}

/* Produce a PKCS #10 certification request for the user in ripemInfo.
   If attributes->haveChallengePassword is TRUE, then
     attributes->challengePassowrd is a null-terminated string to use as
     the challenge password.  If attributes->haveUnstructuredName is TRUE, then
     attributes->unstructuredName is a null-terminated string to use as
     the unstructured name.  The caller is responsible for allocating the
     memory that attributes->challengePassoword or ->unstructuredName points
     to.  Other attributes in the RIPEMAttributes are ignored.
   attributes may be (RIPEMAttributes *)NULL, in which case no attributes
     are used.
   This returns a pointer to the output in output and its length in
     outputLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
 */
char *RIPEMCertifyRequestPKCS (ripemInfo, output, outputLen, attributes)
RIPEMInfo *ripemInfo;
unsigned char **output;
unsigned int *outputLen;
RIPEMAttributes *attributes;
{
  RIPEMEncipherPKCSFrame *frame;
  BufferStream *stream;
  char *errorMessage;
  unsigned char signature[MAX_SIGNATURE_LEN], buffer[MAX_TAG_AND_LEN_BYTES],
    *p;
  unsigned int signatureLen;
  
  /* Make sure any old frame is deleted and make a new one.  Use
       the encipher frame.
   */
  if (ripemInfo->z.encipherFrame != (RIPEMEncipherFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.encipherFrame->Destructor) (ripemInfo->z.encipherFrame);
    free (ripemInfo->z.encipherFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEMEncipherPKCSFrame */
  if ((ripemInfo->z.encipherFrame = (RIPEMEncipherFrame *)malloc
       (sizeof (*frame))) == (RIPEMEncipherFrame *)NULL)
    return (ERR_MALLOC);
  RIPEMEncipherPKCSFrameConstructor
    ((RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame);

  /* Get stream for quick access. */
  frame = (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  /* Reserve space for the tag and length of the outer encoding. */
  if ((errorMessage = BufferStreamWrite
       ((unsigned char *)NULL, MAX_TAG_AND_LEN_BYTES, stream))
      != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = WriteCertifyRequestInfo
       (stream, &ripemInfo->userDN, &ripemInfo->publicKey, attributes))
      != (char *)NULL)
    return (errorMessage);

  /* Now sign it.  The encoding is offset by MAX_TAG_AND_LEN_BYTES */
  R_SignBlock
    (signature, &signatureLen, stream->buffer + MAX_TAG_AND_LEN_BYTES,
     stream->point - MAX_TAG_AND_LEN_BYTES, DA_MD5, &ripemInfo->privateKey);

  /* We can now encode the algorithm ID and the signature as bit string,
       which includes the unused bits octet.
   */
  if ((errorMessage = BufferStreamWrite
       (ALG_ID_MD5_WITH_RSA_ENCRYPTION,
        sizeof (ALG_ID_MD5_WITH_RSA_ENCRYPTION), stream)) != (char *)NULL)
    return (errorMessage);
  p = buffer;
  *p++ = BER_BIT_STRING;
  put_der_len (&p, signatureLen + 1);
  if ((errorMessage = BufferStreamWrite (buffer, p - buffer, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamPutc (0, stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamWrite (signature, signatureLen, stream))
      != (char *)NULL)
    return (errorMessage);

  /* Now we can insert the tag and length octets for the entire encoding.
   */
  p = buffer;
  *p++ = BER_SEQUENCE;
  put_der_len (&p, stream->point - MAX_TAG_AND_LEN_BYTES);

  /* This is where the final result will be. */
  *output = stream->buffer + MAX_TAG_AND_LEN_BYTES - (p - buffer);
  R_memcpy ((POINTER)*output, buffer, p - buffer);
  *outputLen = stream->point - ((*output) - stream->buffer);

  return ((char *)NULL);
}

/* Initializes a certs-and-crls-only message for outputting the CRL and
     certificates for the user in ripemInfo.
   This returns a pointer to the output in partOut and its length in
     PartOutLen.  The memory for the output is allocated inside ripemInfo
     and should be treated as "read only".  Upon return, the output must be
     copied or written to a file since future calls to RIPEM may modify it. On
     error return, the pointer to the output is undefined.
   After this, call RIPEMCertsAndCRL_PKCSUpdate to include extra certs in the
     output, and call RIPEMCertsAndCRL_PKCSFinal to output the CRL and finish.
   Returns NULL for success, otherwise error string.
 */
char *RIPEMCertsAndCRL_PKCSInit (ripemInfo, partOut, partOutLen)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
{
  RIPEMEncipherPKCSFrame *frame;
  BufferStream *stream;
  char *errorMessage;

  /* Make sure any old frame is deleted and make a new one.  Use
       the encipher frame.
   */
  if (ripemInfo->z.encipherFrame != (RIPEMEncipherFrame *)NULL) {
    /* Be sure to call the "virtual" destructor */
    (*ripemInfo->z.encipherFrame->Destructor) (ripemInfo->z.encipherFrame);
    free (ripemInfo->z.encipherFrame);
  }
  /* Be sure to malloc for the size of an entire RIPEMEncipherPKCSFrame */
  if ((ripemInfo->z.encipherFrame = (RIPEMEncipherFrame *)malloc
       (sizeof (*frame))) == (RIPEMEncipherFrame *)NULL)
    return (ERR_MALLOC);
  RIPEMEncipherPKCSFrameConstructor
    ((RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame);

  /* Get stream for quick access. */
  frame = (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  /* Write the PKCS #7 ContentInfo to the output stream.
   */
  if ((errorMessage = BufferStreamWrite
       (CONTENT_INFO_START, sizeof (CONTENT_INFO_START), stream))
      != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (CONTENT_TYPE_SIGNED_DATA, sizeof (CONTENT_TYPE_SIGNED_DATA),
        stream)) != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (DATA_VERSION, sizeof (DATA_VERSION), stream)) != (char *)NULL)
    return (errorMessage);
  /* Must explicitly put the version byte. */
  if ((errorMessage = BufferStreamPutc (1, stream)) != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (EMPTY_DIGEST_ALGORITHMS, sizeof (EMPTY_DIGEST_ALGORITHMS), stream))
      != (char *)NULL)
    return (errorMessage);

  if ((errorMessage = BufferStreamWrite
       (CONTENT_INFO_DATA_START, sizeof (CONTENT_INFO_DATA_START), stream))
      != (char *)NULL)
    return (errorMessage);
  if ((errorMessage = BufferStreamWrite
       (CONTENT_TYPE_DATA, sizeof (CONTENT_TYPE_DATA), stream))
      != (char *)NULL)
    return (errorMessage);
  /* Omit the content for certs-and-crls-only message. */
  if ((errorMessage = BufferStreamWrite
       (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
      != (char *)NULL)
    return (errorMessage);

  /* Get ready to output certificates.
   */
  if ((errorMessage = BufferStreamWrite
       (CERTIFICATES_SET, sizeof (CERTIFICATES_SET), stream))
      != (char *)NULL)
    return (errorMessage);

  /* Set the output. */
  *partOut = frame->outStream.buffer;
  *partOutLen = frame->outStream.point;

  return ((char *)NULL);
}

/* Call this after RIPEMCertsAndCRL_PKCSInit.  This may be called zero or more
     times to add extra certificates to the certs-and-crls-only message.  This
     is a way to export certificates for other user's to import into their
     database.  Note that this can be called an arbitrarily large number of
     times (especially using the RIPEMDatabaseCursor) without overrunning
     memory.
   See RIPEMCertsAndCRL_PKCSInit for a description of partOut and partOutLen.
   Return NULL for success or error string.
 */
char *RIPEMCertsAndCRL_PKCSUpdate (ripemInfo, partOut, partOutLen, certs)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
TypList *certs;
{
  TypListEntry *entry;
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  char *errorMessage;
  
  if (frame == (RIPEMEncipherPKCSFrame *)NULL)
    return ("Not initialized by RIPEMCertsAndCRL_PKCSInit");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor)
    return ("Encoding frame was not initialized by RIPEMCertsAndCRL_PKCSInit");

  /* Get stream for quick access. */
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  for (entry = certs->firstptr; entry; entry = entry->nextptr) {
    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)entry->dataptr, entry->datalen, stream))
        != (char *)NULL)
      return (errorMessage);  
  }

  /* Set the output. */
  *partOut = stream->buffer;
  *partOutLen = stream->point;

  return ((char *)NULL);
}

/* Call this after RIPEMCertsAndCRL_PKCSInit and zero or more calls to
     RIPEMCertsAndCRL_PKCSUpdate.
   If includeSenderCerts is true, this includes the self-
     signed certificate and issuer certificates for the logged-in user.
     If includeCRL is TRUE, this also adds the CRL for
     the user in ripemInfo by getting it from ripemDatabase.
     (If neither includeSenderCerts or includeCRL is true, the only use
      of this message is if certs were added with RIPEMCertsAndCRL_PKCSUpdate.)
   If adding the CRL, this returns an error if the CRL cannot be found or the
     signature is corrupt.  Otherwise, if the CRL is expired, it is still used.
   See RIPEMCertsAndCRL_PKCSInit for a description of partOut and partOutLen.
   Return NULL for success or error string.
 */
char *RIPEMCertsAndCRL_PKCSFinal
  (ripemInfo, partOut, partOutLen, includeSenderCerts, includeCRL,
   ripemDatabase)
RIPEMInfo *ripemInfo;
unsigned char **partOut;
unsigned int *partOutLen;
BOOL includeSenderCerts;
BOOL includeCRL;
RIPEMDatabase *ripemDatabase;
{
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  char *errorMessage = (char *)NULL;
  unsigned char *crlDER = (unsigned char *)NULL;
  int crlLen;
  TypListEntry *entry;

  if (frame == (RIPEMEncipherPKCSFrame *)NULL)
    return ("Not initialized by RIPEMCertsAndCRL_PKCSInit");
  if (frame->ripemEncipherFrame.Destructor != 
      (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor)
    return ("Encoding frame was not initialized by RIPEMCertsAndCRL_PKCSInit");

  /* Get stream for quick access. */
  stream = &frame->outStream;

  /* Get ready to write to the output. */
  BufferStreamRewind (stream);

  /* For error, break to end of do while (0) block. */
  do {
    if (includeSenderCerts) {
      /* Output the self-signed certificate and issuer certs. */
      if ((errorMessage = BufferStreamWrite
           (ripemInfo->z.userCertDER, ripemInfo->z.userCertDERLen, stream))
          != (char *)NULL)
        break;
      for (entry = ripemInfo->issuerCerts.firstptr; entry;
           entry = entry->nextptr) {
        if ((errorMessage = BufferStreamWrite
             ((unsigned char *)entry->dataptr, entry->datalen, stream))
            != (char *)NULL)
          break;
      }
    }

    /* End the certificates set. */
    if ((errorMessage = BufferStreamWrite
         (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
        != (char *)NULL)
      break;

    if (includeCRL) {
      /* Output a set containing the user's CRL.
       */      
      if ((errorMessage = GetLoggedInLatestCRL
           (&crlDER, &crlLen, ripemInfo, ripemDatabase)) != (char *)NULL)
        break;

      if ((errorMessage = BufferStreamWrite
           (CRLS_SET, sizeof (CRLS_SET), stream)) != (char *)NULL)
        break;
      if ((errorMessage = BufferStreamWrite (crlDER, crlLen, stream))
          != (char *)NULL)
        break;
      if ((errorMessage = BufferStreamWrite
           (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
          != (char *)NULL)
        break;
    }

    /* Output an empty set of set of signerInfos.
     */
    if ((errorMessage = BufferStreamWrite
         (SIGNER_INFOS_START, sizeof (SIGNER_INFOS_START), stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamWrite
         (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
        != (char *)NULL)
      break;

    if ((errorMessage = BufferStreamWrite
         (END_DATA_EXPLICIT_AND_CONTENT_INFO,
          sizeof (END_DATA_EXPLICIT_AND_CONTENT_INFO), stream))
        != (char *)NULL)
      break;

    /* Set the output. */
    *partOut = stream->buffer;
    *partOutLen = stream->point;
  } while (0);
  
  free (crlDER);
  return (errorMessage);
}

void RIPEMEncipherPKCSFrameConstructor (frame)
RIPEMEncipherPKCSFrame *frame;
{
  /* Must set the pointer to the virtual destructor */
  frame->ripemEncipherFrame.Destructor =
    (RIPEM_ENCIPHER_FRAME_DESTRUCTOR)RIPEMEncipherPKCSFrameDestructor;

  BufferStreamConstructor (&frame->outStream);
  InitList (&frame->issuerNames);
}

void RIPEMEncipherPKCSFrameDestructor (frame)
RIPEMEncipherPKCSFrame *frame;
{
  BufferStreamDestructor (&frame->outStream);
  R_memset ((POINTER)&frame->sealContext, 0, sizeof (frame->sealContext));
  R_memset
    ((POINTER)&frame->signatureContext, 0, sizeof (frame->signatureContext));
}

void RIPEMDecipherPKCSFrameConstructor (frame)
RIPEMDecipherPKCSFrame *frame;
{
  /* Must set the pointer to the virtual destructor */
  frame->ripemDecipherFrame.Destructor =
    (RIPEM_DECIPHER_FRAME_DESTRUCTOR)RIPEMDecipherPKCSFrameDestructor;
  BufferStreamConstructor (&frame->outStream);
  BufferStreamConstructor (&frame->input);
  InitList (&frame->certs);
  InitList (&frame->certChain);
  InitDistinguishedNameStruct (&frame->issuerName);
  InitList (&frame->attributesBuffers);
  frame->checkEndConstructed = -1;
  frame->flushedInput = 0;

  /* Default to not detached */
  frame->detached = 0;
}

void RIPEMDecipherPKCSFrameDestructor (frame)
RIPEMDecipherPKCSFrame *frame;
{
  BufferStreamDestructor (&frame->outStream);
  BufferStreamDestructor (&frame->input);
  R_memset
    ((POINTER)&frame->envelopeContext, 0, sizeof (frame->envelopeContext));
  R_memset
    ((POINTER)&frame->signatureContext, 0, sizeof (frame->signatureContext));
  FreeList (&frame->certs);
  FreeList (&frame->certChain);
  R_memset ((POINTER)&frame->signature, 0, sizeof (frame->signature));
  FreeList (&frame->attributesBuffers);
}

/* Write a SignerInfo to stream with the given info.  serialNumber does
     not need to have the leading zeros removed.
   Returns NULL, otherwise error string.
 */
static char *WriteSignerInfo
  (stream, signature, signatureLen, issuerName, issuerNameLen,
   serialNumber, serialNumberLen, digestAlgorithm)
BufferStream *stream;
unsigned char *signature;
unsigned int signatureLen;
unsigned char *issuerName;
unsigned int issuerNameLen;
unsigned char *serialNumber;
unsigned int serialNumberLen;
int digestAlgorithm;
{
  char *errorMessage;
  unsigned int issuerSerialContentLen, totalContentLen, savePoint;
  unsigned char *p;

  /* We have to pre-compute the content length of the entire SignerInfo.
       start by getting the content length of the IssuerAndSerialNumber,
       which we will use again. */
  issuerSerialContentLen =
    issuerNameLen +
    der_len (len_large_unsigned (serialNumber, serialNumberLen));
  totalContentLen =
    der_len (1) +   /* version */
    der_len (issuerSerialContentLen) +  /* issuerAndSerialNumber */
    /* digest algorithm (MD2 and MD5 are the same size) */
    (digestAlgorithm == DA_SHA1 ? sizeof (ALG_ID_SHA1) : sizeof (ALG_ID_MD5)) +
    sizeof (ALG_ID_RSA_ENCRYPTION) +  /* digestEncryptionAlgorithm */
    der_len (signatureLen);    

  /* Save where the buffer stream will write next and reserve enough
       bytes to write the SignerInfo */
  savePoint = stream->point;
  if ((errorMessage = BufferStreamWrite
       ((unsigned char *)NULL, der_len (totalContentLen), stream))
      != (char *)NULL)
    return (errorMessage);
  /* Assign p after BufferStreamWrite since stream->buffer may move. */
  p = stream->buffer + savePoint;

  /* Start the SEQUENCE */
  *p++ = BER_SEQUENCE;
  put_der_len (&p, totalContentLen);

  /* Put the version */
  *p++ = BER_INTEGER;
  put_der_len (&p, 1);
  *p++ = 1;

  /* Put the issuerAndSerialNumber */
  *p++ = BER_SEQUENCE;
  put_der_len (&p, issuerSerialContentLen);
  put_der_data (&p, issuerName, issuerNameLen);
  put_der_large_unsigned
    (&p, serialNumber, serialNumberLen,
     len_large_unsigned (serialNumber, serialNumberLen));

  if (digestAlgorithm == DA_MD2)
    put_der_data (&p, ALG_ID_MD2, sizeof (ALG_ID_MD2));
  else if (digestAlgorithm == DA_MD5)
    put_der_data (&p, ALG_ID_MD5, sizeof (ALG_ID_MD5));
  else if (digestAlgorithm == DA_SHA1)
    put_der_data (&p, ALG_ID_SHA1, sizeof (ALG_ID_SHA1));
  else
    return ("Unsupported digest algorithm");
  put_der_data (&p, ALG_ID_RSA_ENCRYPTION, sizeof (ALG_ID_RSA_ENCRYPTION));

  /* Put the signature */
  *p++ = BER_OCTET_STRING;
  put_der_len (&p, signatureLen);
  put_der_data (&p, signature, signatureLen);

  return ((char *)NULL);
}

/* Write a CertificationRequestInfo to stream with the given info.  Use
     only challengePassword and/or unstructuredName from attributes.
     attributes my be NULL.
   Returns NULL, otherwise error string.
 */
static char *WriteCertifyRequestInfo
  (stream, subjectName, publicKey, attributes)
BufferStream *stream;
DistinguishedNameStruct *subjectName;
R_RSA_PUBLIC_KEY *publicKey;
RIPEMAttributes *attributes;
{
  char *errorMessage;
  unsigned int attributesContentLen, totalContentLen, publicKeyLen,
    valueLen, i, savePoint;
  unsigned char *p, *attribute1Start, *attribute2Start;

  /* We have to pre-compute the content length of the entire encoding.
       Start by getting the content length of the attributes,
       which we will use again.  If zero, then there are no attributes */
  attributesContentLen = 0;
  if (attributes != (RIPEMAttributes *)NULL) {
    if (attributes->haveChallengePassword) {
      valueLen = strlen (attributes->challengePassword);
      attributesContentLen +=
        der_len                   /* sequence for the challenge password */
        (sizeof (CHALLENGE_PASSWORD_ID) +
         der_len                /* set containing one value */
         (der_len (valueLen)));
    }

    if (attributes->haveUnstructuredName) {
      valueLen = strlen (attributes->unstructuredName);
      attributesContentLen +=
        der_len                   /* sequence for the unstructured name */
        (sizeof (UNSTRUCTURED_NAME_ID) +
         der_len                /* set containing one value */
         (der_len (valueLen)));
    }
  }

  totalContentLen =
    der_len (1) +                                    /* version */
    der_len (len_distinguishedname (subjectName)) +  /* subjectName */
    PubKeyToDERLen (publicKey) +                     /* publicKey */
    (attributesContentLen == 0 ? 0 : der_len (attributesContentLen));

  /* Save where the buffer stream will write next and reserve enough
       bytes to write the CertificationRequestInfo */
  savePoint = stream->point;
  if ((errorMessage = BufferStreamWrite
       ((unsigned char *)NULL, der_len (totalContentLen), stream))
      != (char *)NULL)
    return (errorMessage);
  /* Assign p after BufferStreamWrite since stream->buffer may move. */
  p = stream->buffer + savePoint;

  /* Start the SEQUENCE */
  *p++ = BER_SEQUENCE;
  put_der_len (&p, totalContentLen);

  /* Put the version 0 */
  *p++ = BER_INTEGER;
  put_der_len (&p, 1);
  *p++ = 0;

  /* Put the subjectName */
  DistinguishedNameToDER (subjectName, &p);

  /* Put the public key */
  PubKeyToDER (publicKey, p, &publicKeyLen);
  p += publicKeyLen;

  if (attributesContentLen > 0) {
    /* Use [0] IMPLICIT. */
    *p++ = BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0;
    put_der_len (&p, attributesContentLen);

    /* The DER encoding of a SET requires that the elements are ordered.
       So keep track of where each attribute starts before we
         encode it since we will have to compare them.
       We only deal with two attributes here.  If there were more we
         would have to be more general.
     */
    attribute1Start = p;
    /* Encode the first attribute */
    EncodePKCS10Attribute (&p, attributes, 1);

    attribute2Start = p;
    /* Encode the second attribute */
    EncodePKCS10Attribute (&p, attributes, 2);

    if (attribute2Start != attribute1Start && p != attribute2Start) {
      /* There was a first and second attribute, so we must swap them if
           they are not ordered properly.  Since they have different
           object identifiers (at least) assume we can just start comparing
           the strings and that we will find a difference before we hit
           the end */
      i = 0;
      while (1) {
        if (attribute1Start[i] != attribute2Start[i])
          break;
	++i;
      }

      if (attribute1Start[i] > attribute2Start[i]) {
        /* The first encoded attribute is greater, so we must swap to
           make it less.  Encode #2 then #1 starting where #1 used to. */
        p = attribute1Start;
        EncodePKCS10Attribute (&p, attributes, 2);
        EncodePKCS10Attribute (&p, attributes, 1);
      }
    }
  }

  return ((char *)NULL);
}

#ifndef RIPEMSIG
/* Write a RecipientInfo to stream with the given info.  serialNumber does
     not need to have the leading zeros removed.
   Returns NULL, otherwise error string.
 */
static char *WriteRecipientInfo
  (stream, encryptedKey, encryptedKeyLen, issuerName, issuerNameLen,
   serialNumber, serialNumberLen)
BufferStream *stream;
unsigned char *encryptedKey;
unsigned int encryptedKeyLen;
unsigned char *issuerName;
unsigned int issuerNameLen;
unsigned char *serialNumber;
unsigned int serialNumberLen;
{
  char *errorMessage;
  unsigned int issuerSerialContentLen, totalContentLen, savePoint;
  unsigned char *p;

  /* We have to pre-compute the content length of the entire RecipientInfo.
       start by getting the content length of the IssuerAndSerialNumber,
       which we will use again. */
  issuerSerialContentLen =
    issuerNameLen +
    der_len (len_large_unsigned (serialNumber, serialNumberLen));
  totalContentLen =
    der_len (1) +   /* version */
    der_len (issuerSerialContentLen) +  /* issuerAndSerialNumber */
    sizeof (ALG_ID_RSA_ENCRYPTION) +  /* keyEncryptionAlgorithm */
    der_len (encryptedKeyLen);    

  /* Save where the buffer stream will write next and reserve enough
       bytes to write the SignerInfo */
  savePoint = stream->point;
  if ((errorMessage = BufferStreamWrite
       ((unsigned char *)NULL, der_len (totalContentLen), stream))
      != (char *)NULL)
    return (errorMessage);
  /* Assign p after BufferStreamWrite since stream->buffer may move. */
  p = stream->buffer + savePoint;

  /* Start the SEQUENCE */
  *p++ = BER_SEQUENCE;
  put_der_len (&p, totalContentLen);

  /* Put the version */
  *p++ = BER_INTEGER;
  put_der_len (&p, 1);
  *p++ = 0;

  /* Put the issuerAndSerialNumber */
  *p++ = BER_SEQUENCE;
  put_der_len (&p, issuerSerialContentLen);
  put_der_data (&p, issuerName, issuerNameLen);
  put_der_large_unsigned
    (&p, serialNumber, serialNumberLen,
     len_large_unsigned (serialNumber, serialNumberLen));

  put_der_data (&p, ALG_ID_RSA_ENCRYPTION, sizeof (ALG_ID_RSA_ENCRYPTION));

  /* Put the encryptedKey */
  *p++ = BER_OCTET_STRING;
  put_der_len (&p, encryptedKeyLen);
  put_der_data (&p, encryptedKey, encryptedKeyLen);

  return ((char *)NULL);
}

/* Decode the RecipientInfo given by der.
   This requires the version to be 0.
   Decode the issuer name into the supplied DistinguishedNameStruct.
   Returns the serialNumber in the buffer which is MAX_SERIAL_NUMBER_LEN
     in length, padded as described by getlargeunsigned.
   Returns a pointer to the encryptedKey.
   This requires key encryption algorithm to be RSA.
   Returns null for success, otherwise error string.
 */
static char *DecodeRecipientInfo
  (der, issuerName, serialNumber, encryptedKey, encryptedKeyLen)
unsigned char *der;
DistinguishedNameStruct *issuerName;
unsigned char *serialNumber;
unsigned char **encryptedKey;
unsigned int *encryptedKeyLen;
{
  unsigned char *recipientInfoEnd, *issuerSerialEnd;
  UINT2 tag;
  unsigned int contentLen;

  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SEQUENCE)
    return (ERR_PKCS_ENCODING);

  /* Remember where the encoding should end */
  recipientInfoEnd = der + contentLen;

  /* Check that the version is 0. */
  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_INTEGER)
    return (ERR_PKCS_ENCODING);
  if (*der != 0)
    return ("Invalid RecipientInfo version");
  der += 1;

  /* Decode the issuerAndSerialNumber.
   */
  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SEQUENCE)
    return (ERR_PKCS_ENCODING);
  issuerSerialEnd = der + contentLen;
  if (DERToDistinguishedName (&der, issuerName) != 0)
    return ("Invalid issuer name encoding in RecipientInfo");
  if (getlargeunsigned (serialNumber, MAX_SERIAL_NUMBER_LEN, &der) != 0)
    return (ERR_PKCS_ENCODING);
  if (der != issuerSerialEnd)
    return (ERR_PKCS_ENCODING);

  if (R_memcmp
      ((POINTER)der, (POINTER)ALG_ID_RSA_ENCRYPTION,
       sizeof (ALG_ID_RSA_ENCRYPTION)) != 0)
    return ("Unrecognized key encryption algorithm");
  der += sizeof (ALG_ID_RSA_ENCRYPTION);

  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_OCTET_STRING)
    return (ERR_PKCS_ENCODING);
  *encryptedKey = der;
  *encryptedKeyLen = contentLen;
  der += contentLen;

  if (der != recipientInfoEnd)
    return (ERR_PKCS_ENCODING);

  return ((char *)NULL);
}

/* Write the algorithm identifier for encryptionAlgorithm with the IV
     to the stream.
 */
static char *WriteEncryptionAlgorithmID (stream, encryptionAlgorithm, iv)
BufferStream *stream;
int encryptionAlgorithm;
unsigned char *iv;
{
  char *errorMessage;
  unsigned int parameterContentLen, savePoint, totalContentLen;
  int toEncode;
  unsigned char bigEndian[2], *p;

  if (encryptionAlgorithm == EA_DES_CBC) {
    totalContentLen = sizeof (DES_CBC_ID) + der_len (8);

    savePoint = stream->point;
    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)NULL, der_len (totalContentLen), stream))
        != (char *)NULL)
      return (errorMessage);
    /* Assign p after BufferStreamWrite since stream->buffer may move. */
    p = stream->buffer + savePoint;

    *p++ = BER_SEQUENCE;
    put_der_len (&p, totalContentLen);
    /* Write the object ID */
    put_der_data (&p, DES_CBC_ID, sizeof (DES_CBC_ID));

    /* Write the tag, length and contents of the IV octet string */
    *p++ = BER_OCTET_STRING;
    put_der_len (&p, 8);
    put_der_data (&p, iv, 8);
  }
  else if (encryptionAlgorithm == EA_DES_EDE3_CBC) {
    totalContentLen = sizeof (DES_EDE3_CBC_ID) + der_len (8);

    savePoint = stream->point;
    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)NULL, der_len (totalContentLen), stream))
        != (char *)NULL)
      return (errorMessage);
    /* Assign p after BufferStreamWrite since stream->buffer may move. */
    p = stream->buffer + savePoint;

    *p++ = BER_SEQUENCE;
    put_der_len (&p, totalContentLen);
    /* Write the object ID */
    put_der_data (&p, DES_EDE3_CBC_ID, sizeof (DES_EDE3_CBC_ID));

    /* Write the tag, length and contents of the IV octet string */
    *p++ = BER_OCTET_STRING;
    put_der_len (&p, 8);
    put_der_data (&p, iv, 8);
  }
  else if (EA_GET_ALGORITHM (encryptionAlgorithm) == EA_RX2_CBC_TOKEN) {
    /* See RC2_VERSIONS for a description of the wacky RC2 parameter encoding.
       Even though we are using the RX2 algorithm in RSAREF, we use
         the RC2 algorithm identifier since RX2 is supposed to be compatible.
       Here, we figure out the length of the parameter contents */
    if (EA_GET_RX2_EFFECTIVE_BITS (encryptionAlgorithm) == 32)
      /* The parameters is just the IV */
      parameterContentLen = 8;
    else {
      /* Set toEncode to the integer we will encode. */
      if (EA_GET_RX2_EFFECTIVE_BITS (encryptionAlgorithm) < 256)
        toEncode =
          RC2_VERSIONS[EA_GET_RX2_EFFECTIVE_BITS (encryptionAlgorithm)];
      else
        toEncode = EA_GET_RX2_EFFECTIVE_BITS (encryptionAlgorithm);

      /* Now, set up the big endian we will encode as an unsigned integer */
      bigEndian[0] = (toEncode >> 8) & 0xff;
      bigEndian[1] = toEncode & 0xff;

      /* The parameters has this integer plus the 8 byte IV */
      parameterContentLen =
        der_len (len_large_unsigned (bigEndian, sizeof (bigEndian))) +
        der_len (8);
    }

    totalContentLen = sizeof (RC2_CBC_ID) + der_len (parameterContentLen);

    savePoint = stream->point;
    if ((errorMessage = BufferStreamWrite
         ((unsigned char *)NULL, der_len (totalContentLen), stream))
        != (char *)NULL)
      return (errorMessage);
    /* Assign p after BufferStreamWrite since stream->buffer may move. */
    p = stream->buffer + savePoint;

    *p++ = BER_SEQUENCE;
    put_der_len (&p, totalContentLen);
    /* Write the object ID */
    put_der_data (&p, RC2_CBC_ID, sizeof (RC2_CBC_ID));

    if (EA_GET_RX2_EFFECTIVE_BITS (encryptionAlgorithm) != 32) {
      /* We have to write the sequence bytes and the integer before the IV. */

      *p++ = BER_SEQUENCE;
      put_der_len (&p, parameterContentLen);
      put_der_large_unsigned
        (&p, bigEndian, sizeof (bigEndian),
         len_large_unsigned (bigEndian, sizeof (bigEndian)));
    }

    /* Write the tag, length and contents of the IV octet string */
    *p++ = BER_OCTET_STRING;
    put_der_len (&p, 8);
    put_der_data (&p, iv, 8);
  }
  else
    return ("Unsupported encryption algorithm");

  return ((char *)NULL);
}

/* Decode the encryption algorithm ID given by der, returning the
     encryptionAlgorithm token (such as EA_DES_CBC) and a pointer within
     der to the IV.
 */
static char *DecodeEncryptionAlgorithmID (der, encryptionAlgorithm, iv)
unsigned char *der;
int *encryptionAlgorithm;
unsigned char **iv;
{
  UINT2 tag;
  unsigned int contentLen, decodedInteger, effectiveBits;
  unsigned char *derEnd, bigEndian[2];

  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SEQUENCE)
    return (ERR_PKCS_ENCODING);
  derEnd = der + contentLen;
  
  if (DERCheckData (&der, (POINTER)DES_CBC_ID, sizeof (DES_CBC_ID))
      == 0) {
    *encryptionAlgorithm = EA_DES_CBC;

    if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_OCTET_STRING)
      return (ERR_PKCS_ENCODING);

    *iv = der;
    der += contentLen;
  }
  else if (DERCheckData
           (&der, (POINTER)DES_EDE3_CBC_ID, sizeof (DES_EDE3_CBC_ID)) == 0) {
    *encryptionAlgorithm = EA_DES_EDE3_CBC;

    if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_OCTET_STRING)
      return (ERR_PKCS_ENCODING);

    *iv = der;
    der += contentLen;
  }
  else if (DERCheckData
           (&der, (POINTER)RC2_CBC_ID, sizeof (RC2_CBC_ID)) == 0) {
    /* Even though we are using the RX2 algorithm in RSAREF, we use
        the RC2 algorithm identifier since RX2 is supposed to be compatible. */
    if (gettaglen (&tag, &contentLen, &der) < 0)
      return (ERR_PKCS_ENCODING);

    if (tag == BER_OCTET_STRING) {
      /* Just an IV means we default to 32 bits */
      *encryptionAlgorithm = EA_RX2_CBC (32);
      *iv = der;
      der += contentLen;
    }
    else if (tag == BER_SEQUENCE) {
      /* Decode the integer */
      if (getlargeunsigned (bigEndian, sizeof (bigEndian), &der) < 0)
        return (ERR_PKCS_ENCODING);
      decodedInteger = (((int)bigEndian[0]) << 8) + (int)bigEndian[1];

      if (decodedInteger < 256) {
        /* We must look up the effective bits in the version table */
        for (effectiveBits = 0; effectiveBits < 256; ++effectiveBits) {
          if (RC2_VERSIONS[effectiveBits] == decodedInteger)
            break;
        }
        /* note that all numbers from 0 to 255 are in the table, so
             we must have found it */
        *encryptionAlgorithm = EA_RX2_CBC (effectiveBits);
      }
      else
        *encryptionAlgorithm = EA_RX2_CBC (decodedInteger);

      /* Now decode the IV */
      if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_OCTET_STRING)
        return (ERR_PKCS_ENCODING);
      *iv = der;
      der += contentLen;
    }
    else
      return (ERR_PKCS_ENCODING);
  }
  else
    return ("Unrecognized encryption algorithm");

  if (der != derEnd)
    return (ERR_PKCS_ENCODING);

  return ((char *)NULL);
}

#endif

/* Decode the SignerInfo given by der.
   This requires the version to be 1.
   Decode the issuer name into the supplied DistinguishedNameStruct.
   Returns the serialNumber in the buffer which is MAX_SERIAL_NUMBER_LEN
     in length, padded as described by getlargeunsigned.
   Returns a pointer to the signature.
   This checks der's digest algorithm against the supplied value.
   This requires digest encryption algorithm to be RSA.
   attributes and attributesBuffers are for
     DecodeAuthenticatedAttributes.  If there are authenticated attributes,
     this uses signatureContext to finalize the digesting of the content
     and reinitializes it to verify the attributes.  In this case,
     when the caller uses R_VerifyFinal, it will check the signature of
     the attributes.  Also, this makes sure the contentType in the attributes
     is Data.
   This skips over unauthenticated attributes if found.
   Returns null for success, otherwise error string.
 */
static char *DecodeSignerInfo
  (der, issuerName, serialNumber, digestAlgorithm, signatureContext,
   signature, signatureLen, attributes, attributesBuffers)
unsigned char *der;
DistinguishedNameStruct *issuerName;
unsigned char *serialNumber;
int digestAlgorithm;
R_SIGNATURE_CTX *signatureContext;
unsigned char **signature;
unsigned int *signatureLen;
RIPEMAttributes *attributes;
TypList *attributesBuffers;
{
  unsigned char *signerInfoEnd, *issuerSerialEnd, *attributesDER;
  UINT2 tag;
  unsigned int contentLen, attributesDERLen;
  char *errorMessage;

  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SEQUENCE)
    return (ERR_PKCS_ENCODING);

  /* Remember where the encoding should end */
  signerInfoEnd = der + contentLen;

  /* Check that the version is 1. */
  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_INTEGER)
    return (ERR_PKCS_ENCODING);
  if (*der != 1)
    return ("Invalid SignerInfo version");
  der += 1;

  /* Decode the issuerAndSerialNumber.
   */
  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SEQUENCE)
    return (ERR_PKCS_ENCODING);
  issuerSerialEnd = der + contentLen;
  if (DERToDistinguishedName (&der, issuerName) != 0)
    return ("Invalid issuer name encoding in SignerInfo");
  if (getlargeunsigned (serialNumber, MAX_SERIAL_NUMBER_LEN, &der) != 0)
    return (ERR_PKCS_ENCODING);
  if (der != issuerSerialEnd)
    return (ERR_PKCS_ENCODING);

  if (digestAlgorithm == DA_MD2) {
    if (DERCheckData (&der, ALG_ID_MD2, sizeof (ALG_ID_MD2)) < 0)
      return ("Digest algorithm in SignerInfo doesn't match SignedData value");
  }
  else if (digestAlgorithm == DA_MD5) {
    if (DERCheckData (&der, ALG_ID_MD5, sizeof (ALG_ID_MD5)) < 0)
      return ("Digest algorithm in SignerInfo doesn't match SignedData value");
  }
  else if (digestAlgorithm == DA_SHA1) {
    if (DERCheckData (&der, ALG_ID_SHA1, sizeof (ALG_ID_SHA1)) < 0)
      return ("Digest algorithm in SignerInfo doesn't match SignedData value");
  }
  else
    /* This shouldn't happen since we set the digestAlgorithm ourselves */
    return ("Internal: bad digestAlgorithm in DecodeSignerInfo");

  if (*der == (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0)) {
    /* There are authenticated attributes. */
    attributesDER = der;
    if (gettaglen (&tag, &contentLen, &der) < 0)
      return (ERR_PKCS_ENCODING);
    attributesDERLen = (der - attributesDER) + contentLen;
    
    if ((errorMessage = ProcessAuthenticatedAttributes
         (attributesDER, attributesDERLen, digestAlgorithm, signatureContext,
          attributes, attributesBuffers)) != 0)
      return (errorMessage);

    der += contentLen;
  }

  if (DERCheckData
      (&der, ALG_ID_RSA_ENCRYPTION, sizeof (ALG_ID_RSA_ENCRYPTION)) < 0)
    return ("Unrecognized digest encryption algorithm");

  if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_OCTET_STRING)
    return (ERR_PKCS_ENCODING);
  *signature = der;
  *signatureLen = contentLen;
  der += contentLen;

  if (der < signerInfoEnd) {
    /* Assume this is an unauthenticated attributes, which we want to skip.
     */
    if (gettaglen (&tag, &contentLen, &der) < 0 ||
        tag != (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 1))
      return (ERR_PKCS_ENCODING);
    der += contentLen;
  }

  if (der != signerInfoEnd)
    return (ERR_PKCS_ENCODING);

  return ((char *)NULL);
}

/* Process the attributesDER of length attributesDERLen as described in
     DecodeSignerInfo.
   Note that this may return a bad signature error if the digests don't match.
 */
static char *ProcessAuthenticatedAttributes
  (attributesDER, attributesDERLen, digestAlgorithm, signatureContext,
   attributes, attributesBuffers)
unsigned char *attributesDER;
unsigned int attributesDERLen;
int digestAlgorithm;
R_SIGNATURE_CTX *signatureContext;
RIPEMAttributes *attributes;
TypList *attributesBuffers;
{
  char *errorMessage = (char *)NULL;
  unsigned char digestInAttributes[MAX_DIGEST_LEN],
    digestOfContent[MAX_DIGEST_LEN], setTag = BER_SET;
  unsigned int digestLen;
    
  /* For error, break to end of do while (0) block. */
  do {
    if ((errorMessage = DecodeAuthenticatedAttributes
         (attributesDER, digestInAttributes, attributes, attributesBuffers))
        != (char *)NULL)
      break;

    /* Now get the digest and check it.  We must go inside the
         R_SIGNATURE_CTX to get the digest context.
     */
    R_DigestFinal
      (&signatureContext->digestContext, digestOfContent, &digestLen);
    if (R_memcmp ((POINTER)digestOfContent, (POINTER)digestInAttributes,
                  digestLen) != 0) {
      errorMessage = "Signature on message content is incorrect";
      break;
    }

    /* Now restart the signature check on the authenticated attributes.
       The encoding in attributesDER starts with the IMPLICIT [0] tag
         but we are supposed to digest the SET tag of the original
         Attributes type.  (Why do people use IMPLICIT?!?!)
     */
    R_VerifyInit (signatureContext, digestAlgorithm);
    R_VerifyUpdate (signatureContext, &setTag, 1);
    R_VerifyUpdate (signatureContext, attributesDER + 1, attributesDERLen - 1);

    /* We will call R_VerifyFinal later */
  } while (0);

  R_memset ((POINTER)digestInAttributes, 0, sizeof (digestInAttributes));
  R_memset ((POINTER)digestOfContent, 0, sizeof (digestOfContent));
  return (errorMessage);
}

/* Decode the IMPLICIT [0] authenticated attributes given by der.
   This requires there to be a digest and contentType attribute.  The
     supplied digest must be MAX_DIGEST_LEN bytes long, and this makes
     sure the contentType is Data.
   If an attribute is recognized, put it in the supplied attributes
     struct, otherwise ignore it.
   For signing description, use the supplied attributesBuffers to hold the
     value and point attributes->signingDescription to it.
   Assume that attributes->haveSigningTime, etc. have already all been
     set to FALSE.
   Returns null for success, otherwise error string.
 */
static char *DecodeAuthenticatedAttributes
  (der, digest, attributes, attributesBuffers)
unsigned char *der;
unsigned char *digest;
RIPEMAttributes *attributes;
TypList *attributesBuffers;
{
  unsigned char *attributesEnd, *attributeEnd, *valueSetEnd,
    *attributeType, *buffer;
  UINT2 tag;
  unsigned int contentLen;
  BOOL haveDigest, haveContentType;
  char *errorMessage;

  haveDigest = FALSE;
  haveContentType = FALSE;
  
  if (gettaglen (&tag, &contentLen, &der) < 0 ||
      tag != (BER_CONSTRUCTED | BER_CONTEXT_SPECIFIC | 0))
    return (ERR_PKCS_ENCODING);

  /* Remember where the encoding should end */
  attributesEnd = der + contentLen;

  while (der < attributesEnd) {
    if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SEQUENCE)
      return (ERR_PKCS_ENCODING);

    /* Remember where the encoding should end */
    attributeEnd = der + contentLen;

    attributeType = (unsigned char *)NULL;
    if (DERCheckData (&der, SIGNING_TIME_ID, sizeof (SIGNING_TIME_ID)) >= 0) 
      attributeType = SIGNING_TIME_ID;
    else if (DERCheckData
             (&der, SIGNING_DESCRIPTION_ID, sizeof (SIGNING_DESCRIPTION_ID))
             >= 0) 
      attributeType = SIGNING_DESCRIPTION_ID;
    else if (DERCheckData (&der, CONTENT_TYPE_ID, sizeof (CONTENT_TYPE_ID))
             >= 0) 
      attributeType = CONTENT_TYPE_ID;
    else if (DERCheckData (&der, MESSAGE_DIGEST_ID, sizeof (MESSAGE_DIGEST_ID))
             >= 0) 
      attributeType = MESSAGE_DIGEST_ID;

    if (attributeType == (unsigned char *)NULL) {
      /* Unrecognized identifier, so just skip the object ID and value set.
       */
      if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_OBJECT_ID)
        return (ERR_PKCS_ENCODING);
      der += contentLen;
      
      if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SET)
        return (ERR_PKCS_ENCODING);
      der += contentLen;
    }
    else {
      /* Decode the value set.
       */
      if (gettaglen (&tag, &contentLen, &der) < 0 || tag != BER_SET)
        return (ERR_PKCS_ENCODING);

      valueSetEnd = der + contentLen;
      while (der < valueSetEnd) {
        if (attributeType == SIGNING_TIME_ID) {
          if (DERToUTC (&der, &attributes->signingTime) < 0)
            return ("Invalid encoding for signing time");

          attributes->haveSigningTime = TRUE;
        }
        else if (attributeType == SIGNING_DESCRIPTION_ID) {
          if (gettaglen (&tag, &contentLen, &der) < 0)
            return (ERR_PKCS_ENCODING);

          /* Use the attributesBuffers to hold the value, including null
               terminator.
           */
          if ((buffer = (unsigned char *)malloc (contentLen + 1)) ==
              (unsigned char *)NULL)
            return (ERR_MALLOC);
          R_memcpy ((POINTER)buffer, (POINTER)der, contentLen);
          buffer[contentLen] = '\0';
          if ((errorMessage = AddToList
               ((TypListEntry *)NULL, buffer, contentLen + 1,
                attributesBuffers)) != (char *)NULL) {
            /* error, so free the buffer */
            free (buffer);
            return (errorMessage);
          }

          der += contentLen;

          attributes->signingDescription = (char *)buffer;
          attributes->haveSigningDescription = TRUE;
        }
        else if (attributeType == CONTENT_TYPE_ID) {
          if (DERCheckData
              (&der, CONTENT_TYPE_DATA, sizeof (CONTENT_TYPE_DATA)) != 0)
            return ("Content type in authenticated attributes is not Data");

          haveContentType = TRUE;
        }
        else if (attributeType == MESSAGE_DIGEST_ID) {
          if (gettaglen (&tag, &contentLen, &der) < 0 ||
              tag != BER_OCTET_STRING || contentLen > MAX_DIGEST_LEN)
            return ("Invalid encoding of message digest attribute");

          R_memcpy ((POINTER)digest, (POINTER)der, contentLen);
          der += contentLen;
          haveDigest = TRUE;
        }
        else
          /* This shouldn't happen since we set attributeType ourselves */
          return
          ("Internal: bad attributeType in DecodeAuthenticatedAttributes");
        
        /* The "else if's" should have handled all cases */
      }

      if (der != valueSetEnd)
        return (ERR_PKCS_ENCODING);
    }

    if (der != attributeEnd)
      return (ERR_PKCS_ENCODING);
  }

  if (der != attributesEnd)
    return (ERR_PKCS_ENCODING);

  if (!haveDigest)
    return ("Message digest is missing from authenticated attributes");
  if (!haveContentType)
    return ("Content type is missing from authenticated attributes");

  return ((char *)NULL);
}

/* Return PKCS_SIGNED if input is the SignedData identifier, etc.  Else
      return 0 if there is no match.
   All identifiers are of length sizeof (CONTENT_TYPE_SIGNED_DATA).
 */
static int DecodeContentType (input)
unsigned char *input;
{
  if (R_memcmp
      ((POINTER)input, (POINTER)CONTENT_TYPE_SIGNED_DATA,
       sizeof (CONTENT_TYPE_SIGNED_DATA)) == 0)
    return (PKCS_SIGNED);
  else if (R_memcmp
           ((POINTER)input, (POINTER)CONTENT_TYPE_ENVELOPED_DATA,
            sizeof (CONTENT_TYPE_ENVELOPED_DATA)) == 0)
    return (PKCS_ENVELOPED);
  else if (R_memcmp
           ((POINTER)input, (POINTER)CONTENT_TYPE_SIGNED_ENVELOPED_DATA,
            sizeof (CONTENT_TYPE_SIGNED_ENVELOPED_DATA)) == 0)
    return (PKCS_SIGNED|PKCS_ENVELOPED);
  else
    return (0);
}

/* Use the information now in frame to match the signer's issuer/serial to a
     certificate, select a certificate chain, and copy the signer's public
     key to publicKey.
   This sets the frame's certChain and chainStatus.
   If chainStatus.overall is 0, this found a self-signed cert and
     put it in the first entry of certChain.  In this case, publicKey
     is undefined.  (The caller should check chainStatus.overall)
   This returns an error if a valid public key can't be found or if
     there is no self-signed cert.
   Return NULL for success, otherwise error string.
 */
static char *GetSignerPublicKey (frame, ripemInfo, publicKey, ripemDatabase)
RIPEMDecipherPKCSFrame *frame;
RIPEMInfo *ripemInfo;
R_RSA_PUBLIC_KEY *publicKey;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage = (char *)NULL;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  TypListEntry *entry;
  BOOL isSelfSigned;
  void *certCopy;
  int certLen;

  /* For error, break to end of do while (0) block. */
  do {
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* Search through all the certs in the message looking for a match
         with the issuer name/serial number that was in the SignerInfo. */
    for (entry = frame->certs.firstptr;
         entry != (TypListEntry *)NULL;
         entry = entry->nextptr) {
      if ((certLen = DERToCertificate
           ((unsigned char *)entry->dataptr, certStruct, &fieldPointers)) < 0)
        /* Can't decode, so just skip and try the next one. */
        continue;

      if (R_memcmp
          ((POINTER)&frame->issuerName, (POINTER)&certStruct->issuer,
           sizeof (certStruct->issuer)) != 0 ||
          R_memcmp
          ((POINTER)&frame->serialNumber, (POINTER)&certStruct->serialNumber,
           sizeof (certStruct->serialNumber)) != 0)
        /* issuer/serial doesn't match */
        continue;

      /* Try to get the sender's cert chain.  We set directCertOnly
           FALSE to allow any chain. */
      if ((errorMessage = SelectCertChain
           (ripemInfo, &frame->certChain, &frame->chainStatus,
            &certStruct->subject, &certStruct->publicKey, FALSE,
            ripemDatabase)) != (char *)NULL)
        break;

      if (frame->chainStatus.overall == 0) {
        /* Couldn't find a chain, so try to process a self-signed cert.
         */
        CheckSelfSignedCert
          (&isSelfSigned, certStruct, fieldPointers.innerDER,
           fieldPointers.innerDERLen);

        if (isSelfSigned) {
          /* Copy the self-signed cert to the cert chain.
             The certChain should be empty now.
             Note that chainStatus.overall is still 0.
           */
          if ((certCopy = malloc (certLen)) == NULL) {
            errorMessage = ERR_MALLOC;
            break;
          }
          R_memcpy ((POINTER)certCopy, (POINTER)entry->dataptr, certLen);
          if ((errorMessage = PrependToList
               (certCopy, certLen, &frame->certChain)) != (char *)NULL) {
            /* Free the cert copy we just allocated */
            free (certCopy);
            break;
          }

          /* We have copied the self-signed cert, so break. */
          break;
        }
        else {
          /* Try to find a self-signed cert based on the given subject name
               and public key.  This will return an error if not found.
               In either case, we're done. */
          errorMessage = FindMatchingSelfSignedCert
            (ripemInfo, &certStruct->subject, &certStruct->publicKey);
          break;
        }
      }

      /* Found the public key so break and return */
      *publicKey = certStruct->publicKey;
      break;
    }
    if (errorMessage != (char *)NULL)
      /* Broke loop because of error */
      break;

    if (entry == (TypListEntry *)NULL) {
      /* Finished loop without finding the issuer/serial in the certs which
           came in the message.
         At this point we could look in the database, but the current
           database implementation is not keyed by issuer/serial.  (We
           would have to get and decode every certificate to examine the
           issuer/serial.  If really needed, we could add this routine.) */

      errorMessage =
    "Cannot find a certificate in the message with the sender's issuer/serial";
      break;
    }

    /* Assume we broke the loop because we got the public key */
  } while (0);

  free (certStruct);
  return (errorMessage);
}

/* This is a helper function to find a self-signed certificate in the
     message matching the subject name and public key of the certificate
     which matches the SignerInfo's issuerNameAndSerialNumber.
   If found, the frame's certChain has the self-signed cert.
   If not found, returns "Cannot find certificate chain for sender."
 */
static char *FindMatchingSelfSignedCert (ripemInfo, subjectName, publicKey)
RIPEMInfo *ripemInfo;
DistinguishedNameStruct *subjectName;
R_RSA_PUBLIC_KEY *publicKey;
{
  RIPEMDecipherPKCSFrame *frame =
    (RIPEMDecipherPKCSFrame *)ripemInfo->z.decipherFrame;
  char *errorMessage = (char *)NULL;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  TypListEntry *entry;
  BOOL isSelfSigned;
  void *certCopy;
  int certLen;

  /* For error, break to end of do while (0) block. */
  do {
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }

    /* Search through all the certs in the message looking for a match
         with the subject name and public key. */
    for (entry = frame->certs.firstptr;
         entry != (TypListEntry *)NULL;
         entry = entry->nextptr) {
      if ((certLen = DERToCertificate
           ((unsigned char *)entry->dataptr, certStruct, &fieldPointers)) < 0)
        /* Can't decode, so just skip and try the next one. */
        continue;

      if (R_memcmp
          ((POINTER)subjectName, (POINTER)&certStruct->subject,
           sizeof (certStruct->subject)) != 0 ||
          R_memcmp
          ((POINTER)publicKey, (POINTER)&certStruct->publicKey,
           sizeof (certStruct->publicKey)) != 0)
        /* subject name/public key doesn't match */
        continue;

      CheckSelfSignedCert
        (&isSelfSigned, certStruct, fieldPointers.innerDER,
         fieldPointers.innerDERLen);

      if (isSelfSigned) {
        /* Copy the self-signed cert to the cert chain.
           The certChain should be empty now.
           Note that chainStatus.overall is still 0.
         */
        if ((certCopy = malloc (certLen)) == NULL) {
          errorMessage = ERR_MALLOC;
          break;
        }
        R_memcpy ((POINTER)certCopy, (POINTER)entry->dataptr, certLen);
        if ((errorMessage = PrependToList
             (certCopy, certLen, &frame->certChain)) != (char *)NULL) {
          /* Free the cert copy we just allocated */
          free (certCopy);
          break;
        }

        /* We have copied the self-signed cert, so break. */
        break;
      }
    }
    if (errorMessage != (char *)NULL)
      /* Broke loop because of error */
      break;

    if (entry == (TypListEntry *)NULL) {
      /* Finished loop without a match */
      errorMessage = "Cannot find certificate chain for sender.";
      break;
    }
  } while (0);

  free (certStruct);
  return (errorMessage);
}

/* Encode tag and length octets for the content that has been accumulating
     in the stream.
 */
static void GetEncipherUpdateOutput (partOut, partOutLen, stream)
unsigned char **partOut;
unsigned int *partOutLen;
BufferStream *stream;
{
  unsigned char *p;

  /* We must write the tag and length bytes.  der_len returns the length
       of these plus the actual data, so set *partOutLen to this. Note
       that the content follows the space we allocated for tag and length
       octets. */
  *partOutLen = der_len (stream->point - MAX_TAG_AND_LEN_BYTES);
  /* Point p to where we should put the tag. */
  p = (stream->buffer + stream->point) - *partOutLen;
  /* This is also the result. */
  *partOut = p;

  /* Write the tag and length octets. */
  *p++ = BER_OCTET_STRING;
  put_der_len (&p, stream->point - MAX_TAG_AND_LEN_BYTES);
}

/* This helper routine is used by RIPEMEncipherPKCSFinal (if PKCS_SIGNED) and
     RIPEMSignDetachedPKCSFinal.
   Assume the ripemInfo has a valid RIPEMEncipherPKCSFrame.
   Finalize the signatureContext.  Encrypt the signature if PKCS_ENVELOPED.
   Write the certificate set and the set of one signerInfo to the frame's
     outStream.
   This does not write an END_DATA_EXPLICIT_AND_CONTENT_INFO (the calling
     routine must do this.)
   (If later versions handle authenticated attributes, this can be added
     to this routine.)
   Return NULL for success or error string.
 */
static char *WriteCertsAndSigner (ripemInfo)
RIPEMInfo *ripemInfo;
{
  RIPEMEncipherPKCSFrame *frame =
    (RIPEMEncipherPKCSFrame *)ripemInfo->z.encipherFrame;
  BufferStream *stream;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  TypListEntry *entry;
  char *errorMessage = (char *)NULL;
  int status;
  unsigned char signature[MAX_PEM_ENCRYPTED_SIGNATURE_LEN],
    *nameDER = (unsigned char *)NULL, *derPointer;
  unsigned int signatureLen, localPartOutLen;

  /* For error, break to end of do while (0) block. */
  do {
    /* Get stream for quick access. */
    stream = &frame->outStream;

    /* Output originator and issuer certificates.
     */
    if ((errorMessage = BufferStreamWrite
         (CERTIFICATES_SET, sizeof (CERTIFICATES_SET), stream))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamWrite
         (ripemInfo->z.userCertDER, ripemInfo->z.userCertDERLen, stream))
        != (char *)NULL)
      break;
    for (entry = ripemInfo->issuerCerts.firstptr; entry;
         entry = entry->nextptr) {
      if ((errorMessage = BufferStreamWrite
           ((unsigned char *)entry->dataptr, entry->datalen, stream))
          != (char *)NULL)
        break;
    }
    if ((errorMessage = BufferStreamWrite
         (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
        != (char *)NULL)
      break;

    /* Finalize the signature and encrypt it if enveloping.
     */
    if ((status = R_SignFinal
         (&frame->signatureContext, signature, &signatureLen,
          &ripemInfo->privateKey)) != 0) {
      errorMessage = FormatRSAError (status);
      break;
    }

#ifndef RIPEMSIG
    if (frame->pkcsMode & PKCS_ENVELOPED) {
      /* Encrypt the signature in place.
       */
      if ((status = R_SealUpdate
           (&frame->sealContext, signature, &signatureLen, signature,
            signatureLen)) != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
      if ((status = R_SealFinal
           (&frame->sealContext, signature + signatureLen, &localPartOutLen))
          != 0) {
        errorMessage = FormatRSAError (status);
        break;
      }
      signatureLen += localPartOutLen;
    }
#endif

    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    /* Find the issuer/serial for the sender.  If there is a certificate
         in the issuer cert chains, use that since it is more likely
         to make hierarchy-based implementations happy.  (When RIPEM
         receives this, it will only use it to find the sender's name and
         public key anyway just as it would with a self-signed cert.)
         Otherwise, if there is no issuer cert, use the self-signed cert.
       DERToCertificate will not return an error.
     */
    if (ripemInfo->z.issuerChainCount == 0)
      DERToCertificate
        (ripemInfo->z.userCertDER, certStruct, (CertFieldPointers *)NULL);
    else
      DERToCertificate
        ((unsigned char *)ripemInfo->issuerCerts.firstptr->dataptr,
         certStruct, (CertFieldPointers *)NULL);

    /* Allocate buffer and convert issuer name to DER.
     */
    if ((nameDER = (unsigned char *)malloc
         (len_distinguishedname (&certStruct->issuer) + 4))
        == (unsigned char *)NULL) {
      errorMessage = ERR_MALLOC;
      break;
    }
    derPointer = nameDER;
    DistinguishedNameToDER (&certStruct->issuer, &derPointer);

    /* Output the SignerInfos with one SignerInfo in it.
     */
    if ((errorMessage = BufferStreamWrite
         (SIGNER_INFOS_START, sizeof (SIGNER_INFOS_START), stream))
        != (char *)NULL)
      break;
    if ((errorMessage = WriteSignerInfo
         (stream, signature, signatureLen, nameDER, derPointer - nameDER,
          certStruct->serialNumber, sizeof (certStruct->serialNumber),
          frame->digestAlgorithm))
        != (char *)NULL)
      break;
    if ((errorMessage = BufferStreamWrite
         (END_INDEFINITE_LEN, sizeof (END_INDEFINITE_LEN), stream))
        != (char *)NULL)
      break;
  } while (0);
  
  R_memset ((POINTER)signature, 0, sizeof (signature));
  free (certStruct);
  free (nameDER);
  return (errorMessage);
}

/* This is a helper for WriteCertifyRequestInfo.  The attributeNumber is from 1
     up to the number of attributes allowed in a PKCS #10 request
     (for example, 1 for challenge password and 2 for unstructure name).
     If the attribute used used (such as attributes->haveChallengePassword
     is TRUE) then encode the attribute, starting at *p and advancing the
     pointer.  If the attribute is not used, don't advance the pointer.
 */
static void EncodePKCS10Attribute (p, attributes, attributeNumber)
unsigned char **p;
RIPEMAttributes *attributes;
unsigned int attributeNumber;
{
  unsigned int valueLen;

  switch (attributeNumber) {
  case 1:
    /* Challenge password */
    if (!attributes->haveChallengePassword)
      return;
    
    valueLen = strlen (attributes->challengePassword);
    *(*p)++ = BER_SEQUENCE;
    put_der_len
      (p, sizeof (CHALLENGE_PASSWORD_ID) +
           der_len                /* set containing one value */
           (der_len (valueLen)));
    put_der_data (p, CHALLENGE_PASSWORD_ID, sizeof (CHALLENGE_PASSWORD_ID));
    *(*p)++ = BER_SET;
    put_der_len (p, der_len (valueLen));
    /* Finally put the challenge password, choosing between
         printable string and T.61 string */
    *(*p)++ = IsPrintableString
      ((unsigned char *)attributes->challengePassword, valueLen) ?
      ATTRTAG_PRINTABLE_STRING : ATTRTAG_T61_STRING;
    put_der_len (p, valueLen);
    put_der_data
      (p, (unsigned char *)attributes->challengePassword, valueLen);
    break;

  case 2:
    /* Unstructured name */
    if (!attributes->haveUnstructuredName)
      return;
    
    valueLen = strlen (attributes->unstructuredName);
    *(*p)++ = BER_SEQUENCE;
    put_der_len
      (p, sizeof (UNSTRUCTURED_NAME_ID) +
           der_len                /* set containing one value */
           (der_len (valueLen)));
    put_der_data (p, UNSTRUCTURED_NAME_ID, sizeof (UNSTRUCTURED_NAME_ID));
    *(*p)++ = BER_SET;
    put_der_len (p, der_len (valueLen));
    /* Finally put the unstructured name */
    *(*p)++ = ATTRTAG_IA5_STRING;
    put_der_len (p, valueLen);
    put_der_data
      (p, (unsigned char *)attributes->unstructuredName, valueLen);
    break;
  }
}
