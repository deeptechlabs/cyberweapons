/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- ripem.h -------------------------------------------------------*/

/* Use conditional compile so header file is only included once */
#ifndef _RIPEM_H_
#define _RIPEM_H_ 1

/* If this is included by a C++ file, keep declarations in C. */
#ifdef __cplusplus
extern "C" {
#endif

/* Definitions for our "list" data structure.
 */
typedef struct struct_list {
  struct struct_list_entry *firstptr;
  struct struct_list_entry *lastptr;
} TypList;

typedef struct struct_list_entry {
  struct struct_list_entry *nextptr;                /* Address of next entry */
  struct struct_list_entry *prevptr;            /* Address of previous entry */
  void *dataptr;                                   /* Pointer to actual data */
  unsigned int datalen;             /* Number of bytes of data in this entry */
} TypListEntry;

#define FORLIST(mylistptr) \
  { TypListEntry *entry_ptr; \
    void *dptr;  \
    for(entry_ptr=(mylistptr)->firstptr; entry_ptr; \
        entry_ptr=entry_ptr->nextptr) {  \
      dptr = entry_ptr->dataptr; 

#define ENDFORLIST } }

/* Boolean type and values.
 */
#define BOOL int
#define TRUE 1
#define FALSE 0

#ifndef MSDOS
#if defined(__MSDOS__) || defined(_MSDOS)
#define MSDOS
#endif
#endif

#ifdef __TURBOC__
#define __STDC__ 1
/* This gets rid of warnings on forward declarations of structs. */
#pragma warn -stu
#endif


#define INC_RECIP_ALLOC     16

#define MAX_PASSWORD_SIZE  256

#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE   8
#define SALT_SIZE      8

#define SERVER_PORT 1611

#define TRUE 1
#define FALSE 0

#ifndef MACTC /* rwo */

#define PUBLIC_KEY_FILE_ENV     "RIPEM_PUBLIC_KEY_FILE"
#define PRIVATE_KEY_FILE_ENV      "RIPEM_PRIVATE_KEY_FILE"
#define USER_NAME_ENV             "RIPEM_USER_NAME"
#define KEY_TO_PRIVATE_KEY_ENV    "RIPEM_KEY_TO_PRIVATE_KEY"
#define RANDOM_FILE_ENV       "RIPEM_RANDOM_FILE"
#define SERVER_NAME_ENV       "RIPEM_SERVER_NAME"
#define RIPEM_ARGS_ENV        "RIPEM_ARGS"
#define HOME_DIR_ENV        "RIPEM_HOME_DIR"

#else

/* The idea is to have these correspond to "STR " resources */

#define PUBLIC_KEY_FILE_ENV       0x5231
#define PRIVATE_KEY_FILE_ENV      0x5232
#define USER_NAME_ENV             0x5233
#define KEY_TO_PRIVATE_KEY_ENV    0x5234
#define RANDOM_FILE_ENV       0x5235
#define SERVER_NAME_ENV       0x5236
#define RIPEM_ARGS_ENV        0x5237
#define HOME_DIR_ENV        0x5238

#endif

#define SERVER_PORT         1611
#define USER_NAME_DEFAULT    "me"

#define MD5_LEN 16

/* Modes for PEM format */
enum enhance_mode {MODE_ENCRYPTED, MODE_MIC_ONLY, MODE_MIC_CLEAR, MODE_CRL};

/* Modes for PKCS format */
#define PKCS_SIGNED 1
#define PKCS_ENVELOPED 2
#define PKCS_CERTS_AND_CRLS_ONLY 4

#define MESSAGE_FORMAT_RIPEM1 1
#define MESSAGE_FORMAT_PEM 2

typedef enum enum_key_source {KEY_FROM_NONE, KEY_FROM_FILE, KEY_FROM_SERVER,
  KEY_FROM_FINGER} TypKeyOrigin;

#define MAX_KEY_SOURCES 3

#define MAX_CERT_CHAIN_LEN 6

/* Certification status.
 */
#define CERT_VALID 1
#define CERT_REVOCATION_UNKNOWN 2
#define CERT_PENDING 3
#define CERT_EXPIRED 4
#define CERT_CRL_EXPIRED 5
#define CERT_UNVALIDATED 6
#define CERT_CRL_OUT_OF_SEQUENCE 7
#define CERT_REVOKED 8

/* The implementation of DNs here is rather inefficient as it uses fixed
     length RDNs. */
#define MAX_NAME_LENGTH 64
#define MAX_RDN 20
#define MAX_AVA 20

#define ATTRTAG_PRINTABLE_STRING 0x13
#define ATTRTAG_T61_STRING 0x14
#define ATTRTAG_IA5_STRING 0x16

#define X520_ATTRIBUTE 0
#define PKCS9_ATTRIBUTE 0x100
#define ATTRTYPE_COMMONNAME (X520_ATTRIBUTE | 3)
#define ATTRTYPE_STREETADDRESS (X520_ATTRIBUTE | 9)
#define ATTRTYPE_ORGANIZATIONALUNITNAME (X520_ATTRIBUTE | 11)
#define ATTRTYPE_ORGANIZATIONNAME (X520_ATTRIBUTE | 10)
#define ATTRTYPE_LOCALITYNAME (X520_ATTRIBUTE | 7)
#define ATTRTYPE_STATEPROVINCENAME (X520_ATTRIBUTE | 8)
#define ATTRTYPE_COUNTRYNAME (X520_ATTRIBUTE | 6)
#define ATTRTYPE_TITLE (X520_ATTRIBUTE | 12)
#define ATTRTYPE_POSTALCODE (X520_ATTRIBUTE | 17)
#define ATTRTYPE_PHONENUMBER (X520_ATTRIBUTE | 20)
#define ATTRTYPE_EMAILADDRESS (PKCS9_ATTRIBUTE | 1)

typedef struct DistinguishedNameStruct {
  /* Most significant AVAs and RDN are listed first. */
  short AVATypes[MAX_AVA];                                 /* -1 means none. */
  int AVATag[MAX_AVA];                     /* ATTRTAG_PRINTABLE_STRING, etc. */
  char AVAValues[MAX_AVA][MAX_NAME_LENGTH + 1];                 /* C strings */
  short RDNIndexStart[MAX_RDN];              /* index into AVAs for ea. RDN. */
  short RDNIndexEnd[MAX_RDN];                              /* -1 means none. */
} DistinguishedNameStruct;

typedef struct {
  BOOL haveSigningTime;
  unsigned long signingTime;
  BOOL haveSigningDescription;    
  char *signingDescription;                                      /* C string */
  BOOL haveChallengePassword;    
  char *challengePassword;                                       /* C string */
  BOOL haveUnstructuredName;    
  char *unstructuredName;                                        /* C string */
} RIPEMAttributes;

#define MAX_SERIAL_NUMBER_LEN MAX_DIGEST_LEN

typedef struct CertificateStruct {
  unsigned int version;
  unsigned char serialNumber[MAX_SERIAL_NUMBER_LEN];      /* up to 128 bits. */
  int digestAlgorithm;
  DistinguishedNameStruct issuer;
  unsigned long notBefore;                             /* seconds since 1970 */
  unsigned long notAfter;                              /* seconds since 1970 */
  DistinguishedNameStruct subject;
  R_RSA_PUBLIC_KEY publicKey;
  unsigned char signature[MAX_SIGNATURE_LEN];
  int signatureLen;
} CertificateStruct;

typedef struct {
  unsigned char *innerDER;
  unsigned int innerDERLen;
} CertFieldPointers;

typedef struct {
  int overall;      /* Overall chain status = "worst" of individual statuses */
  int individual[MAX_CERT_CHAIN_LEN];            /* Individual cert statuses */
} ChainStatusInfo;

typedef struct struct_server {
  char *servername;
  int  serverport;
} TypServer;  

typedef struct struct_file {
  FILE *stream;
  char *filename;
} TypFile;

typedef struct struct_pubkeysource {
  TypList filelist;
  TypList serverlist;
  TypKeyOrigin origin[MAX_KEY_SOURCES];
} TypKeySource;

typedef struct RIPEMDatabase {
  TypKeySource pubKeySource;
  TypKeySource privKeySource;
  TypKeySource crlSource;
  char *preferencesFilename;
} RIPEMDatabase;

typedef struct {
  char *smartName;                                              /* allocated */
  BOOL finished;
  BOOL firstCall;
  unsigned int keySource;
  TypListEntry *fileEntry;
  TypFile *typFile;
} RIPEMDatabaseCursor;

#define LINEBUFSIZE  200

typedef struct {
  unsigned char publicKeyDigest[MD5_LEN];    /* MD5 of the user's public key */
  unsigned int chainLenAllowed;  /* 1 means they may certify one other, etc. */
} ChainLenAllowedInfo;

#include "p.h"

/* OK, I admit it.  I wish I were coding in C++.  The following types
     should be thought of as a base class with a pure virtual destructor */
struct RIPEMDecipherFrame;
typedef void (*RIPEM_DECIPHER_FRAME_DESTRUCTOR)
  P ((struct RIPEMDecipherFrame *));  
typedef struct RIPEMDecipherFrame {
  RIPEM_DECIPHER_FRAME_DESTRUCTOR Destructor;
} RIPEMDecipherFrame;

struct RIPEMEncipherFrame;
typedef void (*RIPEM_ENCIPHER_FRAME_DESTRUCTOR)
  P ((struct RIPEMEncipherFrame *));  
typedef struct RIPEMEncipherFrame {
  RIPEM_ENCIPHER_FRAME_DESTRUCTOR Destructor;
} RIPEMEncipherFrame;

struct RIPEM_CRLsFrame;
typedef void (*RIPEM_CRLS_FRAME_DESTRUCTOR)
  P ((struct RIPEM_CRLsFrame *));  
typedef struct RIPEM_CRLsFrame {
  RIPEM_CRLS_FRAME_DESTRUCTOR Destructor;
} RIPEM_CRLsFrame;

typedef struct RIPEMInfo {
  R_RANDOM_STRUCT randomStruct;                  /* zeroized by "destructor" */
  char errMsgTxt[LINEBUFSIZE];           /* scratch for error return strings */
  R_RSA_PUBLIC_KEY publicKey;
  R_RSA_PRIVATE_KEY privateKey;                  /* zeroized by "destructor" */
  /* We only compute passwordDigest with MD5 */
  unsigned char passwordDigest[MD5_LEN];         /* zeroized by "destructor" */
  DistinguishedNameStruct userDN;
  TypList issuerCerts;                              /* freed by "destructor" */
  FILE *debugStream;                           /* not closed by "destructor" */
  int debug;

  struct {
    int used_pub_key_in_message;
    unsigned char *userCertDER;                     /* freed by "destructor" */
    unsigned int userCertDERLen;
    /* Issuer/serial aliases are set during LoginUser and used for
         looking up the user in issuer/serial based recipient IDs when
         receiving an encrypted message. The alias is actually the MD5
         of the issuer name as a DNStruct with the serial number. */
    unsigned int issuerSerialAliasCount;
    unsigned char *issuerSerialAliases;              /* concatenated aliases */
    unsigned int issuerChainCount; /* # of issuer cert chains in issuerCerts */
    TypList *usernameAliases;      /* May be NULL. Not freed by "destructor" */
    
    /* This next section has the info kept in the RIPEM preferences.
     */
    unsigned int chainLensAllowedCount;      /* elements in chainLensAllowed */
    /* chainLensAllowed is an allocated copy created by SetChainLensAllowed */
    ChainLenAllowedInfo *chainLensAllowed;
    UINT4 currentCRLLastUpdate;                      /* zero if not supplied */

    /* These are used internally to keep track of the state between calls */
    RIPEMEncipherFrame *encipherFrame;
    RIPEMDecipherFrame *decipherFrame;
    RIPEM_CRLsFrame *crlsFrame;
  } z;                                      /* all zeroized by "constructor" */
} RIPEMInfo;

typedef struct {
  R_RSA_PUBLIC_KEY publicKey;
  char *username;
} RecipientKeyInfo;

/* This string contains the RIPEM library version. */
extern char *RIPEM_VERSION;

extern char *ERR_MALLOC;

/* These are possible error returns */
extern char *ERR_SELF_SIGNED_CERT_NOT_FOUND;
extern char *ERR_PREFERENCES_NOT_FOUND;
extern char *ERR_PREFERENCES_CORRUPT;
extern char *ERR_CERT_ALREADY_VALIDATED;
extern char *ERR_NO_PEM_HEADER_BEGIN;

void RIPEMInfoConstructor P ((RIPEMInfo *));
void RIPEMInfoDestructor P ((RIPEMInfo *));
char *RIPEMGenerateKeys
  P ((RIPEMInfo *, unsigned int, unsigned int, int, unsigned char *,
      unsigned int, RIPEMDatabase *));
void InitDistinguishedNameStruct P((DistinguishedNameStruct *));
unsigned int GetDNSmartNameIndex P((DistinguishedNameStruct *));
char *GetDNSmartNameValue P((DistinguishedNameStruct *));
void R_time P ((UINT4 *));
void *R_realloc P ((void *, unsigned int));
char *RIPEMLoginUser
  P ((RIPEMInfo *, char *, RIPEMDatabase *, unsigned char *, unsigned int));
char *RIPEMSavePreferences P((RIPEMInfo *, RIPEMDatabase *));
char *SetChainLenAllowed
  P((RIPEMInfo *, unsigned char *, unsigned int, RIPEMDatabase *));
unsigned int GetChainLenAllowed P((RIPEMInfo *, unsigned char *));
char *WriteSelfSignedCert P((RIPEMInfo *, unsigned int, int, RIPEMDatabase *));
char *RIPEMChangePassword
  P ((RIPEMInfo *, unsigned char *, unsigned int, RIPEMDatabase *));
char *RIPEMEncipherInit
  P ((RIPEMInfo *, enum enhance_mode, int, int, int, RecipientKeyInfo *,
      unsigned int));
char *RIPEMEncipherDigestUpdate
  P ((RIPEMInfo *, unsigned char *, unsigned int));
char *RIPEMEncipherUpdate
  P ((RIPEMInfo *, unsigned char **, unsigned int *, unsigned char *,
      unsigned int, RIPEMDatabase *));
char *RIPEMEncipherFinal
  P ((RIPEMInfo *, unsigned char **, unsigned int *, RIPEMDatabase *));
char *RIPEMDecipherInit P ((RIPEMInfo *, BOOL));
char *RIPEMDecipherUpdate
  P ((RIPEMInfo *, unsigned char **, unsigned int *, unsigned char *,
      unsigned int, RIPEMDatabase *));
char *RIPEMDecipherFinal
  P((RIPEMInfo *, TypList *, ChainStatusInfo *, enum enhance_mode *));
char *RIPEMSignDetachedPKCSInit P((RIPEMInfo *, int));
char *RIPEMSignDetachedPKCSDigestUpdate
  P((RIPEMInfo *, unsigned char *, unsigned int));
char *RIPEMSignDetachedPKCSFinal
  P((RIPEMInfo *, unsigned char **, unsigned int *, RIPEMAttributes *));
char *RIPEMVerifyDetachedPKCSInit P((RIPEMInfo *, int));
char *RIPEMVerifyDetachedPKCSDigestUpdate
  P((RIPEMInfo *, unsigned char *, unsigned int));
char *RIPEMVerifyDetachedPKCSUpdate
  P((RIPEMInfo *, unsigned char *, unsigned int, RIPEMDatabase *));
char *RIPEMVerifyDetachedPKCSFinal
  P((RIPEMInfo *, TypList *, ChainStatusInfo *, RIPEMAttributes *));
char *RIPEMRequestCRLsInit P((RIPEMInfo *, unsigned char **, unsigned int *));
char *RIPEMRequestCRLsUpdate
  P((RIPEMInfo *, unsigned char **, unsigned int *,
     DistinguishedNameStruct *));
char *RIPEMRequestCRLsFinal P((RIPEMInfo *, unsigned char **, unsigned int *));
char *RIPEMEncipherPKCSInit
  P((RIPEMInfo *, unsigned char **, unsigned int *, int, int, int,
     RecipientKeyInfo *, unsigned int, RIPEMDatabase *));
char *RIPEMEncipherPKCSUpdate
  P((RIPEMInfo *, unsigned char **, unsigned int *, unsigned char *,
     unsigned int partInLen));
char *RIPEMEncipherPKCSFinal
  P((RIPEMInfo *, unsigned char **, unsigned int *, RIPEMAttributes *));
char *RIPEMDecipherPKCSInit P((RIPEMInfo *));
char *RIPEMDecipherPKCSUpdate
  P((RIPEMInfo *, unsigned char **, unsigned int *, unsigned char *,
     unsigned int, RIPEMDatabase *));
char *RIPEMDecipherPKCSFinal
  P((RIPEMInfo *, TypList *, ChainStatusInfo *, int *, RIPEMAttributes *));
void InitRIPEMAttributes P((RIPEMAttributes *));
char *RIPEMCertifyRequestPKCS
  P((RIPEMInfo *, unsigned char **, unsigned int *, RIPEMAttributes *));
char *RIPEMCertsAndCRL_PKCSInit
  P((RIPEMInfo *, unsigned char **, unsigned int *));
char *RIPEMCertsAndCRL_PKCSUpdate
  P((RIPEMInfo *, unsigned char **, unsigned int *, TypList *));
char *RIPEMCertsAndCRL_PKCSFinal
  P((RIPEMInfo *, unsigned char **, unsigned int *, BOOL, BOOL,
     RIPEMDatabase *));
char *RIPEMUpdateCRL
  P((RIPEMInfo *, UINT4, unsigned char *, unsigned int, int, RIPEMDatabase *));
char *RIPEMPublishCRL
  P((RIPEMInfo *, unsigned char **, unsigned int *, int, RIPEMDatabase *));
char *RIPEMPublishCRLInit
  P((RIPEMInfo *, unsigned char **, unsigned int *, int, RIPEMDatabase *));
char *RIPEMPublishCRLUpdate
  P((RIPEMInfo *, unsigned char **, unsigned int *, TypList *));
char *RIPEMPublishCRLFinal P((RIPEMInfo *, unsigned char **, unsigned int *));
char *GetUnvalidatedPublicKey
  P ((char *, TypKeySource *, R_RSA_PUBLIC_KEY *, BOOL *, RIPEMInfo *));
int DERToCertificate
  P((unsigned char *, CertificateStruct *, CertFieldPointers *));
char *GetPublicKeyDigest P((unsigned char *, R_RSA_PUBLIC_KEY *));
char *GetCertsBySmartname P((RIPEMDatabase *, TypList *, char *, RIPEMInfo *));
char *SelectCertChain
  P ((RIPEMInfo *, TypList *, ChainStatusInfo *, DistinguishedNameStruct *,
      R_RSA_PUBLIC_KEY *, BOOL, RIPEMDatabase *));
char *CrackLine P((char *, TypList *));
char *CrackRecipients P((char *, TypList *));
char *FormatRSAError P((int));
char *ValidateAndWriteCert
  P((RIPEMInfo *, struct CertificateStruct *, int, RIPEMDatabase *));
int IsPrintableString P((unsigned char *, unsigned int));

/* List managing routines.
 */
void InitList P((TypList *));
char *AddToList P((TypListEntry *, void *, unsigned int, TypList *));
char *AppendLineToList P((char *, TypList *));
void FreeList P((TypList *));
char *PrependToList P((void *, unsigned int, TypList *));

/* Database managing routines.
 */
void RIPEMDatabaseConstructor P((RIPEMDatabase *));
char *AddKeySourceFilename P((TypKeySource *, char *));
char *InitRIPEMDatabase P((RIPEMDatabase *, char *, RIPEMInfo *));
void RIPEMDatabaseDestructor P((RIPEMDatabase *));

void RIPEMDatabaseCursorConstructor P((RIPEMDatabaseCursor *));
void RIPEMDatabaseCursorDestructor P((RIPEMDatabaseCursor *));
char *RIPEMCertCursorInit P((RIPEMDatabaseCursor *, char *, RIPEMDatabase *));
char *RIPEMCertCursorUpdate
  P ((RIPEMDatabaseCursor *, BOOL *, TypList *, RIPEMDatabase *, RIPEMInfo *));

#undef P

#ifdef __cplusplus
}
#endif

#endif
/*--- End of ripem.h ------------------------------------------------*/
