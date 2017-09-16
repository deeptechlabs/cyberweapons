/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/* Defines main for rcerts command line certificate manager.
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

#include "usagepro.h"
#include "getsyspr.h"
#include "parsitpr.h"
#include "getoptpr.h"

typedef struct {
  char *keyToPrivateKey;
  char *homeDir;
  char *debugFilename;
  char *username;
  BOOL usePKCSFormat;
  int digestAlgorithm;
} RCERTSArgs;

typedef struct {
  TypList certChain;                        /* currently selected cert chain */
  ChainStatusInfo chainStatus;
  CertificateStruct *certStruct;     /* loaded with the selected user's cert */
  CertFieldPointers fieldPointers;
  BOOL usePKCSFormat;
  int digestAlgorithm;                         /* for signing certs and CRLs */
} RCERTSState;

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

/* Note: this is normalized so that 12 * SECONDS_IN_MONTH is 365 days. */
#define SECONDS_IN_MONTH \
  ((UINT4)((UINT4)365 * (UINT4)24 * (UINT4)3600) / (UINT4)12)

static void MainExit P((int stat));
static void RCERTSArgsConstructor P((RCERTSArgs *));
static void RCERTSArgsDestructor P((RCERTSArgs *));
static char *CrackCommandLine
  P((int, char **, RIPEMInfo *, RCERTSArgs *, RIPEMDatabase *));
static char *CrackKeyServerInfo P((char *, RIPEMDatabase *));
static unsigned int GetPasswordToPrivateKey
  P((unsigned char *, unsigned int, char *));
static char *DoMenu P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static void GetInputLine P((char *, unsigned int, char *));
static char *SelectUser
  P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *ViewUserDetail P((RCERTSState *, RIPEMInfo *));
static char *RequestCRLs P((RCERTSState *, RIPEMInfo *));
static char *ModifyChainLenAllowed
  P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *RevokeSelectedUser
  P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *IssueDirectCertificate
  P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *RenewSelectedUser
  P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *EnableStandardIssuers
  P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *RenewCRL P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *PublishCRL P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static char *OutputCertifyRequest P((RCERTSState *, RIPEMInfo *));
static char *ExportCerts P((RCERTSState *, RIPEMInfo *, RIPEMDatabase *));
static BOOL FindSubjectPublicKey
  P((TypList *, DistinguishedNameStruct *, R_RSA_PUBLIC_KEY *,
     CertificateStruct *certStruct));
static char *CertStatusString P((int));
static char *EnableIssuer
  P((RIPEMInfo *, DistinguishedNameStruct *, unsigned char *,
     unsigned int, unsigned char *, unsigned int, unsigned int, 
     unsigned int, int, RIPEMDatabase *));

/* This is needed only by getsys.c so set to not initialized and
     RandomStructPointer will be ignored. */
int RandomStructInitialized = 0;
R_RANDOM_STRUCT *RandomStructPointer;        /* ignored when not initialized */

#ifdef __BORLANDC__
extern unsigned _stklen = 20000;  /* Increase stack size for Borland C */
#endif

extern char USAGE_MESSAGE_LINE1[];
extern char *RCERTS_USAGE_MESSAGE[];

/* The following initialized C arrays represent the 
   public key modulus and exponent encoded as byte vectors, most
   significant byte first.
 */

/* Low Assurance CA */
static unsigned char LOW_ASSURANCE_MODULUS[96] = {
  0xb0, 0xb4, 0x0e, 0x9a, 0x3a, 0x46, 0x4e, 0x87, 0x03, 0xff, 0xb8, 0xdb,
  0xca, 0xd8, 0xaf, 0x41, 0xf3, 0xc3, 0xf4, 0x13, 0x1c, 0xf6, 0x57, 0x1e,
  0x39, 0xa5, 0x35, 0x49, 0xb4, 0x20, 0x94, 0xdc, 0x92, 0xf8, 0xee, 0x1e,
  0xa1, 0x03, 0x5f, 0x94, 0x21, 0x2b, 0x75, 0x1a, 0x3b, 0x07, 0x44, 0x5d,
  0xbd, 0xd6, 0xef, 0x4d, 0x7e, 0x23, 0x00, 0xf4, 0x2c, 0xf5, 0x73, 0x47,
  0x90, 0xbc, 0xe8, 0xba, 0x51, 0x7f, 0xa8, 0x19, 0xee, 0xf7, 0x5f, 0x17,
  0x46, 0xdc, 0xe5, 0xff, 0xd1, 0x23, 0xfe, 0x64, 0x2e, 0x68, 0x94, 0xb3,
  0x81, 0xde, 0x5a, 0x40, 0x28, 0x8d, 0xd6, 0xd7, 0x14, 0xaf, 0x84, 0xef
};
static unsigned char LOW_ASSURANCE_EXPONENT[3] = { 0x01, 0x00, 0x01 };

/* Commercial CA */
unsigned char COMMERCIAL_CA_MODULUS[125] = {
  0xa4, 0xfb, 0x81, 0x62, 0x7b, 0xce, 0x10, 0x27, 0xdd, 0xe8, 0xf7, 0xbe,
  0x6c, 0x6e, 0xc6, 0x70, 0x99, 0xdb, 0xb8, 0xd5, 0x05, 0x03, 0x69, 0x28,
  0x82, 0x9c, 0x72, 0x7f, 0x96, 0x3f, 0x8e, 0xec, 0xac, 0x29, 0x92, 0x3f,
  0x8a, 0x14, 0xf8, 0x42, 0x76, 0xbe, 0xbd, 0x5d, 0x03, 0xb9, 0x90, 0xd4,
  0xd0, 0xbc, 0x06, 0xb2, 0x51, 0x33, 0x5f, 0xc4, 0xc2, 0xbf, 0xb6, 0x8b,
  0x8f, 0x99, 0xb6, 0x62, 0x22, 0x60, 0xdd, 0xdb, 0xdf, 0x20, 0x82, 0xb4,
  0xca, 0xa2, 0x2f, 0x2d, 0x50, 0xed, 0x94, 0x32, 0xde, 0xe0, 0x55, 0x8d,
  0xd4, 0x68, 0xe2, 0xe0, 0x4c, 0xd2, 0xcd, 0x05, 0x16, 0x2e, 0x95, 0x66,
  0x5c, 0x61, 0x52, 0x38, 0x1e, 0x51, 0xa8, 0x82, 0xa1, 0xc4, 0xef, 0x25,
  0xe9, 0x0a, 0xe6, 0x8b, 0x2b, 0x8e, 0x31, 0x66, 0xd9, 0xf8, 0xd9, 0xfd,
  0xbd, 0x3b, 0x69, 0xd9, 0xeb
};
unsigned char COMMERCIAL_CA_EXPONENT[3] = { 0x01, 0x00, 0x01 };

/* Verisign Beta Class 1, soon to expire.  NOT the "official" Class 1. */
unsigned char VERISIGN_BETA_CLASS1_MODULUS[128] = {
  0xbd, 0xd7, 0xc4, 0xed, 0x8e, 0xd6, 0xb3, 0x7f, 0x3a, 0xf8, 0x62,
  0x95, 0x22, 0xfd, 0xd6, 0xb5, 0xb5, 0xf2, 0x11, 0x1d, 0x06, 0xdd,
  0xed, 0x64, 0x6e, 0x80, 0xf0, 0x0d, 0x95, 0x5f, 0x53, 0xb5, 0x42,
  0x4b, 0xff, 0x80, 0x56, 0x3e, 0x7d, 0x4a, 0xc5, 0x5c, 0x26, 0xb0,
  0x3a, 0x91, 0x03, 0xd4, 0xe4, 0xfc, 0x00, 0x8d, 0xe7, 0xcf, 0xbc,
  0x2e, 0x8e, 0x05, 0x9b, 0x4d, 0x0b, 0xc1, 0x88, 0x87, 0x11, 0xf6,
  0x98, 0xd6, 0x57, 0x33, 0x15, 0xd3, 0xb9, 0x4e, 0x57, 0xe1, 0xb1,
  0xac, 0x90, 0x75, 0x02, 0x44, 0xf8, 0xfb, 0xa4, 0xb9, 0x38, 0xaa,
  0xc6, 0xce, 0x0a, 0x13, 0x73, 0x47, 0x83, 0xc4, 0x94, 0xfc, 0xde,
  0xa7, 0x64, 0x1a, 0xe6, 0x71, 0xf3, 0x9c, 0xaf, 0xe9, 0x6e, 0x06,
  0x71, 0x46, 0xef, 0x29, 0xd9, 0x48, 0x10, 0x10, 0x22, 0xb6, 0xec,
  0xd8, 0x14, 0x0f, 0x8d, 0x34, 0x7f, 0x27, 
};
unsigned char VERISIGN_BETA_CLASS1_EXPONENT[3] = { 0x01, 0x00, 0x01 };

/* Verisign Class 1 */
unsigned char VERISIGN_CLASS1_MODULUS[128] = {
  0xe5, 0x19, 0xbf, 0x6d, 0xa3, 0x56, 0x61, 0x2d, 0x99, 0x48, 0x71,
  0xf6, 0x67, 0xde, 0xb9, 0x8d, 0xeb, 0xb7, 0x9e, 0x86, 0x80, 0x0a,
  0x91, 0x0e, 0xfa, 0x38, 0x25, 0xaf, 0x46, 0x88, 0x82, 0xe5, 0x73,
  0xa8, 0xa0, 0x9b, 0x24, 0x5d, 0x0d, 0x1f, 0xcc, 0x65, 0x6e, 0x0c,
  0xb0, 0xd0, 0x56, 0x84, 0x18, 0x87, 0x9a, 0x06, 0x9b, 0x10, 0xa1,
  0x73, 0xdf, 0xb4, 0x58, 0x39, 0x6b, 0x6e, 0xc1, 0xf6, 0x15, 0xd5,
  0xa8, 0xa8, 0x3f, 0xaa, 0x12, 0x06, 0x8d, 0x31, 0xac, 0x7f, 0xb0,
  0x34, 0xd7, 0x8f, 0x34, 0x67, 0x88, 0x09, 0xcd, 0x14, 0x11, 0xe2,
  0x4e, 0x45, 0x56, 0x69, 0x1f, 0x78, 0x02, 0x80, 0xda, 0xdc, 0x47,
  0x91, 0x29, 0xbb, 0x36, 0xc9, 0x63, 0x5c, 0xc5, 0xe0, 0xd7, 0x2d,
  0x87, 0x7b, 0xa1, 0xb7, 0x32, 0xb0, 0x7b, 0x30, 0xba, 0x2a, 0x2f,
  0x31, 0xaa, 0xee, 0xa3, 0x67, 0xda, 0xdb
};
unsigned char VERISIGN_CLASS1_EXPONENT[3] = { 0x01, 0x00, 0x01 };

#ifdef MACTC  /* rwo */
clock_t Time0, Time1;
#endif

int main (argc, argv)
int argc;
char *argv[];
{
  RCERTSArgs rcertsArgs;
  RCERTSState state;
  RIPEMDatabase ripemDatabase;
  RIPEMInfo ripemInfo;
  int j;
  char *errorMessage, password[MAX_PASSWORD_SIZE], buffer[8];
  unsigned int passwordLen;
  BOOL alreadyPrintedError = FALSE;

  /* Set ripemInfo to initial state. */
  RIPEMInfoConstructor (&ripemInfo);

  RCERTSArgsConstructor (&rcertsArgs);

  /* Initialize state */
  R_memset ((POINTER)&state, 0, sizeof (state));
  
  RIPEMDatabaseConstructor (&ripemDatabase);

#ifdef MACTC
  setvbuf(stderr, NULL, _IONBF, 0);
  fprintf(stderr, "Off we go...\n");
  argc = ccommand(&argv);
  Time0 = clock();
#endif

  /* For error, break to end of do while (0) block. */
  do {
    /* Append the RIPEM_VERSION to the end of the first usage message line
         so it will appear if we have to print the usage. */
    strcat (USAGE_MESSAGE_LINE1, RIPEM_VERSION);

    /* Parse the command line. */
    if ((errorMessage = CrackCommandLine
         (argc, argv, &ripemInfo, &rcertsArgs, &ripemDatabase))
        != (char *)NULL) {
      usage (errorMessage, RCERTS_USAGE_MESSAGE);
      alreadyPrintedError = TRUE;
      break;
    }
    state.usePKCSFormat = rcertsArgs.usePKCSFormat;
    state.digestAlgorithm = rcertsArgs.digestAlgorithm;

    /* Open the debug file.
     */
    if (rcertsArgs.debugFilename != (char *)NULL) {
      if ((ripemInfo.debugStream = fopen
           (rcertsArgs.debugFilename, "w")) == (FILE *)NULL) {
        sprintf (ripemInfo.errMsgTxt,
                 "Can't open debug file %s.", rcertsArgs.debugFilename);
        errorMessage = ripemInfo.errMsgTxt;
        break;
      }
    }
    else
      ripemInfo.debugStream = stderr;

    /* We now have a debug stream and the user's choice of home dir.
       Make sure the home dir exists and that it has an ending directory
         separator.  This will try to get a default name is none is specified
         yet.
     */
    if ((errorMessage = EstablishRIPEMHomeDir
         (&rcertsArgs.homeDir, &ripemInfo)) != (char *)NULL)
      break;

    /* Now we have a home dir, so open the database. */
    if ((errorMessage = InitRIPEMDatabase
         (&ripemDatabase, rcertsArgs.homeDir, &ripemInfo)) != (char *)NULL)
      break;

    /* Clear the parameters so that users typing "ps" or "w" can't
     * see what parameters we are using.
     */
    for (j = 1; j < argc; j++)
      R_memset ((POINTER)argv[j], 0, strlen (argv[j]));

    /* Get the password.  Prompt twice if generating. */
    passwordLen = GetPasswordToPrivateKey
      ((unsigned char *)password, sizeof (password),
       rcertsArgs.keyToPrivateKey);

    /* Log in the user and load the preferences, checking for special errors.
     */
    if ((errorMessage = RIPEMLoginUser
         (&ripemInfo, rcertsArgs.username, &ripemDatabase,
          (unsigned char *)password, passwordLen)) != (char *)NULL) {
      /* Consider ERR_SELF_SIGNED_CERT_NOT_FOUND an error */
      if (strcmp (errorMessage, ERR_PREFERENCES_NOT_FOUND) == 0) {
        /* This is OK, just issue a warning. */
        fputs ("Warning: User preferences were not found.  RIPEM will use defaults.\n", stderr);
        errorMessage = (char *)NULL;
      }
      else if (strcmp (errorMessage, ERR_PREFERENCES_CORRUPT) == 0) {
        /* Issuer alert and continue. */
        fputs ("ALERT: Preference information has been corrupted. RIPEM will use defaults.\n", stderr);
        errorMessage = (char *)NULL;
      }
      else
        /* Other errors. */
        break;
    }

    /* Allocate the certStruct which will hold the selected user. */
    if ((state.certStruct = (CertificateStruct *)malloc
         (sizeof (*state.certStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }
    
    /* Initialize the state to the logged in user.  Don't expect the
         chain select to fail.
     */
    if ((errorMessage = SelectCertChain
         (&ripemInfo, &state.certChain, &state.chainStatus,
          &ripemInfo.userDN, &ripemInfo.publicKey, TRUE, &ripemDatabase))
        != (char *)NULL)
      break;
    /* Decode the user's cert into state's certStruct */
    DERToCertificate
      ((unsigned char *)state.certChain.firstptr->dataptr,
       state.certStruct, &state.fieldPointers);

    if (state.chainStatus.overall == CERT_CRL_OUT_OF_SEQUENCE) {
      puts ("Note that the CRL issued by you found in the database is out of sequence.");
      puts ("  This means that CRLs recently issued by you may have been deleted by");
      puts ("  someone to back up to an earlier CRL without their revocation.");
      puts ("  You may need to replace some revocations.");

      /* Make the user view this message before continuing */
      GetInputLine (buffer, sizeof (buffer), "  Hit <ENTER> to continue:");
    }

    puts ("");
    if (state.usePKCSFormat)
      puts ("(Using PKCS format for messages.)");
    else
      puts ("(Using PEM format for messages.  Use '-M pkcs' if you want PKCS.)");

    if (state.digestAlgorithm == DA_MD2)
      puts ("Using MD2 to sign certificates. (Use '-a algorithm' to use a different one.)");
    else if (state.digestAlgorithm == DA_MD5)
      puts ("Using MD5 to sign certificates. (Use '-a algorithm' to use a different one.)");
    else if (state.digestAlgorithm == DA_SHA1)
      puts ("Using SHA-1 to sign certificates.(Use '-a algorithm' to use a different one.)");
        
    if ((errorMessage = DoMenu
         (&state, &ripemInfo, &ripemDatabase)) != (char *)NULL)
      break;
  } while (0);
      
  R_memset ((POINTER)password, 0, sizeof (password));
  RIPEMInfoDestructor (&ripemInfo);
  RIPEMDatabaseDestructor (&ripemDatabase);
  if (ripemInfo.debugStream != (FILE *)NULL && ripemInfo.debugStream != stderr)
    fclose (ripemInfo.debugStream);

  RCERTSArgsDestructor (&rcertsArgs);
  FreeList (&state.certChain);
  free (state.certStruct);

  if (errorMessage != (char *)NULL && !alreadyPrintedError) {
    fputs (errorMessage, stderr);
    fputc ('\n', stderr);
  }

  MainExit (errorMessage == (char *)NULL ? 0 : 1);
  
  /*NOTREACHED*/
  return (0);  /* to shut up compiler warnings */
}

/* End the program and return a returncode to the system.
 */
static void MainExit (status) 
int status;
{
#ifdef MACTC
  double x;
  (void)fflush((FILE *)NULL);
  Time1 = clock();
  x = (Time1 - Time0)/60.0;
  fprintf(stderr, "Exit %d; Elapsed : %5.2f seconds.", status, x);
#endif
  exit (status);
}

static void RCERTSArgsConstructor (rcertsArgs)
RCERTSArgs *rcertsArgs;
{
  /* Pre-zeroize all pointers in rcertsArgs. */
  R_memset ((POINTER)rcertsArgs, 0, sizeof (*rcertsArgs));

  /* Default to MD5 */
  rcertsArgs->digestAlgorithm = DA_MD5;
}

static void RCERTSArgsDestructor (rcertsArgs)
RCERTSArgs *rcertsArgs;
{
  if (rcertsArgs->keyToPrivateKey)
    R_memset
    ((POINTER)rcertsArgs->keyToPrivateKey, 0,
     strlen (rcertsArgs->keyToPrivateKey));

  /* Free all the pointers in rcertsArgs.
   */
  free (rcertsArgs->keyToPrivateKey);
  free (rcertsArgs->homeDir);
  free (rcertsArgs->debugFilename);
  free (rcertsArgs->username);
}

static char *CrackCommandLine
  (argc, argv, ripemInfo, rcertsArgs, ripemDatabase)
int argc;
char *argv[];
RIPEMInfo *ripemInfo;
RCERTSArgs *rcertsArgs;
RIPEMDatabase *ripemDatabase;
{
  extern char *optarg;
  extern int optind, optsp;

  int got_username = FALSE;
  int got_key_to_priv_key = FALSE;
  BOOL cracking=TRUE;
  int j, ch, myargc[2], iarg;
  char *errorMessage = NULL, *cptr, **myargv[2], *env_args;
  char *key_sources = "sf";
  char *key_server_str=NULL;
  TypList mylist;
  TypListEntry *entry;
  unsigned int len;

  InitList (&mylist);
  rcertsArgs->usePKCSFormat = FALSE;

  /* We crack a command line twice:  
   * First, we crack the pseudo-command line in the environment variable
   *   RIPEM_ARGS (if any).  This environment variable exists to make it
   *   easy for users who don't want to type the otherwise lengthy
   *   command line, and is an alternative to the other individual 
   *   environment variables.
   * Then we crack the real command line.  
   * Processing in this way causes the real command line variables
   * to supercede the environment variables.
   *
   * Start by allocating space for a copy of RIPEM_ARGS.  
   * We need to fill in the first token, the name of the program.
   */ 
  env_args = malloc(8);
  strcpy(env_args,"ripem ");
  GetEnvAlloc(RIPEM_ARGS_ENV, &cptr);
  if(cptr) {
    /* If the environment variable exists, call parsit to tokenize
     * the line as the shell normally does.
     */
    StrConcatRealloc(&env_args,cptr);
    myargv[0] = (char **)NULL;
    myargc[0] = parsit(env_args,&(myargv[0]));
    free(env_args);
  } else {
    /* No environment variable exists; just dummy this up. */
    myargv[0] = (char **)NULL;
    myargc[0] = 0;
  }
  myargv[1] = argv;
  myargc[1] = argc;
  /* Now execute the argument processing loop twice. */
  for(iarg=0; iarg<2; optind=1,optsp=1,cracking=TRUE,iarg++)  {
    /* Use the same options string that the ripem executable uses */
    while(cracking &&
          (ch = mygetopt
           (myargc[iarg], myargv[iarg],
            "3edgGcBr:h:b:A:R:p:s:P:S:m:M:u:k:K:i:o:D:F:Z:C:y:Y:T:v:H:x:a:"))
          != -1) {
      switch (ch) {
        case '?':
          return ("Unrecognized command line option.");
                      
        case 'u':       /* My username */
          StrCopyAlloc (&rcertsArgs->username, optarg);
          got_username = TRUE;
          break;

        case 'a':
          /* digest algorithm. */
          rcertsArgs->digestAlgorithm = -1;
          if (!strcmp (optarg, "rsa-md2"))
            rcertsArgs->digestAlgorithm = DA_MD2;
          else if (!strcmp (optarg, "rsa-md5"))
            rcertsArgs->digestAlgorithm = DA_MD5;
          else if (!strcmp (optarg, "sha-1"))
            rcertsArgs->digestAlgorithm = DA_SHA1;

          if (rcertsArgs->digestAlgorithm < 0)
            return ("Digest algorithm must be either \"rsa-md2\", \"rsa-md5\" or \"sha-1\".");
          break;

        case 'M':       /* Message format */
          if (CaseIgnoreEqual (optarg, "pkcs"))
            rcertsArgs->usePKCSFormat = TRUE;
          else
            /* Assume anything else is non-PKCS */
            rcertsArgs->usePKCSFormat = FALSE;

          break;

        case 'p':       /* Public key filename */
          if ((errorMessage = AddKeySourceFilename
               (&ripemDatabase->pubKeySource, optarg)) != (char *)NULL)
            return (errorMessage);
          break;
          
        case 'P':       /* Public key output filename */
          return ("-P is obsolete. Public keys are written to \"pubkeys\" in the RIPEM home dir.");

        case 's':       /* Secret (private) key filename */
          if ((errorMessage = AddKeySourceFilename
               (&ripemDatabase->privKeySource, optarg)) != (char *)NULL)
            return (errorMessage);
          break;
          
        case 'S':       /* Private key output filename */
          return ("-S is obsolete. Private keys are written to \"privkey\" in the RIPEM home dir.");

        case 'y':       /* Name of public key server */
          StrCopyAlloc (&key_server_str, optarg);
          break;

        case 'Y':       /* Order of sources for keys (server vs. file) */
          StrCopyAlloc (&key_sources, optarg);
          break;

        case 'k':       /* Key to private key */
          StrCopyAlloc (&rcertsArgs->keyToPrivateKey, optarg);
          got_key_to_priv_key = TRUE;
          break;

        case 'H':       /* RIPEM home directory */
          StrCopyAlloc (&rcertsArgs->homeDir, optarg);
          break;

        case 'D':       /* Debug level */
          ripemInfo->debug = atoi (optarg);
          break;

        case 'Z':       /* Debug output file */
          StrCopyAlloc (&rcertsArgs->debugFilename, optarg);
          break;

        default:
          /* mygetopt already ensured that only allowed options are used.
             This catches the options which ripem allows but rcerts does not
               use, so just ignore. */
          break;
      }
    }
  }

  /* Parse the -Y argument string (sources of key info) */

  for(j=0; j<MAX_KEY_SOURCES; j++) {
    switch(key_sources[j]) {
      case 's':
      case 'S':
        ripemDatabase->pubKeySource.origin[j] = KEY_FROM_SERVER;
        break;

      case 'f':
      case 'F':
        ripemDatabase->pubKeySource.origin[j] = KEY_FROM_FILE;
        break;
        
      case 'g':
      case 'G':
        ripemDatabase->pubKeySource.origin[j] = KEY_FROM_FINGER;
        break;
    
      default:
        ripemDatabase->pubKeySource.origin[j] = KEY_FROM_NONE;
        break;
    }
  }
  
  /* If we don't have the RIPEM home dir yet, look for the environment
       variable. */
  if (!rcertsArgs->homeDir) {
    /* Set cptr to the name from the environment, or to "" */
    GetEnvFileName (HOME_DIR_ENV, "", &cptr);

    if (*cptr != '\0')
      /* Found it */
      StrCopyAlloc (&rcertsArgs->homeDir, cptr);
  }

  /* Obtain the username if it wasn't specified. */

  if (!got_username)
    GetUserAddress (&rcertsArgs->username);
  
  /* We only want one username, but if a comma seperated list was supplied,
       find the first name.
   */
  len = 0;
  while (rcertsArgs->username[len] != '\0' && rcertsArgs->username[len] != ',')
    ++len;
  /* Trim trailing blanks. */
  while (len > 0 && rcertsArgs->username[len - 1] == ' ')
    --len;
  rcertsArgs->username[len] = '\0';

  /* Obtain the name of the public key server. */
  if(!key_server_str)
    GetEnvAlloc(SERVER_NAME_ENV,&key_server_str);

  errorMessage = CrackKeyServerInfo (key_server_str, ripemDatabase);
  free (key_server_str);
  if (errorMessage != (char *)NULL)
    return (errorMessage);

  /* Add any public and private keys specified by the environment variables.
   */
  GetEnvFileName (PUBLIC_KEY_FILE_ENV, "", &cptr);
  if (strcmp (cptr, "") != 0) {
    CrackLine (cptr, &mylist);
    free (cptr);
    for (entry = mylist.firstptr; entry; entry = entry->nextptr) {
      /* Set length to zero so that FreeList won't try to zeroize it. */
      entry->datalen = 0;
      ExpandFilename ((char **)&entry->dataptr);
      if ((errorMessage = AddKeySourceFilename
           (&ripemDatabase->pubKeySource, (char *)entry->dataptr))
          != (char *)NULL)
        return (errorMessage);
    }
  }

  GetEnvFileName (PRIVATE_KEY_FILE_ENV, "", &cptr);
  if (strcmp (cptr, "") != 0) {
    CrackLine (cptr, &mylist);
    free (cptr);
    for (entry = mylist.firstptr; entry; entry = entry->nextptr) {
      /* Set length to zero so that FreeList won't try to zeroize it. */
      entry->datalen = 0;
      ExpandFilename ((char **)&entry->dataptr);
      if ((errorMessage = AddKeySourceFilename
           (&ripemDatabase->privKeySource, (char *)entry->dataptr))
          != (char *)NULL)
        return (errorMessage);
    }
  }

  /* Special processing for the key to the private key:
   * A key of - means to read the key to the private key
   * from standard input.
   */
  if (got_key_to_priv_key) {
    if (strcmp (rcertsArgs->keyToPrivateKey, "-") == 0) {
#define PWLEN 256
      char line[PWLEN];

      fgets(line,PWLEN,stdin);
      StrCopyAlloc (&rcertsArgs->keyToPrivateKey, line);
      for (cptr = rcertsArgs->keyToPrivateKey; *cptr; cptr++) {
        if(*cptr=='\n' || *cptr=='\r')
          *cptr='\0';
      }
    }
  }

  return ((char *)NULL);
}

/* This is a copy of CrackKeyServer from ripemcmd.c with the ripemDatabase
     argument passed in instead of being global.
 */
static char *CrackKeyServerInfo (keyServerStr, ripemDatabase)
char *keyServerStr;
RIPEMDatabase *ripemDatabase;
{
  TypList name_list;
  TypListEntry *entry;
  TypServer *server_ent;
  char *cptr, *errmsg;
  
  InitList (&ripemDatabase->pubKeySource.serverlist);
  InitList (&name_list);
  
  if(keyServerStr) {
    CrackLine(keyServerStr,&name_list);
    for(entry=name_list.firstptr; entry; entry=entry->nextptr) {
      server_ent = (TypServer *) malloc(sizeof(TypServer));
      
      server_ent->servername = entry->dataptr;
      server_ent->serverport = 0;
      cptr = strchr(server_ent->servername,':');
      if(cptr) {
        server_ent->serverport = atoi(cptr+1);
        if(!server_ent->serverport) {
          return "Invalid server port number";
        }
        *cptr = '\0';
      } else {
        server_ent->serverport = SERVER_PORT;
      }
      errmsg = AddToList
        (NULL, server_ent, sizeof (TypServer),
         &ripemDatabase->pubKeySource.serverlist);
      if(errmsg)
        return errmsg;
    }
  }
  return NULL;    
}

/* This is a copy of GetPasswordToPrivateKey from ripemcmd.c except
     verify and new are always false and also takes rcertsArgs keyToPrivateKey
     as an argument unstead of using a global variable.
 */
static unsigned int GetPasswordToPrivateKey
  (password, maxchars, keyToPrivateKey)
unsigned char *password;
unsigned int maxchars;
char *keyToPrivateKey;
{
  unsigned int pw_len = 0;
  BOOL got_pw = FALSE;
  char *cptr;

  if (keyToPrivateKey != (char *)NULL) {
    strncpy ((char *)password, keyToPrivateKey, maxchars);
    pw_len = (unsigned int)strlen ((char *)password);
    got_pw = TRUE;
  }

  if (!got_pw) {
    GetEnvAlloc (KEY_TO_PRIVATE_KEY_ENV, &cptr);
    if(cptr && *cptr) {
       strncpy ((char *)password, cptr, maxchars);
       pw_len = (unsigned int)strlen ((char *)password);
       got_pw = TRUE;
    }
  }

  if(!got_pw) {
    pw_len = GetPasswordFromUser
      ("Enter password to private key: ", FALSE, password, maxchars);
  }

  return (pw_len);
}

static char *DoMenu (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  BOOL done;
  char command[8], *errorMessage = (char *)NULL;

  done = FALSE;
  while (!done) {
    puts ("");
    if (state->chainStatus.overall != 0) {
      printf ("The selected user is:\n  ");
      WritePrintableName (stdout, &state->certStruct->subject);
      printf ("\n");
    }
    puts ("S - Select user...");
    puts ("V - View detail for the selected user");
    puts ("C - request CRLs for the selected user...");
    puts ("M - Modify chain length allowed for the selected user...");
    puts ("R - Revoke the selected user...");
    puts ("D - issue Direct certificate for the selected user...");
    puts ("U - Update (renew) certificate for the selected user...");
    puts ("E - Enable standard issuers...");
    puts ("N - reNew the CRL issued by you...");
    puts ("P - Publish the CRL issued by you in a CRL message...");
    puts ("O - Output a certification request message...");
    puts ("X - eXport certificates...");
    puts ("Q - Quit");

    GetInputLine (command, sizeof (command), "  Enter choice:");

    switch (*command) {
    case 's':
    case 'S':
      errorMessage = SelectUser (state, ripemInfo, ripemDatabase);
      break;

    case 'v':
    case 'V':
      errorMessage = ViewUserDetail (state, ripemInfo);
      break;
      
    case 'c':
    case 'C':
      errorMessage = RequestCRLs (state, ripemInfo);
      break;
      
    case 'm':
    case 'M':
      errorMessage = ModifyChainLenAllowed (state, ripemInfo, ripemDatabase);
      break;

    case 'r':
    case 'R':
      errorMessage = RevokeSelectedUser (state, ripemInfo, ripemDatabase);
      break;

    case 'd':
    case 'D':
      errorMessage = IssueDirectCertificate (state, ripemInfo, ripemDatabase);
      break;

    case 'u':
    case 'U':
      errorMessage = RenewSelectedUser (state, ripemInfo, ripemDatabase);
      break;

    case 'e':
    case 'E':
      errorMessage = EnableStandardIssuers (state, ripemInfo, ripemDatabase);
      break;
      
    case 'n':
    case 'N':
      errorMessage = RenewCRL (state, ripemInfo, ripemDatabase);
      break;
      
    case 'p':
    case 'P':
      errorMessage = PublishCRL (state, ripemInfo, ripemDatabase);
      break;
      
    case 'o':
    case 'O':
      errorMessage = OutputCertifyRequest (state, ripemInfo);
      break;
      
    case 'x':
    case 'X':
      errorMessage = ExportCerts (state, ripemInfo, ripemDatabase);
      break;
      
    case 'Q':
    case 'q':
      done = TRUE;
      break;
      
    case '\0':
      /* Blank line.  Just repeat the menu */
      break;

    default:
      puts ("ERROR: Unrecognized command.  Try again.");
      break;
    }
    if (errorMessage != (char *)NULL)
      /* Broke because of error. */
      break;
  }

  return (errorMessage);
}

/* Print the prompt, then read up to maxLineSize - 1 bytes and put into line,
     null terminated.  This is better than just calling gets, since gets
     does not check for overflow of the line buffer.
   This assumes maxLineSize is at least 1.
 */
static void GetInputLine (line, maxLineSize, prompt)
char *line;
unsigned int maxLineSize;
char *prompt;
{
  unsigned int i;
  
  puts (prompt);  
  fflush (stdout);

  fgets (line, maxLineSize, stdin);
  
  /* Replace the line terminator with a '\0'.
   */
  for (i = 0; line[i] != '\0'; i++) {
    if (line[i] == '\012' || line[i] == '\015' || i == (maxLineSize - 1)) {
      line[i] = '\0';
      return;
    }
  }
}

/* Prompt for a smart name and set the certChain and chainStatus in
     state for that user.  If there are multiple certificates that match
     the smart name, this will prompt the user for the correct one.
   If no chain can be found, this sets state->chainStatus.overall to 0
     and state->certChain is empty.  This also prints a message if no
     chain can be found.
 */
static char *SelectUser (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  TypList selectedCerts, filteredCerts;
  TypListEntry *entry;
  CertificateStruct *filteredCertStruct = (CertificateStruct *)NULL;
  char *errorMessage = (char *)NULL, command[80], buffer[8];
  unsigned int filteredCertCount;
  BOOL foundAChain = FALSE, directCertOnly;

  InitList (&selectedCerts);
  InitList (&filteredCerts);

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate on the heap since it is so big. */
    if ((filteredCertStruct = (CertificateStruct *)malloc
         (sizeof (*filteredCertStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    GetInputLine
      (command, sizeof (command),
       "  Enter name of user to select (blank to cancel):");
    if (! *command)
      /* User cancelled */
      break;

    GetInputLine
      (buffer, sizeof (buffer),
       "  Hit <ENTER> to allow any certificate chain (the default) or enter D to\n    make sure the user is certified directly by you:");
    directCertOnly = (*buffer == 'd' || *buffer == 'D');

    /* Clear previous info in the state. */
    FreeList (&state->certChain);
    state->chainStatus.overall = 0;
    
    /* Select all certs which match this user name. */
    if ((errorMessage = GetCertsBySmartname
         (ripemDatabase, &selectedCerts, command, ripemInfo)) != (char *)NULL)
      break;

    /* Move certs from selectedCerts to filteredCerts, omitting ones with
         duplicate subject/public key (such as expired vs. current certs).
       Also get the count of filtered certs.
     */
    filteredCertCount = 0;
    for (entry = selectedCerts.firstptr; entry; entry = entry->nextptr) {
      /* Decode the certificate into the state's certStruct */
      if (DERToCertificate
          ((unsigned char *)entry->dataptr, state->certStruct,
           (CertFieldPointers *)NULL) < 0) {
        /* Error decoding.  Just issue a warning to debug stream and try
             the next cert. */
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
                   "Warning: Cannot decode certificate from database.\n");
        continue;
      }

      if (!FindSubjectPublicKey
          (&filteredCerts, &state->certStruct->subject,
           &state->certStruct->publicKey, filteredCertStruct)) {
        /* This subject/public key has not already been added to
             the filteredCerts, so add.  We will "transfer" from
             selectedCerts by setting the entry to NULL in selectedCerts
             so it won't be freed. */
        if ((errorMessage = AddToList
             ((TypListEntry *)NULL, entry->dataptr, entry->datalen,
              &filteredCerts)) != (char *)NULL)
          break;
        entry->dataptr = NULL;
        entry->datalen = 0;
        ++filteredCertCount;
      }
    }
    if (errorMessage != (char *)NULL)
      /* Broke because of error */
      break;

    if (filteredCertCount == 0) {
      /* None found */
      printf ("Cannot find any certificate for %s.\n", command);
      break;
    }

    if (filteredCertCount > 1)
      printf
    ("There are up to %u entries which match that user name. Please choose:\n",
       filteredCertCount);

    /* Let the user pick the entry.  If there is one entry, this loop will
         automatically use it.
     */
    for (entry = filteredCerts.firstptr; entry; entry = entry->nextptr) {
      DERToCertificate
        ((unsigned char *)entry->dataptr, filteredCertStruct,
         (CertFieldPointers *)NULL);

      /* Clear previous cert chain and get the chain for this cert. */
      FreeList (&state->certChain);
      if ((errorMessage = SelectCertChain
           (ripemInfo, &state->certChain, &state->chainStatus,
            &filteredCertStruct->subject, &filteredCertStruct->publicKey,
            directCertOnly, ripemDatabase)) != (char *)NULL)
        break;
      /* Note that we are done with filteredCertStruct now. */

      if (state->chainStatus.overall == 0)
        /* A cert chain for this cert could not be completed.  In this
             case filteredCertCount is too high. */
        break;

      /* Set foundAChain so we know whether there was something for
           the user to reject. */
      foundAChain = TRUE;
      
      /* Decode the selected user's cert into state's certStruct */
      DERToCertificate
        ((unsigned char *)state->certChain.firstptr->dataptr,
         state->certStruct, &state->fieldPointers);

      if (filteredCertCount == 1)
        /* There is only one possibility, so don't prompt the user. */
        break;

      /* Display this entry to the user and let them choose.
       */
      printf ("\nCertificate for:\n  ");
      WritePrintableName (stdout, &state->certStruct->subject);
      printf ("\n");
      if (state->certChain.firstptr == state->certChain.lastptr)
        /* There is only one certificate in the chain. */
        printf ("  certified directly by you.\n");
      else {
        /* This chain is certified via the subject at the top of the
             chain (end of the list).  Use filteredCertStruct show the
             subject at the top of the chain.
         */
        DERToCertificate
          ((unsigned char *)state->certChain.lastptr->dataptr,
           filteredCertStruct, (CertFieldPointers *)NULL);
        printf ("  certified indirectly through:\n  ");
        WritePrintableName (stdout, &filteredCertStruct->subject);
        printf ("\n");
      }

      GetInputLine
        (command, sizeof (command),
         "  Choose: Select, Quit or <ENTER> to see next entry:");
      if (*command == 's' || *command == 'S')
        break;
      else if (*command == 'q' || *command == 'Q') {
        state->chainStatus.overall = 0;
        /* certChain will be freed below */
        break;
      }
      /* Default is to continue */
    }
    if (errorMessage != (char *)NULL)
      /* Broke because of error. */
      break;

    if (state->chainStatus.overall == 0) {
      /* No chain, so free the certChain list */
      FreeList (&state->certChain);

      if (!foundAChain) {
        /* chainStatus.overall is zero because there are no valid chains. */
        if (directCertOnly)
          puts ("Could not find certificate for this user issued directly by you.");
        else
          puts ("Could not find any valid certificate chain.");
      }
    }
  } while (0);

  FreeList (&selectedCerts);
  FreeList (&filteredCerts);
  free (filteredCertStruct);
  return (errorMessage);
}

static char *ViewUserDetail (state, ripemInfo)
RCERTSState *state;
RIPEMInfo *ripemInfo;
{
  CertificateStruct *localCertStruct = (CertificateStruct *)NULL;
  TypListEntry *entry;
  char *errorMessage = (char *)NULL, buffer[8], startDate[18], endDate[18];
  unsigned char digest[MAX_DIGEST_LEN];
  unsigned int chainLenAllowed, i, digestLen;

  if (state->chainStatus.overall == 0) {
    puts ("First use \"Select user\" to select the user to view.");
    return ((char *)NULL);
  }

  /* For error, break to end of do while (0) block. */
  do {
    printf ("The selected user is:\n  ");
    WritePrintableName (stdout, &state->certStruct->subject);
    printf ("\n");

    if (state->certChain.firstptr == state->certChain.lastptr) {
      /* There is only one certificate in the chain. */

      /* Get validity dates. */
      GetDateAndTimeFromTime (startDate, state->certStruct->notBefore);
      GetDateAndTimeFromTime (endDate, state->certStruct->notAfter);
      
      if (R_memcmp
          ((POINTER)&state->certStruct->publicKey,
           (POINTER)&ripemInfo->publicKey, sizeof (ripemInfo->publicKey))
          == 0) {
        printf ("This is your own self-signed certificate.\n");
        /* For one cert, the overall is the same as the individual status. */
        printf ("It has a certificate status of %s\n",
                CertStatusString (state->chainStatus.overall));
        printf
          ("  with a validity period from %s to %s GMT.\n", startDate,
           endDate);

        /* Print the self-signed cert digest.
         */
        R_DigestBlock
          (digest, &digestLen, state->fieldPointers.innerDER,
           state->fieldPointers.innerDERLen,
           state->certStruct->digestAlgorithm);
        printf ("self-signed certificate digest:");
        for (i = 0; i < digestLen; ++i)
          printf (" %02X", (int)digest[i]);
	if (state->certStruct->digestAlgorithm == DA_MD2)
	  printf (" (MD2)");
	else if (state->certStruct->digestAlgorithm == DA_MD5)
	  printf (" (MD5)");
	else if (state->certStruct->digestAlgorithm == DA_SHA1)
	  printf (" (SHA-1)");
        printf ("\n");
      }
      else {
        printf ("This user is certified directly by you.\n");
        /* For one cert, the overall is the same as the individual status. */
        printf ("The certificate for this user has a status of %s\n",
                CertStatusString (state->chainStatus.overall));
        printf
          ("  with a validity period from %s to %s GMT.\n", startDate,
           endDate);

        /* Get chain length allowed.
         */
        if ((errorMessage = GetPublicKeyDigest
             (digest, &state->certStruct->publicKey)) != (char *)NULL)
          break;
        chainLenAllowed = GetChainLenAllowed (ripemInfo, digest);
        if (chainLenAllowed == 0)
          puts
            ("You do not allow this user to make certificates for others.");
        else
          printf
          ("You allow this user to make certificate chains up to length %u.\n",
           chainLenAllowed);
      }
    }
    else {
      /* There is more than one certificate in the chain. */
      printf ("This user has overall certificate chain status of %s.\n",
              CertStatusString (state->chainStatus.overall));

      /* Allocate a certStruct and show the issuers up the chain. */
      if ((localCertStruct = (CertificateStruct *)malloc
           (sizeof (*localCertStruct))) == (CertificateStruct *)NULL) {
        errorMessage = ERR_MALLOC;
        break;
      }

      /* Make i track as we go through the cert list.
       */
      for (entry = state->certChain.firstptr, i = 0;
           entry != (TypListEntry *)NULL;
           entry = entry->nextptr, ++i) {
        DERToCertificate
          ((unsigned char *)entry->dataptr, localCertStruct,
           (CertFieldPointers *)NULL);

        if (entry != state->certChain.lastptr) {
          if (i == 0)
            /* The first cert in the chain */
            printf
              ("This user has a certificate with status %s issued by:\n  ",
               CertStatusString (state->chainStatus.individual[i]));
          else
            /* For cert indexes above the first show that it is an issuer cert.
             */
            printf
            ("And this issuer has a certificate with status %s issued by:\n  ",
             CertStatusString (state->chainStatus.individual[i]));
          WritePrintableName (stdout, &localCertStruct->issuer);
          printf ("\n");
        }
        else {
          printf
          ("And this issuer has a certificate with status %s issued by you\n",
           CertStatusString (state->chainStatus.individual[i]));
        }

        /* Now show the validity period for the cert.
         */
        GetDateAndTimeFromTime (startDate, localCertStruct->notBefore);
        GetDateAndTimeFromTime (endDate, localCertStruct->notAfter);
        printf
          ("  with a validity period from %s to %s GMT.\n", startDate,
           endDate);
      }
    }

    /* Let the user view the info before continuing */
    GetInputLine (buffer, sizeof (buffer), "  Hit <ENTER> to continue:");
  } while (0);

  free (localCertStruct);
  return (errorMessage);
}

static char *RequestCRLs (state, ripemInfo)
RCERTSState *state;
RIPEMInfo *ripemInfo;
{
  FILE *outStream;
  TypListEntry *entry;
  CertificateStruct *localCertStruct = (CertificateStruct *)NULL;
  char *errorMessage, filename[256];
  unsigned char *partOut;
  unsigned int partOutLen;
  
  if (state->chainStatus.overall == 0) {
    puts ("First use \"Select user\" to select the user to request CRLs for.");
    return ((char *)NULL);
  }

  if (state->certChain.firstptr == state->certChain.lastptr) {
    /* There is only one certificate in the chain. */
    puts ("The selected user is certified directly by you, so no CRL retrieval is needed.");
    return ((char *)NULL);
  }
  
  GetInputLine
    (filename, sizeof (filename),
     "  Enter output filename for CRL retrieval request:");
  if ((outStream = fopen (filename, "w")) == (FILE *)NULL)
    return ("Cannot open CRL request file.");

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the localCertStruct on the heap because it's big. */
    if ((localCertStruct = (CertificateStruct *)malloc
         (sizeof (*localCertStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    if ((errorMessage = RIPEMRequestCRLsInit
         (ripemInfo, &partOut, &partOutLen)) != (char *)NULL)
      break;
    fwrite (partOut, 1, partOutLen, outStream);

    /* Write out issuer names for all certs in the chain but the
         top, which is the logged in user.  We have already made
         sure there is at least one certificate in the chain.
     */
    for (entry = state->certChain.firstptr; entry != state->certChain.lastptr;
         entry = entry->nextptr) {
      /* Get issuer name.  Note DERToCertificate won't return an error
           since it was already successfully decoded.
       */
      DERToCertificate
        ((unsigned char *)entry->dataptr, localCertStruct,
         (CertFieldPointers *)NULL);

      if ((errorMessage = RIPEMRequestCRLsUpdate
           (ripemInfo, &partOut, &partOutLen, &localCertStruct->issuer))
          != (char *)NULL)
        break;
      fwrite (partOut, 1, partOutLen, outStream);
    }
    if (errorMessage != (char *)NULL)
      /* Broke loop because of error. */
      break;

    if ((errorMessage = RIPEMRequestCRLsFinal
         (ripemInfo, &partOut, &partOutLen)) != (char *)NULL)
      break;
    fwrite (partOut, 1, partOutLen, outStream);
  } while (0);

  fclose (outStream);
  free (localCertStruct);
  return (errorMessage);
}

static char *ModifyChainLenAllowed (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  unsigned char publicKeyDigest[MD5_LEN];
  unsigned int chainLenAllowed;
  char *errorMessage, command[80];
  
  if (state->chainStatus.overall == 0) {
    puts ("First use \"Select user\" to select the user you want to modify.");
    puts ("Be sure to choose \"D\" for selecting a direct certificate.");
    return ((char *)NULL);
  }

  if (state->certChain.firstptr != state->certChain.lastptr) {
    /* There is more than one certificate in the chain. */
    puts ("This user's certificate is issued by someone else.  You can only set the");
    puts ("  chain length allowed for a user certified directly by you.");
    puts ("Do \"Select user\" again and choose \"D\" for selecting a direct certificate.");
    return ((char *)NULL);
  }
  
  if (R_memcmp
      ((POINTER)&state->certStruct->publicKey,
       (POINTER)&ripemInfo->publicKey, sizeof (ripemInfo->publicKey)) == 0) {
    puts ("This is your own self-signed certificate.  There is no need to modify the");
    puts ("  chain length allowed.");
    return ((char *)NULL);
  }

  /* Get current chain length allowed.
   */
  if ((errorMessage = GetPublicKeyDigest
       (publicKeyDigest, &state->certStruct->publicKey)) != (char *)NULL)
    return (errorMessage);
  chainLenAllowed = GetChainLenAllowed (ripemInfo, publicKeyDigest);
  if (chainLenAllowed == 0)
    puts
     ("You do not currently allow this user to make certificates for others.");
  else
    printf
    ("You currently allow this user to make certificate chains up to length %u.\n",
     chainLenAllowed);

  GetInputLine
    (command, sizeof (command),
     "  Enter new chain length allowed, 0 to not allow chains, or blank to cancel:");

  if (! *command)
    /* User cancelled. */
    return ((char *)NULL);

  /* Set chainLenAllowed to new value.  If sscanf doesn't return 1, it
       means junk was entered. */
  if (sscanf (command, "%u", &chainLenAllowed) != 1) {
    puts ("You did not enter a number.  Chain length allowed was not modified.");
    return ((char *)NULL);
  }

  /* Set the new value and save the preferences. */
  return (SetChainLenAllowed
          (ripemInfo, publicKeyDigest, chainLenAllowed, ripemDatabase));
}

static char *RevokeSelectedUser (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  char command[80], *errorMessage;
  unsigned int validityMonths;
  UINT4 now;
  
  if (state->chainStatus.overall == 0) {
    puts ("First use \"Select user\" to select the user you want to revoke.");
    puts ("Be sure to choose \"D\" for selecting a direct certificate.");
    return ((char *)NULL);
  }

  if (state->certChain.firstptr != state->certChain.lastptr) {
    /* There is more than one certificate in the chain. */
    puts ("This user's certificate is issued by someone else.  You can only revoke a user");
    puts ("  who is certified directly by you.");
    puts ("Do \"Select user\" again and choose \"D\" for selecting a direct certificate.");
    return ((char *)NULL);
  }
  
  if (R_memcmp
      ((POINTER)&state->certStruct->publicKey,
       (POINTER)&ripemInfo->publicKey, sizeof (ripemInfo->publicKey)) == 0) {
    puts ("This is your own self-signed certificate.  You cannot place yourself on the");
    puts ("  CRL issued by you.");
    return ((char *)NULL);
  }

  if (state->chainStatus.overall == CERT_REVOKED) {
    puts ("This user is already revoked.");
    return ((char *)NULL);
  }

  puts ("This will revoke the selected user by adding an entry to the CRL issued by");
  puts ("  you.  It will also renew the CRL.  Once a user is revoked it cannot be");
  puts ("  removed from the CRL until the certificate you issued for the user expires.");
  puts ("If you have never issued a CRL, this will create a new one.");
  
  GetInputLine
    (command, sizeof (command),
     "  Enter the number of months the new CRL will be valid, or blank to cancel:");

  if (! *command)
    /* User cancelled. */
    return ((char *)NULL);

  /* Set validityMonths to new value.  If sscanf doesn't return 1, it
       means junk was entered. */
  if (sscanf (command, "%u", &validityMonths) != 1) {
    puts ("You did not enter a number.  The CRL was not renewed.");
    return ((char *)NULL);
  }
  if (validityMonths == 0) {
    puts ("Validity months must be one or more.  The CRL was not renewed.");
    return ((char *)NULL);
  }

  /* Get the present time so we can compute the nextUpdate time and update
       the CRL with the serialNumber to revoke. */
  R_time (&now);
  if ((errorMessage = RIPEMUpdateCRL
       (ripemInfo, now + (UINT4)validityMonths * SECONDS_IN_MONTH,
	state->certStruct->serialNumber,
        sizeof (state->certStruct->serialNumber), state->digestAlgorithm,
	ripemDatabase))
      != (char *)NULL)
    return (errorMessage);

  puts ("The user has been revoked.  Since the certification status has now changed,");
  puts ("  you must use \"Select User\" to re-select the user's certificate chain.");
  /* Make the user view this message before continuing */
  GetInputLine (command, sizeof (command), "  Hit <ENTER> to continue:");
  
  /* Clear the current user from the state. */
  FreeList (&state->certChain);
  state->chainStatus.overall = 0;

  return ((char *)NULL);
}

static char *IssueDirectCertificate (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  char command[80], *errorMessage = (char *)NULL;
  unsigned int validityMonths;

  if (state->chainStatus.overall == 0) {
    puts ("First use \"Select user\" to select the user you want to issue for.");
    return ((char *)NULL);
  }

  if (state->certChain.firstptr == state->certChain.lastptr) {
    /* There is only one certificate in the chain. */
    puts ("This user is already directly certified by you, so there is no need to");
    puts ("  issue a direct certificate.");
    return ((char *)NULL);
  }
  
  if (state->chainStatus.overall == CERT_REVOKED) {
    puts ("Warning: This user or one of the user's issuers is revoked.");
    GetInputLine
      (command, sizeof (command),
       "  Enter Y to proceed with issuing a direct certificate, anything else to quit:");
    if (! (*command == 'y' || *command == 'Y'))
      return ((char *)NULL);
  }

  /* For error, break to end of do while (0) block. */
  do {
    puts ("This user already has a valid certificate chain through another issuer.");
    puts ("  You may now create a certificate issued directly by you for this user.");
    GetInputLine
      (command, sizeof (command),
       "  Enter the number of months for the certificate validity, or blank to cancel:");

    if (! *command)
      /* User cancelled. */
      break;

    /* Set validityMonths to new value.  If sscanf doesn't return 1, it
         means junk was entered. */
    if (sscanf (command, "%u", &validityMonths) != 1) {
      puts ("You did not enter a number.  The direct certificate was not issued.");
      break;
    }
    if (validityMonths == 0) {
      puts ("Validity months must be one or more.  The direct certificate wasa no issued.");
      break;
    }

    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    /* Set up new certificate values.
     */
    certStruct->subject = state->certStruct->subject;
    certStruct->publicKey = state->certStruct->publicKey;
    R_time (&certStruct->notBefore);
    certStruct->notAfter =
      certStruct->notBefore + (UINT4)validityMonths * SECONDS_IN_MONTH;

    /* Note that this returns an error if there is already a currently
         valid direct certificate. */
    if ((errorMessage = ValidateAndWriteCert
         (ripemInfo, certStruct, state->digestAlgorithm, ripemDatabase))
	!= (char *)NULL) {
      if (strcmp (errorMessage, ERR_CERT_ALREADY_VALIDATED) == 0) {
        puts ("This user is already directly certified by you.  To view this certificate,");
        puts ("  do \"Select user\" again and choose \"D\" for selecting a direct certificate.");
        errorMessage = (char *)NULL;
      }
      break;
    }

    puts ("The direct certificate has been issued.  Since the certification status has");
    puts ("  now changed, you must use \"Select User\" to re-select the user's");
    puts ("  certificate chain.");
    /* Make the user view this message before continuing */
    GetInputLine (command, sizeof (command), "  Hit <ENTER> to continue:");

    /* Clear the current user from the state. */
    FreeList (&state->certChain);
    state->chainStatus.overall = 0;
  } while (0);

  free (certStruct);
    
  return (errorMessage);
}

static char *RenewSelectedUser (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  char command[80], *errorMessage;
  unsigned int validityMonths;
  UINT4 now;
  
  if (state->chainStatus.overall == 0) {
    puts ("First use \"Select user\" to select the user whose certificate you want to");
    puts ("  renew. Be sure to choose \"D\" for selecting a direct certificate.");
    return ((char *)NULL);
  }

  if (state->certChain.firstptr != state->certChain.lastptr) {
    /* There is more than one certificate in the chain. */
    puts ("This user's certificate is issued by someone else.  You can only renew a");
    puts ("  user's certificate which is issued directly by you.");
    puts ("Do \"Select user\" again and choose \"D\" for selecting a direct certificate.");
    return ((char *)NULL);
  }
  
  if (state->chainStatus.overall == CERT_REVOKED) {
    puts ("This certificate is already revoked. You cannot renew a revoked certificate.");
    return ((char *)NULL);
  }

  R_time (&now);

  if (now < state->certStruct->notBefore) {
    puts ("The currently selected certificate has a validity time which begins");
    puts ("  later than now!  Is your computer's clock set correctly?");
    return ((char *)NULL);
  }
  if (now <= state->certStruct->notAfter) {
    /* There is a currently valid certificate.  Only let them renew if
         it is less than a month to expiration. */
    if ((now + SECONDS_IN_MONTH) <= state->certStruct->notAfter) {
      puts ("The currently selected certificate is still valid for at least another month.");
      puts ("  You can only renew a certificate which has less than one month validity, or");
      puts ("  is already expired.");
      return ((char *)NULL);
    }
    else {
      puts ("The currently selected certificate is still valid, but it expires in less");
      puts ("  than one month.  Do you want to renew the certificate with a validity");
      puts ("  period beginning right when the current certificate expires?  (If you make");
      puts ("  such a future certificate and then revoke the current certificate before");
      puts ("  the future one becomes valid, you must revoke the future one also!)");
      GetInputLine
	(command, sizeof (command),
	 "  Enter Y to proceed with renewing the certificate, anything else to quit:");
      if (! (*command == 'y' || *command == 'Y'))
	return ((char *)NULL);

      /* Set now to right after the end of the current period */
      now = state->certStruct->notAfter + (UINT4)1;
    }
  }

  if (R_memcmp
      ((POINTER)&state->certStruct->publicKey,
       (POINTER)&ripemInfo->publicKey, sizeof (ripemInfo->publicKey)) == 0) {
    puts ("This will renew your self-signed certificate by issuing a new self-signed");
    puts ("  certificate with a new validity period.");
  }
  else {
    puts ("This will renew the certificate for the selected user by issuing a new");
    puts ("  certificate with a new validity period.");
  }

  puts ("  Once this new certificate is created, you cannot remove it. (You can only");
  puts ("  revoke it.) Also, the previous certificate will remain in the database.");
  puts ("  RIPEM will use the newer certificate during its validity period.");
  
  GetInputLine
    (command, sizeof (command),
     "  Enter the number of months the new cert will be valid, or blank to cancel:");

  if (! *command)
    /* User cancelled. */
    return ((char *)NULL);

  /* Set validityMonths to new value.  If sscanf doesn't return 1, it
       means junk was entered. */
  if (sscanf (command, "%u", &validityMonths) != 1) {
    puts ("You did not enter a number.  The certificate was not renewed.");
    return ((char *)NULL);
  }
  if (validityMonths == 0) {
    puts ("Validity months must be one or more.  The certificate was not renewed.");
    return ((char *)NULL);
  }

  do {
    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    /* Set up new certificate values.
     */
    certStruct->subject = state->certStruct->subject;
    certStruct->publicKey = state->certStruct->publicKey;
    certStruct->notBefore = now;
    certStruct->notAfter =
      certStruct->notBefore + (UINT4)validityMonths * SECONDS_IN_MONTH;

    /* Note that this returns an error if there is already a currently
         valid direct certificate. */
    if ((errorMessage = ValidateAndWriteCert
         (ripemInfo, certStruct, state->digestAlgorithm, ripemDatabase))
	!= (char *)NULL) {
      if (strcmp (errorMessage, ERR_CERT_ALREADY_VALIDATED) == 0) {
        /* Intercept this error and don't treat as fatal. */
        /* We have already checked an know that this is not for a currently-
	     valid certificate. */
        puts ("You have already made a certificate for this user with a later validity");
        puts ("  period.  Later, when it becomes valid, RIPEM will begin using it.");
        errorMessage = (char *)NULL;
      }
      break;
    }

    puts ("The certificate has been renewed.  Since the certification status has");
    puts ("  now changed, you must use \"Select User\" to re-select the user's");
    puts ("  certificate chain.");
    /* Make the user view this message before continuing */
    GetInputLine (command, sizeof (command), "  Hit <ENTER> to continue:");

    /* Clear the current user from the state. */
    FreeList (&state->certChain);
    state->chainStatus.overall = 0;
  } while (0);

  free (certStruct);
    
  return (errorMessage);
}

static char *EnableStandardIssuers (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  DistinguishedNameStruct name;
  char command[8];

  puts ("");
  puts ("1 - Verisign Class 1 Root Key...");
  puts ("L - Low Assurance Certification Authority...");
  puts ("C - Commercial Certification Authority...");
  puts ("B - Verisign Beta Class 1 Root Key (soon to expire)...");

  GetInputLine
    (command, sizeof (command),
     "  Select the issuer to enable (blank to cancel):");

  if (! *command)
    /* User cancel */
    return ((char *)NULL);
  
  switch (*command) {
  case '1':
    InitDistinguishedNameStruct (&name);
    
    strcpy (name.AVAValues[0], "US");
    name.AVATypes[0] = ATTRTYPE_COUNTRYNAME;
    name.RDNIndexStart[0] = name.RDNIndexEnd[0] = 0;

    strcpy (name.AVAValues[1], "VeriSign, Inc.");
    name.AVATypes[1] = ATTRTYPE_ORGANIZATIONNAME;
    name.RDNIndexStart[1] = name.RDNIndexEnd[1] = 1;

    strcpy
      (name.AVAValues[2], "Class 1 Public Primary Certification Authority");
    name.AVATypes[2] = ATTRTYPE_ORGANIZATIONALUNITNAME;
    name.RDNIndexStart[2] = name.RDNIndexEnd[2] = 2;

    /* Note: multiplying the byte size by 8 to get the modulusBits only
         works because all 8 bits of the MSB are used. */
    return (EnableIssuer
            (ripemInfo, &name, VERISIGN_CLASS1_MODULUS,
             sizeof (VERISIGN_CLASS1_MODULUS), VERISIGN_CLASS1_EXPONENT,
	     sizeof (VERISIGN_CLASS1_EXPONENT),
             8 * sizeof (VERISIGN_CLASS1_MODULUS), 2, state->digestAlgorithm,
	     ripemDatabase));

  case 'l':
  case 'L':
    InitDistinguishedNameStruct (&name);
    
    strcpy (name.AVAValues[0], "US");
    name.AVATypes[0] = ATTRTYPE_COUNTRYNAME;
    name.RDNIndexStart[0] = name.RDNIndexEnd[0] = 0;

    strcpy (name.AVAValues[1], "RSA Data Security, Inc.");
    name.AVATypes[1] = ATTRTYPE_ORGANIZATIONNAME;
    name.RDNIndexStart[1] = name.RDNIndexEnd[1] = 1;

    strcpy (name.AVAValues[2], "Low Assurance Certification Authority");
    name.AVATypes[2] = ATTRTYPE_ORGANIZATIONALUNITNAME;
    name.RDNIndexStart[2] = name.RDNIndexEnd[2] = 2;

    /* Note: multiplying the byte size by 8 to get the modulusBits only
         works because all 8 bits of the MSB are used. */
    return (EnableIssuer
            (ripemInfo, &name, LOW_ASSURANCE_MODULUS,
             sizeof (LOW_ASSURANCE_MODULUS),
             LOW_ASSURANCE_EXPONENT, sizeof (LOW_ASSURANCE_EXPONENT),
             8 * sizeof (LOW_ASSURANCE_MODULUS), 2, state->digestAlgorithm,
	     ripemDatabase));

  case 'c':
  case 'C':
    InitDistinguishedNameStruct (&name);
    
    strcpy (name.AVAValues[0], "US");
    name.AVATypes[0] = ATTRTYPE_COUNTRYNAME;
    name.RDNIndexStart[0] = name.RDNIndexEnd[0] = 0;

    strcpy (name.AVAValues[1], "RSA Data Security, Inc.");
    name.AVATypes[1] = ATTRTYPE_ORGANIZATIONNAME;
    name.RDNIndexStart[1] = name.RDNIndexEnd[1] = 1;

    strcpy (name.AVAValues[2], "Commercial Certification Authority");
    name.AVATypes[2] = ATTRTYPE_ORGANIZATIONALUNITNAME;
    name.RDNIndexStart[2] = name.RDNIndexEnd[2] = 2;

    /* Note: multiplying the byte size by 8 to get the modulusBits only
         works because all 8 bits of the MSB are used. */
    return (EnableIssuer
            (ripemInfo, &name, COMMERCIAL_CA_MODULUS,
             sizeof (COMMERCIAL_CA_MODULUS),
             COMMERCIAL_CA_EXPONENT, sizeof (COMMERCIAL_CA_EXPONENT),
             8 * sizeof (COMMERCIAL_CA_MODULUS), 2, state->digestAlgorithm,
	     ripemDatabase));

  case 'v':
  case 'V':
    InitDistinguishedNameStruct (&name);
    
    strcpy (name.AVAValues[0], "US");
    name.AVATypes[0] = ATTRTYPE_COUNTRYNAME;
    name.RDNIndexStart[0] = name.RDNIndexEnd[0] = 0;

    strcpy (name.AVAValues[1], "VeriSign, Inc.");
    name.AVATypes[1] = ATTRTYPE_ORGANIZATIONNAME;
    name.RDNIndexStart[1] = name.RDNIndexEnd[1] = 1;

    strcpy (name.AVAValues[2], "Class 1 Assurance Level");
    name.AVATypes[2] = ATTRTYPE_ORGANIZATIONALUNITNAME;
    name.RDNIndexStart[2] = name.RDNIndexEnd[2] = 2;

    /* Note: multiplying the byte size by 8 to get the modulusBits only
         works because all 8 bits of the MSB are used. */
    return (EnableIssuer
            (ripemInfo, &name, VERISIGN_BETA_CLASS1_MODULUS,
             sizeof (VERISIGN_BETA_CLASS1_MODULUS),
             VERISIGN_BETA_CLASS1_EXPONENT,
	     sizeof (VERISIGN_BETA_CLASS1_EXPONENT),
             8 * sizeof (VERISIGN_BETA_CLASS1_MODULUS), 2,
	     state->digestAlgorithm, ripemDatabase));

  default:
    puts ("ERROR: Unrecognized selection.");
    return ((char *)NULL);
  }
}

static char *RenewCRL (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  char command[80], *errorMessage;
  unsigned int validityMonths;
  UINT4 now;
  
  puts ("This will renew the CRL issued by you.  This is useful if the CRL validity");
  puts ("  has expired.  Any revocation entries already in the CRL will be kept.");
  puts ("If you have never issued a CRL, this will create a new one.");
  
  GetInputLine
    (command, sizeof (command),
     "  Enter the number of months the new CRL will be valid, or blank to cancel:");

  if (! *command)
    /* User cancelled. */
    return ((char *)NULL);

  /* Set validityMonths to new value.  If sscanf doesn't return 1, it
       means junk was entered. */
  if (sscanf (command, "%u", &validityMonths) != 1) {
    puts ("You did not enter a number.  The CRL was not renewed.");
    return ((char *)NULL);
  }
  if (validityMonths == 0) {
    puts ("Validity months must be one or more.  The CRL was not renewed.");
    return ((char *)NULL);
  }

  /* Get the present time so we can compute the nextUpdate time and update
       the CRL. */
  R_time (&now);
  if ((errorMessage = RIPEMUpdateCRL
       (ripemInfo, now + (UINT4)validityMonths * SECONDS_IN_MONTH,
	(unsigned char *)NULL, 0, state->digestAlgorithm, ripemDatabase))
      != (char *)NULL)
    return (errorMessage);

  if (state->chainStatus.overall != 0) {
    puts ("The CRL has been renewed.  Since the certification status of the current user");
    puts ("  may have changed, you must use \"Select User\" to re-select the user's");
    puts ("  certificate chain.");
    /* Make the user view this message before continuing */
    GetInputLine (command, sizeof (command), "  Hit <ENTER> to continue:");
  
    /* Clear the current user from the state. */
    FreeList (&state->certChain);
    state->chainStatus.overall = 0;
  }

  return ((char *)NULL);
}

static char *PublishCRL (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  Base64Encoder encoder;
  char command[256], *errorMessage = (char *)NULL;
  FILE *stream = (FILE *)NULL;
  unsigned char *partOut;
  unsigned int partOutLen;
  
  Base64EncoderConstructor (&encoder);

  /* For error, break to end of do while (0) block. */
  do {
    if (state->usePKCSFormat) {
      puts ("This will publish the CRL issued by you as a PKCS certs-and-CRLs-only message");
      puts ("  in a file so that you can send it to other users.  This is useful only if");
      puts ("  other users trust you as a certification authority and need to know the");
      puts ("  status of users you certify.");
    }
    else {
      puts ("This will publish the CRL issued by you as a PEM CRL message in a file so that");
      puts ("  you can send it to other users.  This is useful only if other users trust");
      puts ("  you as a certification authority and need to know the status of users");
      puts ("  you certify.");
    }

    GetInputLine
      (command, sizeof (command),
       "  Enter the name of the output file for the CRL message, or blank to cancel:");

    if (! *command)
      /* User cancelled. */
      break;

    if ((stream = fopen (command, "w")) == (FILE *)NULL) {
      printf ("Cannot open %s for write.  Quitting.\n", command);
      break;
    }

    if (state->usePKCSFormat) {
      /* We base 64 encode the output.
       */
      Base64EncoderWriteInit (&encoder);
      if ((errorMessage = RIPEMCertsAndCRL_PKCSInit
           (ripemInfo, &partOut, &partOutLen)) != (char *)NULL)
        break;
      Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);

      /* No update is needed since we are not adding extra certs. */

      if ((errorMessage = RIPEMCertsAndCRL_PKCSFinal
           (ripemInfo, &partOut, &partOutLen, TRUE, TRUE, ripemDatabase))
          != (char *)NULL)
        break;
      Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);

      Base64EncoderWriteFinal (&encoder, stream);
    }
    else {
      /* Produce the output message.  We use MESSAGE_FORMAT_RIPEM1 instead of
           PEM because in a strict RFC 1422 environment, we wouldn't expect
           individual users to be making CRL messages. */
      if ((errorMessage = RIPEMPublishCRL
           (ripemInfo, &partOut, &partOutLen, MESSAGE_FORMAT_RIPEM1,
            ripemDatabase)) != (char *)NULL)
        break;

      fwrite (partOut, 1, partOutLen, stream);
    }
  } while (0);

  Base64EncoderDestructor (&encoder);
  if (stream != (FILE *)NULL)
    fclose (stream);
  return (errorMessage);
}

static char *OutputCertifyRequest (state, ripemInfo)
RCERTSState *state;
RIPEMInfo *ripemInfo;
{
  Base64Encoder encoder;
  RIPEMAttributes attributes;
  char command[256], challengePassword[256], *errorMessage = (char *)NULL,
    *message = "Here is my certificate.\n";
  FILE *stream = (FILE *)NULL;
  unsigned char *partOut;
  unsigned int partOutLen;
  
  Base64EncoderConstructor (&encoder);

  /* For error, break to end of do while (0) block. */
  do {
    if (state->usePKCSFormat) {
      puts ("This will output a PKCS #10 certification request which you can send to a");
      puts ("  certification authority to issue a certificate for you.");
    }
    else {
      puts ("This will output a PEM certification request (RFC 1424) which you can send to");
      puts ("  a PEM-compliant certification authority to issue a certificate for you.");
      puts ("  (Don't use this to make a message for another to receive in RIPEM");
      puts ("  \"validation mode\".  For that, simply send a signed message.)");
      if (ripemInfo->z.issuerChainCount > 0) {
        puts ("  *** Beware that you already have certificates issued for you by at least");
        puts ("  one issuing authority!  For PEM compliance, you should only request to be");
        puts ("  certified by one authority.");
      }
    }

    GetInputLine
      (command, sizeof (command),
       "  Enter the name of the output file for the request, or blank to cancel:");

    if (! *command)
      /* User cancelled. */
      break;

    if ((stream = fopen (command, "w")) == (FILE *)NULL) {
      printf ("Cannot open %s for write.  Quitting.\n", command);
      break;
    }

    if (state->usePKCSFormat) {
      InitRIPEMAttributes (&attributes);

      puts ("Some certification authorities require you to specify a challenge password.");
      GetInputLine
        (challengePassword, sizeof (challengePassword),
         "  Enter your challenge password, or blank for no challenge password:");
      if (*challengePassword) {
        attributes.haveChallengePassword = TRUE;
        attributes.challengePassword = challengePassword;
      }

      puts ("Some certification authorities require you to specify an unstructured name.");
      GetInputLine
        (command, sizeof (command),
         "  Enter the unstructured name, or blank for no unstructured name:");
      if (*command) {
        attributes.haveUnstructuredName = TRUE;
        attributes.unstructuredName = command;
      }

      /* We base 64 encode the output.
       */
      Base64EncoderWriteInit (&encoder);
      if ((errorMessage = RIPEMCertifyRequestPKCS
           (ripemInfo, &partOut, &partOutLen, &attributes))
          != (char *)NULL)
        break;
      Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);
      Base64EncoderWriteFinal (&encoder, stream);
    }
    else {
      if ((errorMessage = RIPEMEncipherInit
           (ripemInfo, MODE_MIC_ONLY, MESSAGE_FORMAT_PEM, DA_MD5, 0,
            (RecipientKeyInfo *)NULL, 0)) != (char *)NULL)
        break;
      if ((errorMessage = RIPEMEncipherDigestUpdate
           (ripemInfo, (unsigned char *)message, strlen (message)))
          != (char *)NULL)
        break;
      /* RIPEMDatabase is only needed for ENCRYPTED messages. */
      if ((errorMessage = RIPEMEncipherUpdate
           (ripemInfo, &partOut, &partOutLen, (unsigned char *)message,
            strlen (message), (RIPEMDatabase *)NULL))
          != (char *)NULL)
        break;
      fwrite (partOut, 1, partOutLen, stream);
      /* RIPEMDatabase is only needed for ENCRYPTED messages. */
      if ((errorMessage = RIPEMEncipherFinal
           (ripemInfo, &partOut, &partOutLen, (RIPEMDatabase *)NULL))
          != (char *)NULL)
        break;
      fwrite (partOut, 1, partOutLen, stream);
    }
  } while (0);

  /* Zeroize in case we had a challenge password */
  R_memset ((POINTER)command, 0, sizeof (command));
  R_memset ((POINTER)challengePassword, 0, sizeof (challengePassword));
  Base64EncoderDestructor (&encoder);
  if (stream != (FILE *)NULL)
    fclose (stream);
  return (errorMessage);
}

static char *ExportCerts (state, ripemInfo, ripemDatabase)
RCERTSState *state;
RIPEMInfo *ripemInfo;
RIPEMDatabase *ripemDatabase;
{
  Base64Encoder encoder;
  RIPEMDatabaseCursor cursor;
  TypList certs;
  char command[256], *errorMessage = (char *)NULL;
  FILE *stream = (FILE *)NULL;
  unsigned char *partOut;
  unsigned int partOutLen;
  BOOL found, exportAll;
  
  Base64EncoderConstructor (&encoder);
  RIPEMDatabaseCursorConstructor (&cursor);
  InitList (&certs);

  /* For error, break to end of do while (0) block. */
  do {
    puts ("");
    puts ("A - Export all certificates in the database...");
    puts ("S - Export the certificates of the currently-selected user...");

    GetInputLine
      (command, sizeof (command),
       "  Select which certificates to export (blank to cancel):");

    if (! *command)
      /* User cancel */
      break;

    if (*command == 'a' || *command == 'A')
      exportAll = TRUE;
    else if (*command == 's' || *command == 'S') {
      if (state->chainStatus.overall == 0) {
        puts ("First use \"Select user\" to select the user to export.");
        break;
      }

      exportAll = FALSE;
    }
    else {
      puts ("ERROR: Unrecognized selection.");
      break;
    }

    puts ("");

    if (state->usePKCSFormat) {
      if (exportAll) {
        puts ("This will create a PKCS certs-and-CRLs-only message containing your CRL as");
        puts ("  well as all of the certificates in your database.  Other users can");
        puts ("  receive this as a normal PKCS message.");
      }
      else {
        puts ("This will create a PKCS certs-and-CRLs-only message containing your CRL as");
        puts ("  well as the certificates of the currently-selected user.  Other users can");
        puts ("  receive this as a normal PKCS message.");
      }
    }
    else {
      if (exportAll) {
        puts ("This will create a PEM CRL message containing your CRL as well as all of the");
        puts ("  certificates in your database.  Other users can receive this as a normal");
        puts ("  PEM message.  Some PEM implementations may not accept a CRL message with");
        puts ("  \"extra certificates\", but RIPEM does.");
      }
      else {
        puts ("This will create a PEM CRL message containing your CRL, your certificates,");
        puts ("  as well as the certificates of the currently-selected user.  Other users");
        puts ("  can receive this as a normal PEM message.  Some PEM implementations may not");
        puts ("  accept a CRL message with \"extra certificates\", but RIPEM does.");
      }
    }

    GetInputLine
      (command, sizeof (command),
       "  Enter the name of the output file for the message, or blank to cancel:");

    if (! *command)
      /* User cancelled. */
      break;

    if ((stream = fopen (command, "w")) == (FILE *)NULL) {
      printf ("Cannot open %s for write.  Quitting.\n", command);
      break;
    }

    if (state->usePKCSFormat) {
      /* We base 64 encode the output.
       */
      Base64EncoderWriteInit (&encoder);
      if ((errorMessage = RIPEMCertsAndCRL_PKCSInit
           (ripemInfo, &partOut, &partOutLen)) != (char *)NULL)
        break;
      Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);

      if (exportAll) {
        /* Add all certs.
         */
        if ((errorMessage = RIPEMCertCursorInit
             (&cursor, (char *)NULL, ripemDatabase)) != (char *)NULL)
          break;
        while (1) {
          /* Make sure cert list is empty. */
          FreeList (&certs);

          if ((errorMessage = RIPEMCertCursorUpdate
               (&cursor, &found, &certs, ripemDatabase, ripemInfo))
              != (char *)NULL)
            break;
          if (!found)
            break;

          if ((errorMessage = RIPEMCertsAndCRL_PKCSUpdate
               (ripemInfo, &partOut, &partOutLen, &certs)) != (char *)NULL)
            break;
          Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);
        }
        if (errorMessage != (char *)NULL)
          /* broke loop because of error */
          break;
      }
      else {
        /* Just output the currently-selected user certs. */
              
        if ((errorMessage = RIPEMCertsAndCRL_PKCSUpdate
             (ripemInfo, &partOut, &partOutLen, &state->certChain))
            != (char *)NULL)
          break;
        Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);
      }

      /* Set includeSenderCerts false since we just included whatever
           certs we needed.  Go ahead and include the CRL even for just
           outputting the currently-selected user certs.
       */
      if ((errorMessage = RIPEMCertsAndCRL_PKCSFinal
           (ripemInfo, &partOut, &partOutLen, FALSE, TRUE, ripemDatabase))
          != (char *)NULL)
        break;
      Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, stream);

      Base64EncoderWriteFinal (&encoder, stream);
    }
    else {
      /* Produce the output message.  We use MESSAGE_FORMAT_RIPEM1 instead of
           PEM because in a strict RFC 1422 environment, we wouldn't expect
           individual users to be making CRL messages. */
      if ((errorMessage = RIPEMPublishCRLInit
           (ripemInfo, &partOut, &partOutLen, MESSAGE_FORMAT_RIPEM1,
            ripemDatabase)) != (char *)NULL)
        return (errorMessage);
      fwrite (partOut, 1, partOutLen, stream);

      if (exportAll) {
        /* Add all certs.
         */
        if ((errorMessage = RIPEMCertCursorInit
             (&cursor, (char *)NULL, ripemDatabase)) != (char *)NULL)
          break;
        while (1) {
          /* Make sure cert list is empty. */
          FreeList (&certs);

          if ((errorMessage = RIPEMCertCursorUpdate
               (&cursor, &found, &certs, ripemDatabase, ripemInfo))
              != (char *)NULL)
            break;
          if (!found)
            break;

          if ((errorMessage = RIPEMPublishCRLUpdate
               (ripemInfo, &partOut, &partOutLen, &certs)) != (char *)NULL)
            break;
          fwrite (partOut, 1, partOutLen, stream);
        }
        if (errorMessage != (char *)NULL)
          /* broke loop because of error */
          break;
      }
      else {
        /* Just output the currently-selected user certs. */
              
        if ((errorMessage = RIPEMPublishCRLUpdate
             (ripemInfo, &partOut, &partOutLen, &state->certChain))
            != (char *)NULL)
          break;
        fwrite (partOut, 1, partOutLen, stream);
      }
      
      if ((errorMessage = RIPEMPublishCRLFinal
           (ripemInfo, &partOut, &partOutLen)) != (char *)NULL)
        break;
      fwrite (partOut, 1, partOutLen, stream);
    }
  } while (0);

  Base64EncoderDestructor (&encoder);
  RIPEMDatabaseCursorDestructor (&cursor);
  FreeList (&certs);
  if (stream != (FILE *)NULL)
    fclose (stream);
  return (errorMessage);
}

/* Scan certList for a cert with the given subject name and public key.
   Return TRUE if found or FALSE if not.
   certStruct must already be allocated for convenience to this routine
     so it doesn't have to allocate it for each call.  This also assumes
     the certs in certList have already been decoded once so there is
     no decoding error.
 */
static BOOL FindSubjectPublicKey (certList, subject, publicKey, certStruct)
TypList *certList;
DistinguishedNameStruct *subject;
R_RSA_PUBLIC_KEY *publicKey;
CertificateStruct *certStruct;
{
  TypListEntry *entry;

  for (entry = certList->firstptr; entry; entry = entry->nextptr) {
    DERToCertificate
      ((unsigned char *)entry->dataptr, certStruct, (CertFieldPointers *)NULL);

    if (R_memcmp
        ((POINTER)&certStruct->subject, (POINTER)subject,
         sizeof (*subject)) == 0 &&
        R_memcmp
        ((POINTER)&certStruct->publicKey, (POINTER)publicKey,
         sizeof (*publicKey)) == 0)
      /* Found one */
      return (TRUE);
  }

  return (FALSE);
}

/* Convert a CERT_ validity status into a string such as "VALID".
 */
static char *CertStatusString (certStatus)
int certStatus;
{
  switch (certStatus) {
  case CERT_VALID:
    return ("VALID");
  case CERT_REVOCATION_UNKNOWN:
    return ("REVOCATION UNKNOWN");
  case CERT_PENDING:
    return ("PENDING");
  case CERT_EXPIRED:
    return ("EXPIRED");
  case CERT_CRL_EXPIRED:
    return ("CRL EXPIRED");
  case CERT_UNVALIDATED:
    return ("UNVALIDATED");
  case CERT_CRL_OUT_OF_SEQUENCE:
    return ("CRL OUT OF SEQUENCE");
  case CERT_REVOKED:
    return ("REVOKED");
    
  default:
    return ("UNRECOGNIZED TYPE");
  }
}

/* Enable the issuer given by name with a public key with the given
     modulus, exponent and modulusBits.  modulusLen and exponentLen
     are lengths in bytes, not bits.  Sign using digestAlgorithm.
   This creates a certificate for the issuer if the issuer isn't already
     validated.  Then this sets the chain length allowed to the given value.
 */
static char *EnableIssuer
  (ripemInfo, name, modulus, modulusLen, exponent, exponentLen,
   modulusBits, chainLenAllowed, digestAlgorithm, ripemDatabase)
RIPEMInfo *ripemInfo;
DistinguishedNameStruct *name;
unsigned char *modulus;
unsigned int modulusLen;
unsigned char *exponent;
unsigned int exponentLen;
unsigned int modulusBits;
unsigned int chainLenAllowed;
int digestAlgorithm;
RIPEMDatabase *ripemDatabase;
{
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  char *errorMessage = (char *)NULL, command[80];
  unsigned int validityMonths;
  unsigned char digest[MD5_LEN];

  /* For error, break to end of do while (0) block. */
  do {
    puts ("");
    puts ("This will create a certificate for the standard issuer.  If there is already");
    puts ("  a certificate with a current validity period (even if it is revoked), this");
    puts ("  will not create a new one.  Once enabled, the only way to disable the");
    puts ("  issuer is to set the its chain length allowed to zero, or to revoke it.");

    GetInputLine
      (command, sizeof (command),
       "  Enter the number of months the certificate will be valid, or blank to cancel:");

    if (! *command)
      /* User cancelled. */
      break;

    /* Set validityMonths to new value.  If sscanf doesn't return 1, it
         means junk was entered. */
    if (sscanf (command, "%u", &validityMonths) != 1) {
      puts ("You did not enter a number.  The issuer was not enabled.");
      break;
    }
    if (validityMonths == 0) {
      puts ("Validity months must be one or more.  The issuer was not enabled.");
      break;
    }

    /* Allocate the certStruct on the heap because it's big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    /* Copy in modulus and exponent, with zero padding in high bytes.
     */
    R_memset
      ((POINTER)&certStruct->publicKey, 0, sizeof (certStruct->publicKey));
    R_memcpy
      ((POINTER)(certStruct->publicKey.modulus +
                 (sizeof (certStruct->publicKey.modulus) -  modulusLen)),
       (POINTER)modulus, modulusLen);
    R_memcpy
      ((POINTER)(certStruct->publicKey.exponent +
                 (sizeof (certStruct->publicKey.exponent) - exponentLen)),
       (POINTER)exponent, exponentLen);
    certStruct->publicKey.bits = modulusBits;

    /* Copy the subject name and set the validity period */
    certStruct->subject = *name;
    R_time (&certStruct->notBefore);
    certStruct->notAfter =
      certStruct->notBefore + (UINT4)validityMonths * SECONDS_IN_MONTH;

    if ((errorMessage = ValidateAndWriteCert
         (ripemInfo, certStruct, digestAlgorithm, ripemDatabase))
	!= (char *)NULL) {
      if (strcmp (errorMessage, ERR_CERT_ALREADY_VALIDATED) == 0) {
        /* Intercept this error and don't treat as fatal. */
        puts ("You have already created a certificate for this issuer. To view this cert,");
        puts ("  do \"Select user\" again and choose \"D\" for selecting a direct certificate.");
        errorMessage = (char *)NULL;
      }
      break;
    }

    /* Set chain length allowed to the given value and save the
         preferences.
     */
    if ((errorMessage = GetPublicKeyDigest (digest, &certStruct->publicKey))
        != (char *)NULL)
      break;
    if ((errorMessage = SetChainLenAllowed
         (ripemInfo, digest, chainLenAllowed, ripemDatabase)) != (char *)NULL)
      break;
  } while (0);

  free (certStruct);
  return (errorMessage);
}

