/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/* Defines main for the RIPEM command line demo.
   Calls RIPEM "library" functions like DoEncipher.
 */

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef SVRV32
#include <sys/types.h>
#endif /* SVRV32 */
#include "global.h"
#include "rsaref.h"
#include "r_random.h"                              /* to get R_GenerateBytes */
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

typedef struct struct_user {
  char *emailaddr;                                          /* Email address */
  BOOL gotpubkey;                     /* =TRUE if we have his/her public key */
} TypUser;

typedef struct {
  BOOL addRecip, includeHeaders, prependHeaders, abortIfRecipUnknown,
    myselfAsRecip, useRndMessage, askDistinguishedName, binaryMessage,
    envelopedOnly;
} RIPEMFlags;

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

#define INPUT_BUFFER_SIZE 1024

#define SECONDS_IN_MONTH \
  ((UINT4)((UINT4)365 * (UINT4)24 * (UINT4)3600) / (UINT4)12)

static void MainEnd P((int stat));
static char *CrackCmd P((RIPEMFlags *, int, char **));
static char *CrackKeyServer P((char *));
static void ShowParams P((RIPEMFlags *));
static char *DoRandom P ((RIPEMInfo *));
static unsigned int GetPasswordToPrivKey
  P ((BOOL, BOOL, unsigned char *, unsigned int));
static char *OpenFiles P((RIPEMInfo *, BOOL));
static char *DoEncipherDriver
  P ((RIPEMInfo *, RIPEMFlags *, FILE *, FILE *, FILE *, enum enhance_mode,
      int, BOOL, int, int, TypList *, FILE *, RIPEMDatabase *));
static char *DoEncipherPKCSDriver
  P ((RIPEMInfo *, FILE *, FILE *, FILE *, enum enhance_mode, int, int,
      RecipientKeyInfo *, unsigned int, BOOL, BOOL, TypList *, BOOL, BOOL,
      RIPEMDatabase *));
static char *DoDecipherDriver
  P ((RIPEMInfo *, FILE *, FILE *, FILE *, int, int, unsigned int, BOOL, BOOL,
      BOOL, FILE *, RIPEMDatabase *));
static char *DoChangePWDriver
  P ((RIPEMInfo *, BOOL, char *, unsigned int, int, FILE *, RIPEMDatabase *));
static char *DoGenerateKeysDriver
  P ((RIPEMInfo *, BOOL, char *, unsigned int, unsigned int, int,
      unsigned char *, unsigned int, FILE *, RIPEMDatabase *));
static char *InitUser P((char *, TypUser **));
static char *GetCertStatusString P((int));
static char *AddUniqueUserToList P((TypUser *, TypList *));
static char *PrintCertNameAndDigest P((unsigned char *, FILE *));
static char *SetNewUserDN P((RIPEMInfo *, BOOL, char *));
static void SetPersonaName P((DistinguishedNameStruct *, char *));
static void SetEmailAddressName P((DistinguishedNameStruct *, char *));
static char *SetCustomizedName P((DistinguishedNameStruct *, char *));
static char *ReadInputLine P((char *, unsigned int, char *));
static void WritePrependedHeaders P((TypList *, FILE *));
static char *ReadPlaintextAlloc P((unsigned char **, unsigned int *));
static char *ReadEmailHeader P((FILE *, TypList *, TypList *));
static int IsWhitespace P((int));

#ifndef RIPEMSIG
static char *GetRecipientKeys
  P ((RIPEMInfo *, RecipientKeyInfo *, unsigned int *, RIPEMFlags *, FILE *,
      RIPEMDatabase *));
static BOOL CheckKeyList P((TypList *, int));
#endif

#ifdef __BORLANDC__
extern unsigned _stklen = 20000;  /* Increase stack size for Borland C */
#endif

extern char usage_msg_line1[];
extern char *usage_msg[];

char author[] = "Mark Riordan  1100 Parker  Lansing MI  48912";
char author2[] = 
  "mrr@scss3.cl.msu.edu or riordanmr@clvax1.cl.msu.edu   Sept 1992";

int Argc;
char **Argv;
FILE *InStream = NULL, *OutStream = NULL;
FILE *ExternalMessageStream = NULL;
TypList RecipientList, UserList;
char *InFileName = NULL, *OutFileName = NULL, *RandomFileName = NULL,
  *DebugFileName = NULL, *ExternalMessageFileName = NULL;
RIPEMDatabase RipemDatabase; 
int  RandomCmdIndex=0;
BOOL UseRndCmdLine=FALSE, UseRndFile=FALSE, UseRndKeyboard=FALSE;
BOOL UseRndSystem=FALSE;
int RandomStructInitialized = 0;
R_RANDOM_STRUCT *RandomStructPointer;                /* used by GetUserInput */
char *HomeDir = NULL;
int Bits=0;
int EncryptionAlgorithm=EA_DES_CBC;
int DigestAlgorithm=DA_MD5;
enum enum_action {ACT_NOT_SPEC, ACT_ENCRYPT, ACT_DECRYPT, ACT_GEN_KEY,
 ACT_CHANGE_PW} Action=ACT_NOT_SPEC;
enum enhance_mode EnhanceMode = MODE_ENCRYPTED;
int MessageFormat = MESSAGE_FORMAT_RIPEM1;
BOOL UsePKCSFormat = FALSE;
BOOL GotValidityMonths=FALSE;
int ValidityMonths = 12;
char *KeyToPrivKey = NULL, *NewKeyToPrivKey = NULL;
FILE *RandomStream = (FILE *)0;
char ErrMsgTxt[LINEBUFSIZE];
FILE *DebugStream = NULL;
FILE *CertInfoStream = NULL;
int Debug = 0;

#ifdef MACTC  /* rwo */
clock_t Time0, Time1;
#endif

#ifdef TESTDOS386
extern int ProcessorType(void);
int Got386 = 0;
#endif

int
main (argc,argv)
int argc;
char *argv[];
{
  RIPEMInfo ripemInfo;
  RIPEMFlags ripemFlags;
  BOOL needSelfSignedCert = FALSE;
  int j, status = 0;
  char *errorMessage, *cptr, password[MAX_PASSWORD_SIZE];
  unsigned int passwordLen;

  /* Set ripemInfo to initial state */
  RIPEMInfoConstructor (&ripemInfo);

#ifdef MACTC
  setvbuf(stderr, NULL, _IONBF, 0);
  fprintf(stderr, "Off we go...\n");
  argc = ccommand(&argv);
  Time0 = clock();
#endif

  Argc = argc;
  Argv = argv;

  RIPEMDatabaseConstructor (&RipemDatabase);
  InitList (&UserList);
  
#ifdef TESTDOS386
  Got386 = (ProcessorType() >= 3);
#endif

  /* For error, break to end of do while (0) block. */
  do {
    /* Append the RIPEM_VERSION to the end of the first usage message line
         so it will appear if we have to print the usage. */
    strcat (usage_msg_line1, RIPEM_VERSION);

    /* Parse the command line. */
    if ((errorMessage = CrackCmd (&ripemFlags, argc, argv)) != (char *)NULL) {
      usage(errorMessage,usage_msg);
      status = 4;
      break;
    }

    /* Open files.  Set ripemInfo.debugStream after this opens it. */
    if ((errorMessage = OpenFiles
         (&ripemInfo, ripemFlags.binaryMessage)) != (char *)NULL) {
      fprintf(stderr,"%s\n",errorMessage);
      status = 3;
      break;
    }
    
    if (Debug > 1)
      ShowParams (&ripemFlags);

    /* Obtain "random" data from various sources and initialize
     * random structure with it.
     */
    if(Action != ACT_DECRYPT) {
      if ((errorMessage = DoRandom (&ripemInfo)) != (char *)NULL) {
        fprintf(stderr,"%s\n",errorMessage);
        status = 3;
        break;
      }
    }

    /* Clear the parameters so that users typing "ps" or "w" can't
     * see what parameters we are using.
     */

    for(j=1; j<argc; j++) {
      cptr = argv[j];
      while(*cptr) *(cptr++) = '\0';
    }

    /* Get down to business and do the action requested of us. */
    ripemInfo.z.usernameAliases = &UserList;
  
    /* Get the password.  Prompt twice if generating. */
    passwordLen = GetPasswordToPrivKey
      (Action == ACT_GEN_KEY, FALSE, (unsigned char *)password,
       sizeof (password));

    if (Action != ACT_GEN_KEY) {
      /* Need to log in for all actions other than key generation.  Log in
           the user and load the preferences, checking for special errors.
         Use the first name in UserList as the one to log in by.
       */
      if ((errorMessage = RIPEMLoginUser
           (&ripemInfo, (char *)UserList.firstptr->dataptr, &RipemDatabase,
            (unsigned char *)password, passwordLen)) != (char *)NULL) {
        if (Action == ACT_CHANGE_PW &&
            !strcmp (errorMessage, ERR_SELF_SIGNED_CERT_NOT_FOUND))
          /* No self-signed cert, but we are trying to use change password
               to upgrade from RIPEM 1.1.  We will create a self-signed cert
               below. */
          needSelfSignedCert = TRUE;
        else if (strcmp (errorMessage, ERR_PREFERENCES_NOT_FOUND) == 0) {
          /* This is OK, just issue a warning.
             Give the warning even if Debug is 0 since it may mean the
               preferences has been unexpectedly deleted. */
          fputs ("Warning: User preferences were not found.  RIPEM will use defaults.\n", CertInfoStream);
          errorMessage = (char *)NULL;
        }
        else if (strcmp (errorMessage, ERR_PREFERENCES_CORRUPT) == 0) {
          /* Issuer alert and continue.
             Give the alert even if Debug is 0 since it may mean the
               preferences has been unexpectedly deleted. */
          fputs ("ALERT: Preference information has been corrupted.  RIPEM will use defaults.\n", CertInfoStream);
          errorMessage = (char *)NULL;
        }
        else {
          /* Other errors. */
          fputs(errorMessage,stderr);
          fputc('\n',stderr);
          status = 1;
          break;
        }
      }
    }

    if(Action == ACT_ENCRYPT) {
      errorMessage = DoEncipherDriver
        (&ripemInfo, &ripemFlags, InStream, OutStream, ExternalMessageStream,
         EnhanceMode, MessageFormat, UsePKCSFormat, DigestAlgorithm,
	 EncryptionAlgorithm, &RecipientList, CertInfoStream, &RipemDatabase);
    } else if(Action == ACT_DECRYPT){
      errorMessage = DoDecipherDriver
        (&ripemInfo, InStream, OutStream, ExternalMessageStream,
         DigestAlgorithm, GotValidityMonths, ValidityMonths,
         ripemFlags.prependHeaders, UsePKCSFormat, ripemFlags.binaryMessage,
         CertInfoStream, &RipemDatabase);
      if (errorMessage != (char *)NULL &&
          strcmp (errorMessage, ERR_NO_PEM_HEADER_BEGIN) == 0) {
        /* This can only be returned from RIPEMDecipherFinal.  If we
             are reading the message from a file, rewind and try to
             read it as a PKCS message. */
        if (InStream != stdin) {
          fseek (InStream, 0L, 0);
          errorMessage = DoDecipherDriver
            (&ripemInfo, InStream, OutStream, ExternalMessageStream,
             DigestAlgorithm, GotValidityMonths, ValidityMonths,
             ripemFlags.prependHeaders, TRUE, ripemFlags.binaryMessage,
             CertInfoStream, &RipemDatabase);
        }
      }
    } else if(Action == ACT_CHANGE_PW) {
      errorMessage = DoChangePWDriver
        (&ripemInfo, needSelfSignedCert, (char *)UserList.firstptr->dataptr,
         ValidityMonths, DigestAlgorithm, CertInfoStream, &RipemDatabase);
    } else {
      errorMessage = DoGenerateKeysDriver
        (&ripemInfo, ripemFlags.askDistinguishedName,
         (char *)UserList.firstptr->dataptr, Bits, ValidityMonths,
	 DigestAlgorithm, (unsigned char *)password, passwordLen,
	 CertInfoStream, &RipemDatabase);
    }

    if(errorMessage) {
      fputs(errorMessage,stderr);
      fputc('\n',stderr);
      status = 1;
      break;
    }
    status = ripemInfo.z.used_pub_key_in_message;
  } while (0);
      
  R_memset ((POINTER)password, 0, sizeof (password));
  if (KeyToPrivKey)
    R_memset ((POINTER)KeyToPrivKey, 0, strlen (KeyToPrivKey));
  if (NewKeyToPrivKey)
    R_memset ((POINTER)NewKeyToPrivKey, 0, strlen (NewKeyToPrivKey));
  RIPEMInfoDestructor (&ripemInfo);
  RIPEMDatabaseDestructor (&RipemDatabase);

  MainEnd (status);
  
  /*NOTREACHED*/
  return (0);  /* to shut up compiler warnings */
}

/*--- function MainEnd ------------------------------------------
 *
 *  End the program and return a returncode to the system.
 */
static void 
MainEnd(stat) 
int stat;
{
#ifdef MACTC
  double x;
  (void)fflush((FILE *)NULL);
  Time1 = clock();
  x = (Time1 - Time0)/60.0;
  fprintf(stderr, "Exit %d; Elapsed : %5.2f seconds.", stat, x);
#endif
  exit(stat);
}
  
/*--- function CrackCmd ---------------------------------------------------
 *
 *  Parse the command line.
 *
 *  Entry   argc     is the usual argument count.
 *          argv     is the usual vector of pointers to arguments.
 *
 *  Exit    Returns the address of a string if an error occurred,
 *            else NULL is returned and some subset of the following
 *            global variables has been set:
 *
 *    encipher       = TRUE if enciphering selected; FALSE for deciphering.
 *    recipient      is the name of the recipient (if enciphering).
 *    file_mode      indicates the mode of the input file (ASCII vs binary)
 *                   if enciphering.
 *    user_init_vec  is the desired initialization vector if specified.
 *    init_vec_size  is the number of bytes in user_init_vec, if specified.
 *    username       is the name of the user running the program.
 *    algorithm      is the desired encryption technique if enciphering.
 *    block_mode     is the block mode (CBC vs. ECB) if enciphering.
 *    prompt         = TRUE if we are to prompt the user for a "random"
 *                   string to help generate the message key.
 *    garble         is TRUE if the private key is encrypted, if deciphering.
 *    RipemDatabase.pubKeySource.filename
 *                   is the name of the public key file if encrypting.
 *    PrivFileSource.filename   is the name of the private key file.
 *    debug          is TRUE if debugging has been selected.
 *    infilename     is the name of the input file if specified.
 *                   Normally, standard input is used; this option was
 *                   implemented due to shortcomings in Microsoft's
 *                   Codeview, which was used during development.
 *    got_infilename is TRUE if the input file was specified explicitly.
 */
static char *CrackCmd (ripemFlags, argc, argv)
RIPEMFlags *ripemFlags;
int argc;
char *argv[];
{
  extern char *optarg;
  extern int optind, optsp;

  int got_action = FALSE;
  int got_username = FALSE;
  int got_key_to_priv_key = FALSE;
  BOOL cracking=TRUE;
  int j, ch, myargc[2], iarg, effectiveBits;
  char *errorMessage = NULL, *cptr, **myargv[2], *env_args;
  char *random_sources = "efms";
  char *key_sources = "sf";
  char *header_opts = "i";
  char *recip_opts = "m";
  TypUser *recipient;
  char *usernameStr, *key_server_str=NULL;
  TypList mylist;
  TypListEntry *entry;

  InitList (&mylist);

  /* Preset flags to FALSE */
  R_memset ((POINTER)ripemFlags, 0, sizeof (*ripemFlags));

  /* We crack a command line twice:  
   * First, we crack the pseudo-command line in the environment variable
   *   RIPEM_ARGS (if any).  This environment variable exists to make it
   *   easy for users who don't want to type the otherwise lengthy
   *   RIPEM command line, and is an alternative to the other individual 
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
    while(cracking &&
          (ch = mygetopt
           (myargc[iarg],myargv[iarg],
            "3edgGcBr:h:b:A:R:p:s:P:S:m:M:u:k:K:i:o:D:F:Z:C:y:Y:T:v:H:x:a:"))
          != -1) {
      switch (ch) {
        case '?':
          return ("Unrecognized command line option.");
                      
        /* Program modes */
        case 'd':    /* Decipher */
          Action = ACT_DECRYPT;
          got_action++;
          break;

        case 'e':       /* Encipher */
          Action = ACT_ENCRYPT;
          got_action++;
          break;

        case 'g':       /* Generate keypair */
          Action = ACT_GEN_KEY;
          got_action++;
          break;
          
        case 'G':    /* Generate keypair, prompting for a distinguished name */
          Action = ACT_GEN_KEY;
          ripemFlags->askDistinguishedName = TRUE;
          got_action++;
          break;
          
        case 'c':   /* Change key to private key */
          Action = ACT_CHANGE_PW;
          got_action++;
          break;

        /* Names (email addresses) of users */
        case 'r':
          /* Store the name of another recipient.  */
          InitUser(optarg,&recipient);
          cptr = AddUniqueUserToList(recipient,&RecipientList);
          if(cptr) return cptr;
          break;
          
        case 'T':   /* Flags governing recipient processing */
          StrCopyAlloc(&recip_opts,optarg);
          break;

        case 'h':       /* Flags governing message headers */
          /* See processing of this string below.
           */
          StrCopyAlloc(&header_opts,optarg);
          break;

        case 'u':       /* My username */
          StrCopyAlloc(&usernameStr,optarg);
          got_username = TRUE;
          break;

        case '3':       /* short for -A des-ede-cbc */
          /* Note that PKCS will use EA_DES_EDE3_CBC */
          EncryptionAlgorithm = EA_DES_EDE2_CBC;
          break;

        case 'A':       /* symmetric cipher */
          EncryptionAlgorithm = -1;
          if (!strcmp(optarg, "des-cbc"))
            EncryptionAlgorithm = EA_DES_CBC;
          if (!strcmp(optarg, "des-ede-cbc"))
            /* Note that PKCS will use EA_DES_EDE3_CBC */
            EncryptionAlgorithm = EA_DES_EDE2_CBC;
          if (!strncmp(optarg, "rx2-cbc/", 7)) {
            /* Try to read the effective bits */
            effectiveBits = atoi (optarg + 8);
	    if (effectiveBits < 1 || effectiveBits > 1023)
	      return ("rx2-cbc effective bits must be 1 <= bits <= 1023");

            EncryptionAlgorithm = EA_RX2_CBC (effectiveBits);
	  }
          if (EncryptionAlgorithm < 0)
    return ("Symmetric cipher must be \"des-cbc\", \"des-ede-cbc\" or \"rx2-cbc/bits\".");
          break;

        case 'a':
          /* digest algorithm. */
          DigestAlgorithm = -1;
          if (!strcmp (optarg, "rsa-md2"))
            DigestAlgorithm = DA_MD2;
          else if (!strcmp (optarg, "rsa-md5"))
            DigestAlgorithm = DA_MD5;
          else if (!strcmp (optarg, "sha-1"))
            DigestAlgorithm = DA_SHA1;

          if (DigestAlgorithm < 0)
            return ("Digest algorithm must be either \"rsa-md2\", \"rsa-md5\" or \"sha-1\".");
          break;

        case 'm':       /* Encryption mode */
          if (CaseIgnoreEqual (optarg, "encrypted"))
            EnhanceMode = MODE_ENCRYPTED;
          else if (CaseIgnoreEqual (optarg, "enveloped-only")) {
            /* Keep EnhanceMode as MODE_ENCRYPTED since a lot of code checks
                 this and does all the right things to find recipients, etc.
                 But set envelopedOnly also. */
            EnhanceMode = MODE_ENCRYPTED;
            ripemFlags->envelopedOnly = TRUE;
          }
          else if (CaseIgnoreEqual (optarg, "mic-only"))
            EnhanceMode = MODE_MIC_ONLY;
          else if (CaseIgnoreEqual (optarg, "mic-clear"))
            EnhanceMode = MODE_MIC_CLEAR;
          else
            return
("Processing mode must be encrypted, mic-only, mic-clear, or enveloped-only.");

          break;

        case 'M':       /* Message format */
          if (CaseIgnoreEqual (optarg, "ripem1"))
            MessageFormat = MESSAGE_FORMAT_RIPEM1;
          else if (CaseIgnoreEqual (optarg, "pem"))
            MessageFormat = MESSAGE_FORMAT_PEM;
          else if (CaseIgnoreEqual (optarg, "pkcs")) {
            MessageFormat = 0;
            UsePKCSFormat = TRUE;
          }
          else
            return
             ("Message format must be one of \"ripem1\" \"pem\" or \"pkcs\".");

          break;

        case 'b':       /* Number of bits in generated key */
          Bits = atoi(optarg);
          if(Bits < MIN_RSA_MODULUS_BITS || Bits > MAX_RSA_MODULUS_BITS) {
            sprintf(ErrMsgTxt,"Number of bits must be %d <= bits <= %d",
                    MIN_RSA_MODULUS_BITS,MAX_RSA_MODULUS_BITS);
            return (ErrMsgTxt);
          }
          break;

        case 'v':                 /* Number of months to validate sender for */
          ValidityMonths = atoi (optarg);
          if (ValidityMonths <= 0)
            return ("Validity months must be > 0");
          else
            GotValidityMonths = TRUE;
          break;

        case 'p':       /* Public key filename */
          if ((errorMessage = AddKeySourceFilename
               (&RipemDatabase.pubKeySource, optarg)) != (char *)NULL)
            return (errorMessage);
          break;
          
        case 'P':       /* Public key output filename */
          return ("-P is obsolete. Public keys are written to \"pubkeys\" in the RIPEM home dir.");

        case 's':       /* Secret (private) key filename */
          if ((errorMessage = AddKeySourceFilename
               (&RipemDatabase.privKeySource, optarg)) != (char *)NULL)
            return (errorMessage);
          break;
          
        case 'S':       /* Private key output filename */
          return ("-S is obsolete. Private keys are written to \"privkey\" in the RIPEM home dir.");

        case 'y':       /* Name of public key server */
          StrCopyAlloc(&key_server_str,optarg);
          break;

        case 'Y':       /* Order of sources for keys (server vs. file) */
          StrCopyAlloc(&key_sources,optarg);
          break;

        case 'k':       /* Key to private key */
          StrCopyAlloc((char **)&KeyToPrivKey,optarg);
          got_key_to_priv_key = TRUE;
          break;

        case 'K':       /* New key to private key for changing password */
          StrCopyAlloc((char **)&NewKeyToPrivKey,optarg);
          break;

        case 'H':       /* RIPEM home directory */
          StrCopyAlloc ((char **)&HomeDir, optarg);
          break;

        case 'i':       /* Input file */
          StrCopyAlloc(&InFileName,optarg);
          break;

        case 'o':       /* Output file */
          StrCopyAlloc(&OutFileName,optarg);
          break;

        case 'x':       /* External message file file */
          StrCopyAlloc (&ExternalMessageFileName, optarg);
          break;

        case 'D':       /* Debug level */
          Debug = atoi(optarg);
          break;

        case 'Z':       /* Debug output file */
          StrCopyAlloc(&DebugFileName,optarg);
          break;

        case 'F':       /* Random input file */
          StrCopyAlloc(&RandomFileName,optarg);
          break;

        case 'R':       /* Sources of random data */
          StrCopyAlloc(&random_sources,optarg);
          break;

        case 'C':       /* Random command args */
          RandomCmdIndex = optind-1;
          cracking = FALSE;
          break;

        case 'B':       /* Binary message */
          ripemFlags->binaryMessage = 1;
          break;
      }
    }
  }

  /* Parse the -R argument string (sources of random info) */

  for(cptr=random_sources; *cptr; cptr++) {
    switch(*cptr) {
      case 'c':
        UseRndCmdLine = TRUE;
        break;
      case 'e':
        UseRndCmdLine = TRUE;
        RandomCmdIndex = 0;
        break;
      case 'f':
        UseRndFile = TRUE;
        break;
      case 'k':
        UseRndKeyboard = TRUE;
        break;
      case 'm':
        ripemFlags->useRndMessage = TRUE;
        break;
      case 's':
        UseRndSystem = TRUE;
        break;
      default:
        return ("-R option should be one or more of \"cefks\"");
    }
  }

  /* Parse the -Y argument string (sources of key info) */

  for(j=0; j<MAX_KEY_SOURCES; j++) {
    switch(key_sources[j]) {
      case 's':
      case 'S':
        RipemDatabase.pubKeySource.origin[j] = KEY_FROM_SERVER;
        break;

      case 'f':
      case 'F':
        RipemDatabase.pubKeySource.origin[j] = KEY_FROM_FILE;
        break;
        
      case 'g':
      case 'G':
        RipemDatabase.pubKeySource.origin[j] = KEY_FROM_FINGER;
        break;
    
      default:
        RipemDatabase.pubKeySource.origin[j] = KEY_FROM_NONE;
        break;
    }
  }
  
  /* Parse the -h option (how to process plaintext message headers) */
  
  for(cptr=header_opts; *cptr; cptr++) {
    switch(*cptr) {
      case 'r':
        ripemFlags->addRecip = TRUE;
        break;
      
      case 'i':
        ripemFlags->includeHeaders = TRUE;
        break;
        
      case 'p':
        ripemFlags->prependHeaders = TRUE;
        break;
        
      default:
        return ("-h option should be one or more of \"ipr\"");
    }
  }
  
  /* Parse the -T option (options for recipients) */
  
  for(cptr=recip_opts; *cptr; cptr++) {
    switch(*cptr) {
      case 'm':     /* Send a copy to myself */
        ripemFlags->myselfAsRecip = TRUE;
        break;
      
      case 'a':     /* Always abort if I can't find key for user */
        ripemFlags->abortIfRecipUnknown = TRUE;
        break;
        
      case 'n':     /* None of the above */
        ripemFlags->myselfAsRecip = FALSE;
        ripemFlags->abortIfRecipUnknown = FALSE;
        break;
        
      default:
        return ("-T option should be one or more of \"amn\"");
    }
  }

  /* If we don't have the RIPEM home dir yet, look for the environment
       variable. */
  if (!HomeDir) {
    GetEnvFileName (HOME_DIR_ENV, "", &HomeDir);
    if (*HomeDir == '\0')
      /* GetEnvFileName returned the "" */
      HomeDir = NULL;
  }

  /* Check for syntax error. */

  if (got_action != 1) {
    return ("Must specify one of -e, -d, -g, -c");
  }
  else if(Action==ACT_ENCRYPT && EnhanceMode==MODE_ENCRYPTED) {
    if (!RecipientList.firstptr && !ripemFlags->addRecip)
      return ("Must specify recipient(s) when enciphering.");
    if (ripemFlags->envelopedOnly && !UsePKCSFormat)
      return ("-m enveloped-only allowed only with -M pkcs");
  }
  else if(Action != ACT_ENCRYPT && RecipientList.firstptr != NULL)
    return ("-r should be specified only when enciphering.");
  else if(Action == ACT_ENCRYPT &&
          RipemDatabase.pubKeySource.origin[0] == KEY_FROM_NONE
          && RipemDatabase.pubKeySource.origin[1] == KEY_FROM_NONE)
    return ("Must specify at least one source of public keys.");
  
  /* Obtain the username if it wasn't specified. */

  if (!got_username)
    GetUserAddress (&usernameStr);
  
  /* Crack the username string (which can contain multiple aliases
   * separated by commas) into a list.
   */
  
  CrackLine(usernameStr,&UserList);

  /* Obtain the name of the public key server. */
  if(!key_server_str)
    GetEnvAlloc(SERVER_NAME_ENV,&key_server_str);

  errorMessage = CrackKeyServer (key_server_str);
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
           (&RipemDatabase.pubKeySource, (char *)entry->dataptr))
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
           (&RipemDatabase.privKeySource, (char *)entry->dataptr))
          != (char *)NULL)
        return (errorMessage);
    }
  }

  /* Obtain the name of the file containing random data. */
  if(UseRndFile && !RandomFileName) {
    GetEnvFileName(RANDOM_FILE_ENV,"",&RandomFileName);
    if (strlen (RandomFileName) == 0)
      RandomFileName = NULL;
  }
  
  /* Special processing for the key to the private key:
   * A key of - means to read the key to the private key
   * from standard input.
   */
  if(got_key_to_priv_key) {
    if(strcmp(KeyToPrivKey,"-")==0) {
#define PWLEN 256
      char line[PWLEN];

      fgets(line,PWLEN,stdin);
      StrCopyAlloc((char **)&KeyToPrivKey,line);
      for(cptr=KeyToPrivKey; *cptr; cptr++) {
        if(*cptr=='\n' || *cptr=='\r')
          *cptr='\0';
      }
    }
  }

  return ((char *)NULL);
}

/*--- function CrackKeyServer ----------------------------------------
 * 
 *  Function to help CrackCmd parse the list of key server names.
 *  The list is specified as a string (either in the -y option or
 *  in the RIPEM_KEY_SERVER env variable) that looks like:
 *
 *     domain_name[:port_num][,domain_name2[:port_num2]...
 *
 *  Entry:  keyServerStr  is a zero-terminated string that contains
 *                  one or more key server names as above,
 *                  or NULL.
 *
 *  Exit: RipemDatabase.pubKeySource  contains the cracked information.
 */
static char *
CrackKeyServer(keyServerStr)
char *keyServerStr;
{
  TypList name_list;
  TypListEntry *entry;
  TypServer *server_ent;
  char *cptr, *errmsg;
  
  InitList (&(RipemDatabase.pubKeySource.serverlist));
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
      errmsg = AddToList(NULL,server_ent,sizeof(TypServer),
       &(RipemDatabase.pubKeySource.serverlist));
      if(errmsg) return errmsg;
    }
  }
  return NULL;    
}

/*--- function ShowParams -------------------------------------
 *
 *  Display the values of various user-supplied options,
 *  defaults, filenames, etc., for debugging purposes.
 */
static void ShowParams (ripemFlags)
RIPEMFlags *ripemFlags;
{
  char *cptr;
  char *not_present = "<none>";
  int j;
  TypListEntry *entry;
#define IFTHERE(str) (str ? str : not_present)

  fprintf(DebugStream,"%s\n",usage_msg[0]);
  fprintf(DebugStream,"Action=");
  switch(Action) {
    case ACT_NOT_SPEC:
      cptr = "<none>";
      break;
    case ACT_ENCRYPT:
      cptr = "Encrypt";
      break;
    case ACT_DECRYPT:
      cptr = "Decrypt";
      break;
    case ACT_GEN_KEY:
      cptr = "Generate";
      break;
    case ACT_CHANGE_PW:
      cptr = "Change PW";
      break;
  }
  fprintf(DebugStream,"%s  ",cptr);
  fprintf(DebugStream,"Recipients=");
  fprintf(DebugStream,"\n");
  /* Username is the first of the aliases */
  fprintf(DebugStream,"Your Username=%s\n",
         UserList.firstptr ? (char *)UserList.firstptr->dataptr : not_present);
  fprintf(DebugStream,"List of aliases to your username: \n");
  for(entry=UserList.firstptr; entry; entry=entry->nextptr) {
    fprintf(DebugStream,"   %s\n",(char *)entry->dataptr);
  }
  
  if(Action==ACT_GEN_KEY) {
    fprintf(DebugStream,"Bits in gen key=%d  ",Bits);
  }
  if(Action==ACT_ENCRYPT) {
      fprintf(DebugStream,"Proc mode=\"%s\"", (EnhanceMode == MODE_ENCRYPTED) ?
              (ripemFlags->envelopedOnly ? "enveloped-only" : "encrypted")
              : (EnhanceMode == MODE_MIC_ONLY ? "mic-only" : "mic-clear"));
  }
  fprintf(DebugStream,"\n");

  fprintf(DebugStream,"Input=%s Output=%s\n",
          InFileName ? InFileName : "<stdin>",
          OutFileName ? OutFileName : "<stdout>");
  fprintf(DebugStream,"ExternalMessageFileName=%s\n",
          ExternalMessageFileName ? ExternalMessageFileName : "(none)");
  fprintf(DebugStream,"PubKeyFiles=");
  FORLIST(&RipemDatabase.pubKeySource.filelist);
    fprintf(DebugStream,"%s ",((TypFile *)dptr)->filename);
  ENDFORLIST;
  fprintf(DebugStream,"\n");
  fprintf(DebugStream,"PrivKeyFiles=");
  FORLIST(&RipemDatabase.privKeySource.filelist);
    fprintf(DebugStream,"%s ",((TypFile *)dptr)->filename);
  ENDFORLIST;
  fprintf(DebugStream,"\n");
  fprintf(DebugStream,"Home directory=%s\n",HomeDir ? HomeDir : "(None)");
  fprintf(DebugStream,"Sources of \"random\" data: ");
  if(UseRndCmdLine) {
    fprintf(DebugStream,"Command line, args %d-%d;\n ",
            RandomCmdIndex,Argc);
  }
  if(UseRndFile) fprintf(DebugStream,"File \"%s\"; ",IFTHERE(RandomFileName));
  if(UseRndKeyboard) fprintf(DebugStream,"Keyboard; ");
  if(ripemFlags->useRndMessage) fprintf(DebugStream,"Message; ");
  if(UseRndSystem) fprintf(DebugStream,"running System.");
  fprintf(DebugStream,"\n");

  if(UseRndCmdLine) {
    fprintf(DebugStream,"Random command-line arguments: ");
    for(j=RandomCmdIndex; j<Argc; j++) {
      fprintf(DebugStream,"%s ",Argv[j]);
    }
    fprintf(DebugStream,"\n");
  }

  fprintf(DebugStream, "Public key servers:\n");
  { TypServer *server_ent;
    TypListEntry *entry;
    
    for(entry=RipemDatabase.pubKeySource.serverlist.firstptr; entry; 
        entry=entry->nextptr) {
      server_ent = (TypServer *) entry->dataptr;
      if(server_ent->servername)
        fprintf(DebugStream,"   %s port %d\n",server_ent->servername,
                server_ent->serverport);
    }
  }
  fprintf(DebugStream,"Public key key sources (in order) = ");
  for(j=0; j<MAX_KEY_SOURCES; j++) {
    switch(RipemDatabase.pubKeySource.origin[j]) {
      case KEY_FROM_FILE:
        fprintf(DebugStream,"file ");
        break;
      case KEY_FROM_SERVER:
        fprintf(DebugStream,"server ");
        break;
      case KEY_FROM_FINGER:
        fprintf(DebugStream,"finger ");
        break;
      default:
        fprintf(DebugStream,"UNKNOWN");
        break;
    }
  }
  putc('\n',DebugStream);
}

/*--- function DoRandom ---------------------------------------
 *
 *  Assemble pseudo-random data from various locations and
 *  feed it into a R_RANDOM_STRUCT structure.
 *
 *  Entry: UseRndCmdLine     \
 *         UseRndFile         \
 *         UseRndKeyboard     / These tell which sources to use
 *         UseRndSystem      /  for random data
 *         RandomCmdIndex       "argv" index at which to start, if
 *                              using command line params as random.
 *          RandomStream        Stream pointer to random file, if any.
 *
 *   Exit:  RandomStruct    contains the init'ed random struct.
     Returns NULL for success, otherwise error string.
 */
static char *DoRandom (ripemInfo)
RIPEMInfo *ripemInfo;
{
#define RANBUFSIZE 1024
  unsigned char *ranbuf, *timebuf;
  int nbytes, ntimebytes, jarg, totbytes=0, getting_random=TRUE;
  char *errorMessage = (char *)NULL;

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate on heap since it is too big for the stack */
    if ((ranbuf = (unsigned char *)malloc (RANBUFSIZE))
        == (unsigned char *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }
    if ((timebuf = (unsigned char *)malloc (RANBUFSIZE))
        == (unsigned char *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    R_memset(ranbuf,0,RANBUFSIZE);

    /* RandomStruct is already initialized.
       Set up global variables accessed by GetUserInput */
    RandomStructInitialized = 1;
    RandomStructPointer = &ripemInfo->randomStruct;

    /* Because we use the random struct during the
      * process of obtaining random data, we seed it first
      * to avoid RE_NEED_RANDOM errors.
      */
    while(getting_random) {
      unsigned int nbytes_needed;

      R_GetRandomBytesNeeded(&nbytes_needed,&ripemInfo->randomStruct);
      if(nbytes_needed) {
        R_RandomUpdate(&ripemInfo->randomStruct,ranbuf,256);
      } else {
        getting_random = FALSE;
      }
    }

    /* If requested, obtain random info from the running system. */
    if(UseRndSystem) {
      nbytes = GetRandomBytes(ranbuf,RANBUFSIZE,ripemInfo);
      R_RandomUpdate(&ripemInfo->randomStruct,ranbuf,nbytes);
      totbytes += nbytes;
    }

    /* If requested, obtain random info from the user at the
      * keyboard.
      */
    if(UseRndKeyboard) {
      fprintf(stderr,"Enter random string: ");
      nbytes = ntimebytes = RANBUFSIZE;
      GetUserInput(ranbuf,&nbytes,timebuf,&ntimebytes,TRUE);
      R_RandomUpdate(&ripemInfo->randomStruct,ranbuf,nbytes);
      R_RandomUpdate(&ripemInfo->randomStruct,timebuf,ntimebytes);
      totbytes += nbytes+ntimebytes;
    }

    /* If requested, obtain random info from the command line
      * arguments.
      */
    if(UseRndCmdLine) {
      for(jarg=RandomCmdIndex; jarg<Argc; jarg++) {
        nbytes = strlen(Argv[jarg]);
        R_RandomUpdate
          (&ripemInfo->randomStruct,(unsigned char *)Argv[jarg], nbytes);
        totbytes += nbytes;
      }
    }

    /* If requested & available, read random information from
     * randomly-selected spots on the "random" file.
     */
    if(UseRndFile && RandomStream) {
      long int filesize, myoffset;
      int iterations;

      /* Find the size of the file by seeking to the end
       * and then finding out where we are.
       */
      fseek(RandomStream,0L,2);  /* seek to end of file */
      filesize = ftell(RandomStream);

      /* Figure out how many blocks to read. Do this by
       * computing a pseudo-random number from the information
       * seeded so far.
       */

      R_GenerateBytes(ranbuf,1,&ripemInfo->randomStruct);
      iterations = 1 + (ranbuf[0] & 7);
      if(Debug>1) {
        fprintf(DebugStream,"Random file: seeking to byte ");
      }

      while(iterations--) {
        R_GenerateBytes
          ((unsigned char *)&myoffset,sizeof(myoffset),
           &ripemInfo->randomStruct);
        if(myoffset<0) myoffset = (-myoffset);
        myoffset %= filesize;
        if(Debug>1) fprintf(DebugStream,"%ld ",myoffset);
        fseek(RandomStream,myoffset,0); /* seek to location */
        nbytes = fread(ranbuf,1,RANBUFSIZE,RandomStream);
        R_RandomUpdate(&ripemInfo->randomStruct,ranbuf,nbytes);
        totbytes += nbytes;
      }
      if(Debug>1) fprintf(DebugStream,"\n");
    }

    if(Debug>1) {
      fprintf(DebugStream,"%d bytes of pseudo-random data obtained.\n",
              totbytes);
    }
  } while (0);

  if (ranbuf != (unsigned char *)NULL) {
    R_memset (ranbuf, 0, RANBUFSIZE);
    free (ranbuf);
  }
  if (timebuf != (unsigned char *)NULL) {
    R_memset (timebuf, 0, RANBUFSIZE);
    free (timebuf);
  }

  return (errorMessage);
}

/*--- function GetPasswordToPrivKey ---------------------------------
 *
 *  Get the password to the encrypted private key.
 *
 *  Entry:  verify   is TRUE if we should prompt twice.
 *          new      is TRUE if it's a new password (change prompt)
 *          maxchars is the buffer size for password.
 *
 *  Exit:   password is the zero-terminated password.
 *
 *  Look for it in this order:
 *    Argument extracted from command line,
 *    value of environment variable,
 *    prompt user interactively.
 */
static unsigned int
GetPasswordToPrivKey (verify, new, password, maxchars)
BOOL verify;
BOOL new;
unsigned char *password;
unsigned int maxchars;
{
   unsigned int pw_len = 0;
   BOOL got_pw = FALSE;
   char *cptr;

  if (new) {
    if(NewKeyToPrivKey) {
      strncpy((char *)password,NewKeyToPrivKey,maxchars);
      pw_len = (unsigned int)strlen((char *)password);
      got_pw = TRUE;
    }
  }
  else {
   if(KeyToPrivKey) {
      strncpy((char *)password,KeyToPrivKey,maxchars);
      pw_len = (unsigned int)strlen((char *)password);
      got_pw = TRUE;
   }
  }

   if(!got_pw && !new) {
      GetEnvAlloc(KEY_TO_PRIVATE_KEY_ENV, &cptr);
      if(cptr && *cptr) {
         strncpy((char *)password,cptr,maxchars);
         pw_len = (unsigned int)strlen((char *)password);
         got_pw = TRUE;
      }
   }

   if(!got_pw) {
      if(new) {
         cptr = "Enter new password to private key: ";
      } else {
         cptr = "Enter password to private key: ";
      }
      pw_len = GetPasswordFromUser(cptr,verify,password,maxchars);
   }

   return pw_len;
}

/*--- function OpenFiles --------------------------------------
 *
 *  Open files for RIPEM.
 *
 *  Entry: binaryMessage determines if the message file is opened binary.
 *
 *  Exit:   InStream, OutStream, RandomStream, ExternalMessageStream contain
 *          file pointers to the
 *          corresponding files (or streams), if there's no error.
 *          DebugStream is opened and ripemInfo->debugStream is set to it.
 *          The RipemDatabase is initialized.
 *
 *          Returns NULL if no error, else address of error string.
 */
static char *OpenFiles (ripemInfo, binaryMessage)
RIPEMInfo *ripemInfo;
BOOL binaryMessage;
{
  char *errorMessage;
  FILE *stream;
        
  if(InFileName) {
    if (binaryMessage && Action == ACT_ENCRYPT)
      InStream = fopen (InFileName,"rb");
    else
      InStream = fopen (InFileName,"r");
    if(!InStream) {
      sprintf(ErrMsgTxt,"Can't open input file %s.",InFileName);
      return(ErrMsgTxt);
    }
  } else
    InStream = stdin;
  
  if(OutFileName) {
    if (binaryMessage && Action == ACT_DECRYPT)
      OutStream = fopen (OutFileName,"wb");
    else
      OutStream = fopen (OutFileName,"w");
    if(!OutStream) {
      sprintf(ErrMsgTxt,"Can't open output file %s.",OutFileName);
      return(ErrMsgTxt);
    }
  } else
    OutStream = stdout;

  if (ExternalMessageFileName) {
    /* The external message file is always read. */
    ExternalMessageStream =
      fopen (ExternalMessageFileName, binaryMessage ? "rb" : "r");
    if (!ExternalMessageStream) {
      sprintf (ErrMsgTxt, "Can't open external message file %s.",
               ExternalMessageFileName);
      return (ErrMsgTxt);
    }
  }
  
  if(DebugFileName) {
    DebugStream = fopen(DebugFileName,"w");
    if(!DebugStream) {
      sprintf(ErrMsgTxt,"Can't open debug file %s.",DebugFileName);
      return(ErrMsgTxt);
    }
  } else
    DebugStream = stderr;

  CertInfoStream = DebugStream;

  /* Set up debug info in ripemInfo */
  ripemInfo->debugStream = DebugStream;
  ripemInfo->debug = Debug;

  /* We now have a debug stream and the user's choice of home dir.
     Make sure the home dir exists and that it has an ending directory
       separator.  This will try to get a default name is none is specified
       yet.
   */
  if ((errorMessage = EstablishRIPEMHomeDir (&HomeDir, ripemInfo))
      != (char *)NULL)
    return (errorMessage);

  /* Now we have a home dir, so open the database. */
  if ((errorMessage = InitRIPEMDatabase
       (&RipemDatabase, HomeDir, ripemInfo)) != (char *)NULL)
    return (errorMessage);

  if (RandomFileName == (char *)NULL) {
    /* Random file has not been specified yet, so try to open randomin in
         home dir for read. If successful, use it.
     */
    if ((RandomFileName = (char *)malloc (strlen (HomeDir) + 9))
        == (char *)NULL)
      return (ERROR_MALLOC);
    strcpy (RandomFileName, HomeDir);
    strcat (RandomFileName, "randomin");
    
    if ((stream = fopen (RandomFileName, "r")) != (FILE *)NULL)
      /* The randomin file was opened, so close it to be opened later. */
      fclose (stream);
    else {
      /* There is no randomin, so get rid of RandomFileName */
      free (RandomFileName);
      RandomFileName = (char *)NULL;
    }
  }

  if(Action != ACT_DECRYPT && UseRndFile) {
    if(RandomFileName) {
      RandomStream = fopen(RandomFileName,"r");
      if(!RandomStream) {
        sprintf(ErrMsgTxt,
                "Can't open random data file \"%s\".",RandomFileName);
        return(ErrMsgTxt);
      } else {
#ifdef MSDOS
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#ifdef __GNUC__
        _setmode(fileno(RandomStream),O_BINARY);
#else
#ifdef __TURBOC__
#define _setmode setmode
#define _fileno fileno
#endif
        _setmode(_fileno(RandomStream),O_BINARY);
#endif
#endif
      }
    }
  }
  
  return ((char *)NULL);
}

/* Do processing on recipient list and email headers.  Then call DoEncipher.
   recipientList is a list of TypUser.  If addRecip in ripemFlags is set, this
     modifies recipientList by adding recipients from the email header.
   If usePKCSFormat is TRUE, this ignores messageFormat and uses
     PKCS_SIGNED|PKCS_ENVELOPED if enhanceMode is MODE_ENCRYPTED with
     ripemFlags->envelopedOnly FALSE, PKCS_ENVELOPED if enhanceMode is
     MODE_ENCRYPTED with ripemFlags->envelopedOnly TRUE, otherwise
     PKCS_SIGNED.  For PKCS, this uses EA_DES_EDE3_CBC if encryptionAlgorithm
     was set to EA_DES_EDE2_CBC.
   If externalMessageStream is set, this makes sure this is a PKCS
     signed message.  inStream is ignored and outStream gets the
     detached signature data.
 */
static char *DoEncipherDriver
  (ripemInfo, ripemFlags, inStream, outStream, externalMessageStream,
   enhanceMode, messageFormat, usePKCSFormat, digestAlgorithm,
   encryptionAlgorithm, recipientList, certInfoStream, ripemDatabase)
RIPEMInfo *ripemInfo;
RIPEMFlags *ripemFlags;
FILE *inStream;
FILE *outStream;
FILE *externalMessageStream;
enum enhance_mode enhanceMode;
int messageFormat;
BOOL usePKCSFormat;
int digestAlgorithm;
int encryptionAlgorithm;
TypList *recipientList;
FILE *certInfoStream;
RIPEMDatabase *ripemDatabase;
{
  BOOL useHeaderList, useReadEmailHeader = FALSE;
  unsigned char *partOut, *plaintext = (unsigned char *)NULL;
  unsigned int partOutLen, plaintextLen;
  char *errorMessage, *line = (char *)NULL;
  RecipientKeyInfo *recipientKeys = (RecipientKeyInfo *)NULL;
  unsigned int recipientKeyCount = 0;
  TypList headerList, recipientNames;
  TypListEntry *entry;
#ifndef RIPEMSIG
  unsigned int usernameCount;
  TypUser *recipient;
#endif

#ifdef RIPEMSIG
UNUSED_ARG (recipientList)
UNUSED_ARG (certInfoStream)
UNUSED_ARG (ripemDatabase)
#endif
  
  /* Set to initial state so it is OK to free on error at any time. */
  InitList (&headerList);
  InitList (&recipientNames);

  /* For error, break to end of do while (0) block. */
  do {
    if (externalMessageStream != (FILE *)NULL) {
      if (!usePKCSFormat) {
        errorMessage = "External message text not supported for PEM format";
        break;
      }
      if (enhanceMode == MODE_ENCRYPTED) {
        errorMessage =
          "External message text only supported for signed messages.";
        break;
      }

      /* Ignore the given value for inStream and set it to
           externalMessageStream for reading any header lines.
           (It's not clear that looking for header lines makes any
           sense for a PKCS detached message but do it anyway.) */
      inStream = externalMessageStream;
    }

    if (ripemFlags->includeHeaders && !ripemFlags->addRecip &&
        !ripemFlags->prependHeaders)
      /* includeHeaders is set, but we don't need to add recipients or
           prepend the headers.  This means DoEncipher should just read the
           whole text as is without interpreting any part of it as a header. */
      useHeaderList = FALSE;
    else {
      /* Process the email header.  Note that if none of includeHeaders,
           prependHeaders or addRecip is set, this has the effect of omitting
           the email header from the message. */
      if ((errorMessage = ReadEmailHeader
           (inStream,
            (ripemFlags->includeHeaders || ripemFlags->prependHeaders) ?
            &headerList : (TypList *)NULL,
            ripemFlags->addRecip ? &recipientNames : (TypList *)NULL))
          != (char *)NULL)
        break;
      useReadEmailHeader = TRUE;
      useHeaderList = ripemFlags->includeHeaders;
    }
#ifndef RIPEMSIG
    if (enhanceMode == MODE_ENCRYPTED) {
      if (ripemFlags->addRecip) {
        /* The recipients in the email header were put in recipientNames,
             so explicitly add them to recipentList now.
         */
        for (entry = recipientNames.firstptr; entry;
             entry = entry->nextptr) {
          if ((errorMessage = InitUser ((char *)entry->dataptr, &recipient))
              != (char *)NULL)
            break;
          if ((errorMessage = AddUniqueUserToList (recipient, recipientList))
              != (char *)NULL) {
            /* Free the recipient that we just allocated */
            free (recipient);
            break;
          }
        }
        if (errorMessage != (char *)NULL)
          break;
      }
      /* Print recipients to debug stream and also get count.
       */
      usernameCount = 0;
      if (ripemInfo->debug > 1)
        fprintf (ripemInfo->debugStream, "Recipients: ");
      for (entry = recipientList->firstptr; entry;
           entry = entry->nextptr) {
        recipient = (TypUser *)entry->dataptr;
        if (ripemInfo->debug > 1)
          fprintf(ripemInfo->debugStream,"%s,", recipient->emailaddr);
        ++usernameCount;
      }
      if (ripemInfo->debug > 1)
        fprintf
        (ripemInfo->debugStream, "%d Total Recipients\n", usernameCount);
      
      /* Allocate recipientKeys buffer. We are done using usernameCount,
           so increment it if there is an entry for myselfAsRecip.
       */
      if (ripemFlags->myselfAsRecip)
        ++usernameCount;
      if ((recipientKeys = (RecipientKeyInfo *)malloc
           (usernameCount * sizeof (*recipientKeys)))
          == (RecipientKeyInfo *)NULL) {
        errorMessage = ERROR_MALLOC;
        break;
      }
      if ((errorMessage = GetRecipientKeys
           (ripemInfo, recipientKeys, &recipientKeyCount, ripemFlags,
            certInfoStream, ripemDatabase)) != (char *)NULL)
        break;
    }
#endif

    /* Write the email headers before the message if requested. */
    if (ripemFlags->prependHeaders)
      WritePrependedHeaders (&headerList, outStream);

    if (usePKCSFormat) {
      /* Skip the rest of this function and do PKCS instead */
      if (encryptionAlgorithm == EA_DES_EDE2_CBC)
        /* PKCS uses EDE3, not EDE2 */
        encryptionAlgorithm = EA_DES_EDE3_CBC;

      errorMessage = DoEncipherPKCSDriver
        (ripemInfo, inStream, outStream, externalMessageStream, enhanceMode,
         digestAlgorithm,encryptionAlgorithm, recipientKeys, recipientKeyCount,
         ripemFlags->useRndMessage, useHeaderList, &headerList,
         ripemFlags->binaryMessage, ripemFlags->envelopedOnly, ripemDatabase);
      break;
    }

    /* Encipher with PEM message format */

    if (ripemFlags->binaryMessage) {
      errorMessage = "Binary message text not supported for PEM format";
      break;
    }

    /* Don't allocate the line buffer until we need it */
    if ((line = (char *)malloc (INPUT_BUFFER_SIZE)) == (char *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }
    
    if (inStream == stdin) {
      /* This is a special case since we can't rewind stdin.
         Read the entire remaining input into an allocated buffer and
           use this for enciphering. */
      if ((errorMessage = ReadPlaintextAlloc (&plaintext, &plaintextLen))
          != (char *)NULL)
        break;
    }

#ifndef RIPEMSIG
    /* If encrypting and useRndMessage is
         set, read some bytes from the message for random update.
       If reading from a file, remember to rewind.
     */
    if (enhanceMode == MODE_ENCRYPTED && ripemFlags->useRndMessage) {
      if (inStream == stdin)
        R_RandomUpdate (&ripemInfo->randomStruct, plaintext, plaintextLen);
      else {
        /* Don't bother about how many bytes fread returns, since we'll
             just feed the whole buffer to random update anyway. */
        fread (line, 1, INPUT_BUFFER_SIZE, inStream);
        R_RandomUpdate
          (&ripemInfo->randomStruct, (unsigned char *)line, INPUT_BUFFER_SIZE);

        /* Rewind and skip past the headers if necessary to reposition. */
        fseek (inStream, 0L, 0);
        if (useReadEmailHeader)
          ReadEmailHeader (inStream, (TypList *)NULL, (TypList *)NULL);
      }
    }
#endif
    
    /* Initialize the enhance process. */
#ifdef DOGETRUSAGE
    if (ripemInfo->debug > 1)
      ReportCPUTime ("Before RIPEMEncipherInit",ripemInfo);
#endif
    if ((errorMessage = RIPEMEncipherInit
         (ripemInfo, enhanceMode, messageFormat, digestAlgorithm,
	  encryptionAlgorithm, recipientKeys, recipientKeyCount))
	!= (char *)NULL)
      break;
#ifdef DOGETRUSAGE
    if (ripemInfo->debug > 1)
      ReportCPUTime ("After RIPEMEncipherInit",ripemInfo);
#endif

    /* Make first pass through input to digest the text.
     */
    if (useHeaderList) {
      /* Headers are included in the text, so digest them now.
       */
      for (entry = headerList.firstptr; entry; entry = entry->nextptr) {
        if ((errorMessage = RIPEMEncipherDigestUpdate
             (ripemInfo, (unsigned char *)entry->dataptr,
              strlen ((char *)entry->dataptr))) != (char *)NULL)
          break;

        if ((errorMessage = RIPEMEncipherDigestUpdate
             (ripemInfo, (unsigned char *)"\n", 1)) != (char *)NULL)
          break;
      }
      if (errorMessage != (char *)NULL)
        /* broke because of error */
        break;

      /* Add a blank line after the email header. */
      if ((errorMessage = RIPEMEncipherDigestUpdate
           (ripemInfo, (unsigned char *)"\n", 1)) != (char *)NULL)
        break;
    }

    /* Digest the input text.
     */
    if (inStream == stdin) {
      if ((errorMessage = RIPEMEncipherDigestUpdate
           (ripemInfo, plaintext, plaintextLen)) != (char *)NULL)
        break;
    }
    else {
      while (fgets (line, INPUT_BUFFER_SIZE, inStream)) {
        /* Line already includes the '\n', so digest.
         */
        if ((errorMessage = RIPEMEncipherDigestUpdate
             (ripemInfo, (unsigned char *)line, strlen (line)))
            != (char *)NULL)
          break;
      }
      if (errorMessage != (char *)NULL)
        /* broke because of error */
        break;

      /* Rewind for second pass.  If we used ReadEmailHeader above, we
           must call it again to skip past the header.
       */
      fseek (inStream, 0L, 0);
      if (useReadEmailHeader)
        ReadEmailHeader (inStream, (TypList *)NULL, (TypList *)NULL);
    }
    
    if (useHeaderList) {
      /* Headers are included in the text, so we must encipher them first.
       */
      for (entry = headerList.firstptr; entry; entry = entry->nextptr) {
        if ((errorMessage = RIPEMEncipherUpdate
             (ripemInfo, &partOut, &partOutLen,
              (unsigned char *)entry->dataptr,
              strlen ((char *)entry->dataptr), ripemDatabase)) != (char *)NULL)
          break;
        fwrite (partOut, 1, partOutLen, outStream);

        if ((errorMessage = RIPEMEncipherUpdate
             (ripemInfo, &partOut, &partOutLen, (unsigned char *)"\n", 1,
              ripemDatabase)) != (char *)NULL)
          break;
        fwrite (partOut, 1, partOutLen, outStream);
      }
      if (errorMessage != (char *)NULL)
        /* broke because of error */
        break;

      /* Encipher a blank line after the email header. */
      if ((errorMessage = RIPEMEncipherUpdate
           (ripemInfo, &partOut, &partOutLen, (unsigned char *)"\n", 1,
            ripemDatabase)) != (char *)NULL)
        break;
      fwrite (partOut, 1, partOutLen, outStream);
    }

    /* Encipher the input text.
     */
    if (inStream == stdin) {
      if ((errorMessage = RIPEMEncipherUpdate
           (ripemInfo, &partOut, &partOutLen, plaintext, plaintextLen,
            ripemDatabase)) != (char *)NULL)
        break;
      fwrite (partOut, 1, partOutLen, outStream);
    }
    else {
      while (fgets (line, INPUT_BUFFER_SIZE, inStream)) {
        /* Line already includes the '\n'.
         */
        if ((errorMessage = RIPEMEncipherUpdate
             (ripemInfo, &partOut, &partOutLen, (unsigned char *)line,
              strlen (line), ripemDatabase)) != (char *)NULL)
          break;
        fwrite (partOut, 1, partOutLen, outStream);
      }
      if (errorMessage != (char *)NULL)
        /* broke because of error */
        break;
    }

    /* Finalize and flush the output.
     */
    if ((errorMessage = RIPEMEncipherFinal
         (ripemInfo, &partOut, &partOutLen, ripemDatabase)) != (char *)NULL)
      break;
    fwrite (partOut, 1, partOutLen, outStream);
  } while (0);

  if (plaintext != (unsigned char *)NULL) {
    /* zeroize and free */
    R_memset ((POINTER)plaintext, 0, plaintextLen);
    free (plaintext);
  }
  if (line != (char *)NULL) {
    R_memset ((POINTER)line, 0, INPUT_BUFFER_SIZE);
    free (line);
  }
  free (recipientKeys);
  FreeList (&headerList);
  FreeList (&recipientNames);
  return (errorMessage);
}

/* This is a helper to DoEncipherDriver to process a PKCS message.
   Note that we can process an arbitary amount of data, even from stdin.
   If binaryMessage, assume inStream opened as "rb" and don't do translation.
     Otherwise, change '\n' to <CR><LF> because RIPEMEncipherPKCSUpdate
     processes the input "as is".  This assumes inStream is opened as "r".
   This base64 encodes the output.
   If useHeaderList is true, encipher the headerList before the text.
   encryptionAlgorithm must be one of the values required by
     RIPEMEncipherPKCSInit.
   If externalMessageStream is set, this makes sure this is a 
     signed message.  inStream is ignored and outStream gets the
     detached signature data.
   Returne NULL for success, otherwise error string.
 */
static char *DoEncipherPKCSDriver
  (ripemInfo, inStream, outStream, externalMessageStream, enhanceMode,
   digestAlgorithm, encryptionAlgorithm, recipientKeys, recipientKeyCount,
   useRndMessage, useHeaderList, headerList, binaryMessage, envelopedOnly,
   ripemDatabase)
RIPEMInfo *ripemInfo;
FILE *inStream;
FILE *outStream;
FILE *externalMessageStream;
enum enhance_mode enhanceMode;
int digestAlgorithm;
int encryptionAlgorithm;
RecipientKeyInfo *recipientKeys;
unsigned int recipientKeyCount;
BOOL useRndMessage;
BOOL useHeaderList;
TypList *headerList;
BOOL binaryMessage;
BOOL envelopedOnly;
RIPEMDatabase *ripemDatabase;
{
  Base64Encoder encoder;
  char *errorMessage = (char *)NULL;
  unsigned char *input = (unsigned char *)NULL, *partIn, *partOut,
    *inputEnd, *p;
  TypListEntry *entry;
  BOOL haveInput, foundLF;
  unsigned int inputLen, partInLen, partOutLen;
  int pkcsMode;

#ifdef RIPEMSIG
UNUSED_ARG (useRndMessage)
#endif

  Base64EncoderConstructor (&encoder);

  /* For error, break to end of do while (0) block. */
  do {
    if (externalMessageStream != (FILE *)NULL) {
      if (enhanceMode == MODE_ENCRYPTED) {
        errorMessage =
          "External message text only supported for signed messages.";
        break;
      }

      /* Ignore the given value for inStream and set it to
           externalMessageStream for reading input so that we can read from
           inStream for both detached and non-detached. */
      inStream = externalMessageStream;
    }

    if ((input = (unsigned char *)malloc (INPUT_BUFFER_SIZE))
        == (unsigned char *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    /* Read the first input now in case we need to use it for useRndMessage */
    inputLen = fread (input, 1, INPUT_BUFFER_SIZE, inStream);
    haveInput = TRUE;

#ifndef RIPEMSIG
    if (enhanceMode == MODE_ENCRYPTED && useRndMessage) {
      /* Use some random seeding from the header lines and the beginning
           of the text.
       */
      if (useHeaderList) {
        for (entry = headerList->firstptr; entry; entry = entry->nextptr)
          R_RandomUpdate
            (&ripemInfo->randomStruct, (unsigned char *)entry->dataptr,
             strlen ((char *)entry->dataptr));
      }
      
      R_RandomUpdate (&ripemInfo->randomStruct, input, inputLen);
    }
#endif

    Base64EncoderWriteInit (&encoder);

    if (externalMessageStream == (FILE *)NULL) {
      if (enhanceMode == MODE_ENCRYPTED) {
        if (envelopedOnly)
          pkcsMode = PKCS_ENVELOPED;
        else
          pkcsMode = PKCS_SIGNED | PKCS_ENVELOPED;
      }
      else
        pkcsMode = PKCS_SIGNED;
      if ((errorMessage = RIPEMEncipherPKCSInit
           (ripemInfo, &partOut, &partOutLen, pkcsMode, digestAlgorithm,
	    encryptionAlgorithm, recipientKeys, recipientKeyCount,
	    ripemDatabase)) != (char *)NULL)
        break;
      Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, outStream);
    }
    else {
      /* Init the detached signature */
      if ((errorMessage = RIPEMSignDetachedPKCSInit
           (ripemInfo, digestAlgorithm)) != (char *)NULL)
        break;
    }

    if (useHeaderList) {
      /* Headers are included in the text, so we must encipher them first.
       */
      for (entry = headerList->firstptr; entry; entry = entry->nextptr) {
        if (externalMessageStream == (FILE *)NULL) {
          if ((errorMessage = RIPEMEncipherPKCSUpdate
               (ripemInfo, &partOut, &partOutLen,
                (unsigned char *)entry->dataptr,
                strlen ((char *)entry->dataptr))) != (char *)NULL)
            break;
          Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, outStream);
        }
        else {
          /* Sign the header as detached text.  (The meaning of headers
               in a detached message is unclear but do it anyway.) */
          if ((errorMessage = RIPEMSignDetachedPKCSDigestUpdate
               (ripemInfo, (unsigned char *)entry->dataptr,
                strlen ((char *)entry->dataptr))) != (char *)NULL)
            break;
        }

        /* Do a <CR><LF> at the end of the line.  Do this regardless of
             the status of binaryMessage.  (The meaning of headers is unclear
             in binary messages anyway.)
         */
        if (externalMessageStream == (FILE *)NULL) {
          if ((errorMessage = RIPEMEncipherPKCSUpdate
               (ripemInfo, &partOut, &partOutLen, (unsigned char *)"\015\012",
                2)) != (char *)NULL)
            break;
          Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, outStream);
        }
        else {
          if ((errorMessage = RIPEMSignDetachedPKCSDigestUpdate
               (ripemInfo, (unsigned char *)"\015\012", 2)) != (char *)NULL)
            break;
        }
      }
      if (errorMessage != (char *)NULL)
        /* broke because of error */
        break;

      /* Encipher a blank line after the email header. */
      if (externalMessageStream == (FILE *)NULL) {
        if ((errorMessage = RIPEMEncipherPKCSUpdate
             (ripemInfo, &partOut, &partOutLen,(unsigned char *)"\015\012", 2))
            != (char *)NULL)
          break;
        Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, outStream);
      }
      else {
        if ((errorMessage = RIPEMSignDetachedPKCSDigestUpdate
             (ripemInfo, (unsigned char *)"\015\012", 2)) != (char *)NULL)
          break;
      }
    }

    /* Encipher the input text.
     */
    while (1) {
      if (haveInput)
        /* Already have the input.  Set to FALSE so we read it from now on. */
        haveInput = FALSE;
      else
        inputLen = fread (input, 1, INPUT_BUFFER_SIZE, inStream);

      if (binaryMessage) {
        /* The input file has been opened "rb" so just encipher it */
        if (externalMessageStream == (FILE *)NULL) {
          if ((errorMessage = RIPEMEncipherPKCSUpdate
               (ripemInfo, &partOut, &partOutLen, input, inputLen))
              != (char *)NULL)
            break;
          Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, outStream);
        }
        else {
          /* Process as detached message */
          if ((errorMessage = RIPEMSignDetachedPKCSDigestUpdate
               (ripemInfo, input, inputLen)) != (char *)NULL)
            break;
        }
      }
      else {
        /* Encipher while converting '\n' to <CR><LF> in the input */

        inputEnd = input + inputLen;
        for (partIn = input; partIn < inputEnd; partIn += partInLen) {
          /* Scan for a '\n'.
             This assumes that the input stream is opened with "r" so that
               end-of-line characters are converted to '\n' */
          foundLF = FALSE;
          for (p = partIn; p < inputEnd; ++p) {
            if (*p == '\n') {
              foundLF = TRUE;
              break;
            }
          }
          partInLen = p - partIn;

          if (externalMessageStream == (FILE *)NULL) {
            if ((errorMessage = RIPEMEncipherPKCSUpdate
                 (ripemInfo, &partOut, &partOutLen, partIn, partInLen))
                != (char *)NULL)
              break;
            Base64EncoderWriteUpdate(&encoder, partOut, partOutLen, outStream);
          }
          else {
            /* Process as detached message */
            if ((errorMessage = RIPEMSignDetachedPKCSDigestUpdate
                 (ripemInfo, partIn, partInLen)) != (char *)NULL)
              break;
          }

          if (foundLF) {
            /* We scanned up to a '\n', so encipher a <CR><LF> now. */
            if (externalMessageStream == (FILE *)NULL) {
              if ((errorMessage = RIPEMEncipherPKCSUpdate
                   (ripemInfo, &partOut, &partOutLen,
                    (unsigned char *)"\015\012", 2)) != (char *)NULL)
                break;
              Base64EncoderWriteUpdate(&encoder,partOut,partOutLen, outStream);
            }
            else {
              if ((errorMessage = RIPEMSignDetachedPKCSDigestUpdate
                   (ripemInfo, (unsigned char *)"\015\012", 2))
                  != (char *)NULL)
                break;
            }

            /* Skip the '\n'*/
            ++partInLen;
          }
        }
        if (errorMessage != (char *)NULL)
          /* Broke loop because of error */
          break;
      }

      if (inputLen < INPUT_BUFFER_SIZE)
        /* We didn't get all we asked for which means end of stream */
        break;
    }
    if (errorMessage != (char *)NULL)
      /* Broke loop because of error */
      break;

    if (externalMessageStream == (FILE *)NULL) {
      if ((errorMessage = RIPEMEncipherPKCSFinal
           (ripemInfo, &partOut, &partOutLen, (RIPEMAttributes *)NULL))
          != (char *)NULL)
        break;
    }
    else {
      /* The entire PKCS detached signature data is produced in this call. */
      if ((errorMessage = RIPEMSignDetachedPKCSFinal
           (ripemInfo, &partOut, &partOutLen, (RIPEMAttributes *)NULL))
          != (char *)NULL)
        break;
    }
    Base64EncoderWriteUpdate (&encoder, partOut, partOutLen, outStream);

    Base64EncoderWriteFinal (&encoder, outStream);
  } while (0);

  Base64EncoderDestructor (&encoder);
  if (input != (unsigned char *)NULL) {
    R_memset ((POINTER)input, 0, INPUT_BUFFER_SIZE);
    free (input);
  }

  return (errorMessage);
}

/* If externalMessageStream is not null, this requires a PKCS message and
     verifies the detached message using the given digestAlgorithm, and
     outStream is ignored.
   If externalMessageStream is null, digestAlgorithm is ignored.
 */
static char *DoDecipherDriver
  (ripemInfo, inStream, outStream, externalMessageStream, digestAlgorithm,
   validate, validityMonths, prependHeaders, usePKCSFormat, binaryMessage,
   certInfoStream, ripemDatabase)
RIPEMInfo *ripemInfo;
FILE *inStream;
FILE *outStream;
FILE *externalMessageStream;
int digestAlgorithm;
int validate;
unsigned int validityMonths;
BOOL prependHeaders;
BOOL usePKCSFormat;
BOOL binaryMessage;
FILE *certInfoStream;
RIPEMDatabase *ripemDatabase;
{
  TypList certChain;
  enum enhance_mode enhanceMode;
  int pkcsMode, i;
  char *errorMessage, *input = (char *)NULL, *messageType,
    signingTime[18];
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  ChainStatusInfo chainStatus;
  unsigned char *partOut, *decodedLine = (unsigned char *)NULL,
    *partOutEnd, *p, *inputEnd, *partIn;
  BOOL foundCR, foundLF;
  unsigned int partOutLen, decodedLineLen, inputLen, partInLen;
  UINT4 endValidity;
  RIPEMAttributes authenticatedAttributes;

  /* Set to initial state so it is OK to free on error at any time. */
  InitList (&certChain);

  do {
    if (externalMessageStream != (FILE *)NULL) {
      if (!usePKCSFormat) {
        errorMessage = "External message text not supported for PEM format";
        break;
      }
    }

    /* Allocate the certStruct on the heap since it is so big. */
    if ((certStruct = (CertificateStruct *)malloc (sizeof (*certStruct)))
        == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }
    if ((input = (char *)malloc (INPUT_BUFFER_SIZE)) == (char *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    if (usePKCSFormat) {
      /* decodedLine used only by PKCS */
      if ((decodedLine = (unsigned char *)malloc (INPUT_BUFFER_SIZE))
          == (unsigned char *)NULL) {
        errorMessage = ERROR_MALLOC;
        break;
      }

      if (externalMessageStream == (FILE *)NULL) {
        if ((errorMessage = RIPEMDecipherPKCSInit (ripemInfo))
            != (char *)NULL)
          break;
      }
      else {
        /* Initialize a detached signature verification. */
        if ((errorMessage = RIPEMVerifyDetachedPKCSInit
             (ripemInfo, digestAlgorithm)) != (char *)NULL)
          break;

        /* Now we must digest the detached message in the same manner
             in which it is done when signing it.
         */
        while (1) {
          inputLen = fread
            ((unsigned char *)input, 1, INPUT_BUFFER_SIZE,
             externalMessageStream);

          if (binaryMessage) {
            /* The input file has been opened "rb" so just digest it */
            if ((errorMessage = RIPEMVerifyDetachedPKCSDigestUpdate
                 (ripemInfo, (unsigned char *)input, inputLen))
                != (char *)NULL)
              break;
          }
          else {
            /* Digest while converting '\n' to <CR><LF> in the input */

            inputEnd = (unsigned char *)input + inputLen;
            for (partIn = input; partIn < inputEnd; partIn += partInLen) {
              /* Scan for a '\n'.
                 This assumes that the input stream is opened with "r" so that
                   end-of-line characters are converted to '\n' */
              foundLF = FALSE;
              for (p = partIn; p < inputEnd; ++p) {
                if (*p == '\n') {
                  foundLF = TRUE;
                  break;
                }
              }
              partInLen = p - partIn;

              if ((errorMessage = RIPEMVerifyDetachedPKCSDigestUpdate
                   (ripemInfo, partIn, partInLen)) != (char *)NULL)
                break;

              if (foundLF) {
                /* We scanned up to a '\n', so encipher a <CR><LF> now. */
                if ((errorMessage = RIPEMVerifyDetachedPKCSDigestUpdate
                     (ripemInfo, (unsigned char *)"\015\012", 2))
                    != (char *)NULL)
                  break;

                /* Skip the '\n'*/
                ++partInLen;
              }
            }
            if (errorMessage != (char *)NULL)
              /* Broke loop because of error */
              break;
          }

          if (inputLen < INPUT_BUFFER_SIZE)
            /* We didn't get all we asked for which means end of stream */
            break;
        }
        if (errorMessage != (char *)NULL)
          /* Broke loop because of error */
          break;
      }
    }
    else {
      if (binaryMessage) {
        errorMessage = "Binary message text not supported for PEM format";
        break;
      }

      if ((errorMessage = RIPEMDecipherInit (ripemInfo, prependHeaders))
          != (char *)NULL)
        break;
    }
    
    while (fgets (input, INPUT_BUFFER_SIZE, inStream)) {
      if (usePKCSFormat) {
        /* Strip whitespace off the end of the line.
         */
        for (i = strlen (input) - 1; i >= 0; --i) {
          if (IsWhitespace ((int)input[i]))
            input[i] = '\0';
          else
            break;
        }
        
        /* Decode into the decodedLine.  Note that this assumes that the
             input encoding has line lengths a multiple of 4.
         */
        if (R_DecodePEMBlock
            (decodedLine, &decodedLineLen, (unsigned char *)input,
             strlen (input)) != 0) {
          errorMessage = "Invalid base 64 encoding of input";
          break;
        }
        
        if (externalMessageStream == (FILE *)NULL) {
          if ((errorMessage = RIPEMDecipherPKCSUpdate
               (ripemInfo, &partOut, &partOutLen, decodedLine, decodedLineLen,
                ripemDatabase)) != (char *)NULL)
            break;

          if (binaryMessage)
            /* The output file has been opened "wb" so just write it */
            fwrite (partOut, 1, partOutLen, outStream);
          else {
            /* Now output the result, skipping over any '\r'.  Since outStream
                 is opened with "w", it will replace the remaining '\n' with
                 the local end-of-line characters.
             */
            partOutEnd = partOut + partOutLen;
            while (partOut < partOutEnd) {
              foundCR = FALSE;
              for (p = partOut; p < partOutEnd; ++p) {
                if (*p == '\r') {
                  foundCR = TRUE;
                  break;
                }
              }

              fwrite (partOut, 1, p - partOut, outStream);

              if (foundCR)
                /* Skip over the '\r' */
                ++p;

              partOut += (p - partOut);
            }
          }
        }
        else {
          /* Process the detached signature data.  There is no output. */
          if ((errorMessage = RIPEMVerifyDetachedPKCSUpdate
               (ripemInfo, decodedLine, decodedLineLen, ripemDatabase))
              != (char *)NULL)
            break;
        }
      }
      else {
        /* Process the PEM message */
        if ((errorMessage = RIPEMDecipherUpdate
             (ripemInfo, &partOut, &partOutLen, (unsigned char *)input,
              strlen (input), ripemDatabase)) != (char *)NULL)
          break;
        fwrite (partOut, 1, partOutLen, outStream);
      }
    }
    if (errorMessage != (char *)NULL)
      /* Broke while loop because of error */
      break;
    if (!feof (inStream)) {
      errorMessage = "Error reading input stream";
      break;
    }

    if (usePKCSFormat) {
      if (externalMessageStream == (FILE *)NULL) {
        if ((errorMessage = RIPEMDecipherPKCSFinal
             (ripemInfo, &certChain, &chainStatus, &pkcsMode,
              &authenticatedAttributes)) != (char *)NULL)
          break;
      }
      else {
        /* Finalize for a detached signature */
        if ((errorMessage = RIPEMVerifyDetachedPKCSFinal
             (ripemInfo, &certChain, &chainStatus,
              &authenticatedAttributes)) != (char *)NULL)
          break;

        /* The mode must be signed */
        pkcsMode = PKCS_SIGNED;
      }
    }
    else {
      if ((errorMessage = RIPEMDecipherFinal
           (ripemInfo, &certChain, &chainStatus, &enhanceMode))
          != (char *)NULL)
        break;
    }

    if (usePKCSFormat) {
      if (pkcsMode == PKCS_CERTS_AND_CRLS_ONLY) {
        /* Certs only, so just print a message and finish. */
        fprintf (certInfoStream,
                 "Received certificates-and-CRLs-only message.\n");
        break;
      }
      else if (pkcsMode == PKCS_ENVELOPED) {
        /* Enveloped only, there is no sender, so just print a message and
             finish.  Separate with dashed lines since the output may
             have gone to stdout. */
        fputs ("-------------------------\n", certInfoStream);
        fprintf (certInfoStream,
                 "Received enveloped-only message (no sender).\n");
        fputs ("-------------------------\n", certInfoStream);
        break;
      }
    }
    else {
      if (enhanceMode == MODE_CRL) {
        /* There are no senders, so just print a message and finish. */
        fprintf (certInfoStream, "Received CRL message.\n");
        break;
      }
    }

    if (chainStatus.overall == 0) {
      /* Check if there is an entry in the certChain which will be
           a self-signed certificate. */
      if (!certChain.firstptr) {
        errorMessage = "The sender has not been validated. Have them send a self-signed certificate.";
        break;
      }
      else {
        /* Decode the self-signed cert at the "bottom" of the chain.
           Note DERToCertificate won't return an error
             since it was already successfully decoded.
         */
        DERToCertificate
          ((unsigned char *)certChain.firstptr->dataptr, certStruct,
           &fieldPointers);

        if (validate) {
          /* The user specified the validity months, so validate
               the sender's certificate.
             certStruct already has the correct subject name and public
               key.  Set the validity, not allowing it to go past the
               end validity of the sender's self-signed cert.
           */
          R_time (&certStruct->notBefore);
          if (certStruct->notAfter < certStruct->notBefore) {
            /* The expiration date in the sender's cert is earlier than now. */
            errorMessage =
              "Cannot validate the sender because their self-signed certificate has expired.";
            break;
          }
          endValidity = certStruct->notBefore +
            ((UINT4)validityMonths * SECONDS_IN_MONTH);
          if (endValidity < certStruct->notAfter)
            /* The end validity is within the limit set forth by the
                 sender's self-signed certificate. */
            certStruct->notAfter = endValidity;

          if ((errorMessage = ValidateAndWriteCert
               (ripemInfo, certStruct, digestAlgorithm, ripemDatabase))
              != (char *)NULL)
            break;

          fprintf (certInfoStream,
                   "This user has now been validated:\n");
          WritePrintableName (certInfoStream, &certStruct->subject);
          fprintf (certInfoStream,
                   "\nYou may now receive messages from this user.\n");
          break;
        }
        else {
          /* We are not supposed to validate the sender's public key,
             so just output a message giving the sender's name and
             self-signed digest.
           */
          if ((errorMessage = PrintCertNameAndDigest
               ((unsigned char *)certChain.firstptr->dataptr,
                certInfoStream)) != (char *)NULL)
            break;

          fprintf (certInfoStream,
                   "Contact sender to verify certificate digest.\n");
          errorMessage =
          "To validate sender, receive message again in validation mode (-v).";
          break;
        }
      }
    }
    else {
      /* Non-zero chain status, so write out the sender information.
       */
      fputs ("-------------------------\n", certInfoStream);
      if (usePKCSFormat) {
        if (pkcsMode == PKCS_SIGNED)
          messageType = "signed";
        else
          /* PKCS_ENVELOPED case was handled above */
          messageType = "signed and encrypted";
      }
      else
        messageType = (enhanceMode == MODE_ENCRYPTED ?
                       "signed and encrypted" : "signed");
      fprintf (certInfoStream, "Received %s message.\n", messageType);

      if (usePKCSFormat) {
        /* Print any authenticated attributes.
         */
        if (authenticatedAttributes.haveSigningTime) {
          GetDateAndTimeFromTime
            (signingTime, authenticatedAttributes.signingTime);
          fprintf (certInfoStream, "Signing time: %s GMT\n", signingTime);
        }
        
        if (authenticatedAttributes.haveSigningDescription)
          fprintf (certInfoStream, "Signing description: \"%s\"\n",
                   authenticatedAttributes.signingDescription);
      }

      if (chainStatus.overall == CERT_UNVALIDATED) {
        /* For unvalidated keys, the sender's name is the first entry in
             the "certChain". */
        fprintf (certInfoStream, "Sender username: %s\n",
                 (char *)certChain.firstptr->dataptr);
        fprintf (certInfoStream,
                 "Signature status: key found but not validated.\n");
      }
      else {
        /* Decode the cert at the "bottom" of the chain.
           Note DERToCertificate won't return an error
            since it was already successfully decoded.
         */
        DERToCertificate
          ((unsigned char *)certChain.firstptr->dataptr, certStruct,
           (CertFieldPointers *)NULL);
        fprintf (certInfoStream, "Sender name: ");
        WritePrintableName (certInfoStream, &certStruct->subject);
        fprintf (certInfoStream, "\n");

        fprintf
          (certInfoStream, "Signature status: %s.\n",
           GetCertStatusString (chainStatus.overall));
      }
      fputs ("-------------------------\n", certInfoStream);
    }
  } while (0);

  if (input != (char *)NULL) {
    R_memset ((POINTER)input, 0, INPUT_BUFFER_SIZE);
    free (input);
  }
  if (decodedLine != (unsigned char *)NULL) {
    R_memset ((POINTER)decodedLine, 0, INPUT_BUFFER_SIZE);
    free (decodedLine);
  }
  free (certStruct);
  FreeList (&certChain);
  return (errorMessage);
}

/* If needSelfSignedCert is TRUE, make a DN from username and call
     WriteSelfSignedCert with validityMonths and digestAlgorithm
       for upgrading from RIPEM 1.1.
     Otherwise ignore username and validityMonths and digestAlgorithm.
 */
static char *DoChangePWDriver
  (ripemInfo, needSelfSignedCert, username, validityMonths, digestAlgorithm,
   certInfoStream, ripemDatabase)
RIPEMInfo *ripemInfo;
BOOL needSelfSignedCert;
char *username;
unsigned int validityMonths;
int digestAlgorithm;
FILE *certInfoStream;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;
  unsigned char newPassword[MAX_PASSWORD_SIZE];
  unsigned int newPasswordLen;

  /* For error, break to end of do while (0) block. */
  do {
    if (needSelfSignedCert) {
      /* ripemInfo already has public and private key.  We need a self-signed
           cert for upgrading from RIPEM 1.1 */
      if ((errorMessage = SetNewUserDN (ripemInfo, FALSE, username))
          != (char *)NULL)
        break;
      if ((errorMessage = WriteSelfSignedCert
           (ripemInfo, validityMonths, digestAlgorithm, ripemDatabase))
	  != (char *)NULL)
        break;
    }

    newPasswordLen = GetPasswordToPrivKey
      (TRUE, TRUE, newPassword, sizeof (newPassword));

    if ((errorMessage = RIPEMChangePassword
         (ripemInfo, newPassword, newPasswordLen, ripemDatabase))
        != (char *)NULL)
      break;
    if ((errorMessage = PrintCertNameAndDigest
         (ripemInfo->z.userCertDER, certInfoStream))
        != (char *)NULL)
      break;
  } while (0);

  R_memset ((POINTER)newPassword, 0, sizeof (newPassword));
  return (errorMessage);
}

static char *DoGenerateKeysDriver
  (ripemInfo, askDistinguishedName, username, bits, validityMonths,
   digestAlgorithm, password, passwordLen, certInfoStream, ripemDatabase)
RIPEMInfo *ripemInfo;
BOOL askDistinguishedName;
char *username;
unsigned int bits;
unsigned int validityMonths;
int digestAlgorithm;
unsigned char *password;
unsigned int passwordLen;
FILE *certInfoStream;
RIPEMDatabase *ripemDatabase;
{
  char *errorMessage;
  unsigned char buf[4];

  if (bits == 0) {
    R_GenerateBytes (buf, 1, &ripemInfo->randomStruct);
    bits = 508 + (0x0f & buf[0]);
    if (bits < 512)
      bits = 512;
    if (ripemInfo->debug > 1) {
      fprintf (ripemInfo->debugStream,
               "Selected size of key being generated = %d bits.\n", bits);
    }
  }
  
  if ((errorMessage = SetNewUserDN
       (ripemInfo, askDistinguishedName, username)) != (char *)NULL)
    return (errorMessage);

  fprintf (certInfoStream, "Generating keys...\n");
  if ((errorMessage = RIPEMGenerateKeys
       (ripemInfo, bits, validityMonths, digestAlgorithm, password,
	passwordLen, ripemDatabase)) != (char *)NULL)
    return (errorMessage);

  /* Write the new cert's DN and self-signed digest.
   */
  return (PrintCertNameAndDigest
          (ripemInfo->z.userCertDER, certInfoStream));
}

/*--- function InitUser ---------------------------------------
 *
 *  Initialize a TypUser structure.
 *
 *  Entry: email       points to the user's email address (zero-terminated).
 *
 *  Exit:  userEntry       points to a pointer to a newly-allocated TypUser 
 *                                              structure.
 */
static char *
InitUser(email,userEntry)
char *email;
TypUser **userEntry;
{
  char *errorMessage = NULL;
  char *cptr;
  
  *userEntry = (TypUser *) malloc(sizeof **userEntry);
  if(*userEntry) {
    (*userEntry)->gotpubkey = FALSE;
    if(!StrCopyAlloc(&cptr,email)) {
      free (*userEntry);
      errorMessage = ERROR_MALLOC;
    } else {
      (*userEntry)->emailaddr = cptr;
    }
  } else {
    errorMessage = ERROR_MALLOC;
  }
  
  return errorMessage;
}                       

/* Convert a CERT_ validity status into a string such as "VALID".
 */
static char *GetCertStatusString (certStatus)
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

/*--- function AddUniqueUserToList --------------------------------------------
 *
 *  Add a TypUser structure to a list, first checking to ensure that
 *  the user isn't already on the list.
 *
 *  Entry:  user    points to a TypUser structure.
 *
 *   Exit:  list     may have been updated to include this entry.
 *        Returns NULL if successful, else a pointer to an error message.
 */
static char *
AddUniqueUserToList(user,list)
TypUser *user;
TypList *list;
{
  TypListEntry *entry_ptr = list->firstptr;
  TypUser *user_ptr;
  BOOL found=FALSE;
  
  for(; !found && entry_ptr; entry_ptr = entry_ptr->nextptr) {
    user_ptr = (TypUser *)(entry_ptr->dataptr);
    
    if(CaseIgnoreEqual(user_ptr->emailaddr,user->emailaddr)) {
      found = TRUE;
    }
  }
  if(!found) {
    return AddToList(NULL,user,sizeof *user,list);
  } else {
    return NULL;
  }
}

static char *PrintCertNameAndDigest (certDER, outStream)
unsigned char *certDER;
FILE *outStream;
{
  unsigned char digest[MAX_DIGEST_LEN];
  unsigned int digestLen, i;
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  CertFieldPointers fieldPointers;
  char *errorMessage = (char *)NULL;

  /* For error, break to end of do while (0) block. */
  do {
    /* Allocate the certStruct on the heap because it's big. */
    if ((certStruct = (CertificateStruct *)malloc
         (sizeof (*certStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }

    if (DERToCertificate (certDER, certStruct, &fieldPointers) < 0) {
      errorMessage = "Can't decode certificate for printing digest";
      break;
    }
    
    R_DigestBlock
      (digest, &digestLen, fieldPointers.innerDER, fieldPointers.innerDERLen,
       certStruct->digestAlgorithm);

    fputs ("User: ", outStream);
    WritePrintableName (outStream, &certStruct->subject);
    fprintf (outStream, "\n");

    fprintf (outStream, "User certificate digest: ");
    for (i = 0; i < digestLen; ++i)
      fprintf (outStream, "%02X ", (int)digest[i]);
    if (certStruct->digestAlgorithm == DA_MD2)
      fprintf (outStream, "(MD2)");
    else if (certStruct->digestAlgorithm == DA_MD5)
      fprintf (outStream, "(MD5)");
    else if (certStruct->digestAlgorithm == DA_SHA1)
      fprintf (outStream, "(SHA-1)");
    fprintf (outStream, "\n");
  } while (0);

  free (certStruct);
  return (errorMessage);
}

/* Take the username and set the userDN in ripemInfo.
   If askDistinguishedName is FALSE, set it to the Persona CA version.
   Otherwise prompt the user for the name fields, offering the supplied
     username as a default common name.
   Returns NULL for success, otherwise an error string if the user quits.
 */
static char *SetNewUserDN (ripemInfo, askDistinguishedName, username)
RIPEMInfo *ripemInfo;
BOOL askDistinguishedName;
char *username;
{
  char inputLine[MAX_NAME_LENGTH + 1], *errorMessage;
  
  /* Make sure RDN indexes are -1 */
  InitDistinguishedNameStruct (&ripemInfo->userDN);

  if (!askDistinguishedName) {
    /* This is the default behavior for -g */
    SetPersonaName (&ripemInfo->userDN, username);
    return ((char *)NULL);
  }

  puts ("");
  puts ("    Creating a distinguished name for your certificate");
  puts ("(at any time, enter ! to quit)");
  puts ("");
  puts ("P - Persona Certificate (default)");
  puts ("E - Email address only");
  puts ("C - Customized (you enter all the fields)");
  puts ("Q or ! - Quit");

  if ((errorMessage = ReadInputLine
       (inputLine, sizeof (inputLine),
    "  Select the type of name you want (blank for default type of Persona):"))
      != (char *)NULL)
    return (errorMessage);

  switch (*inputLine) {
  case '\0':
  case 'p':
  case 'P':
    printf ("Your default Persona common name is \"%s\".\n", username);
    if ((errorMessage = ReadInputLine
         (inputLine, sizeof (inputLine),
          "  Enter your Persona common name (blank to use the default):"))
        != (char *)NULL)
      return (errorMessage);

    SetPersonaName (&ripemInfo->userDN, *inputLine ? inputLine : username);
    break;

  case 'e':
  case 'E':
    printf ("Your default email address is \"%s\".\n", username);
    if ((errorMessage = ReadInputLine
         (inputLine, sizeof (inputLine),
          "  Enter your email address (blank to use the default):"))
        != (char *)NULL)
      return (errorMessage);

    SetEmailAddressName(&ripemInfo->userDN, *inputLine ? inputLine : username);
    break;

  case 'c':
  case 'C':
    if ((errorMessage = SetCustomizedName (&ripemInfo->userDN, username))
        != (char *)NULL)
      return (errorMessage);
    break;

  case 'q':
  case 'Q':
    return ("Quitting at user's request");

  default:
    return ("Unrecognized response for the type of name to create");
  };

  printf ("Your distinguished name is:\n");
  WritePrintableName (stdout, &ripemInfo->userDN);
  if ((errorMessage = ReadInputLine
       (inputLine, sizeof (inputLine), "\n  Hit ENTER to accept this name or ! to quit:"))
      != (char *)NULL)
    return (errorMessage);

  printf ("\nYour RIPEM username is \"%s\" which you must use to log in.\n",
          GetDNSmartNameValue (&ripemInfo->userDN));

  return ((char *)NULL);
}

/* Assume dn is already initialized.
 */
static void SetPersonaName (dn, commonName)
DistinguishedNameStruct *dn;
char *commonName;
{
  strcpy (dn->AVAValues[0], "US");
  dn->AVATypes[0] = ATTRTYPE_COUNTRYNAME;
  dn->RDNIndexStart[0] = dn->RDNIndexEnd[0] = 0;

  strcpy (dn->AVAValues[1], "RSA Data Security, Inc.");
  dn->AVATypes[1] = ATTRTYPE_ORGANIZATIONNAME;
  dn->RDNIndexStart[1] = dn->RDNIndexEnd[1] = 1;

  strcpy (dn->AVAValues[2], "Persona Certificate");
  dn->AVATypes[2] = ATTRTYPE_ORGANIZATIONALUNITNAME;
  dn->RDNIndexStart[2] = dn->RDNIndexEnd[2] = 2;

  dn->AVATypes[3] = ATTRTYPE_COMMONNAME;
  /* Use PRINTABLE_STRING tag if possible, otherwise T61_STRING */
  dn->AVATag[3] =
    (IsPrintableString ((unsigned char *)commonName, strlen (commonName)) ?
     ATTRTAG_PRINTABLE_STRING : ATTRTAG_T61_STRING);
  strcpy (dn->AVAValues[3], commonName);
  dn->RDNIndexStart[3] = dn->RDNIndexEnd[3] = 3;
}

/* Assume dn is already initialized.
 */
static void SetEmailAddressName (dn, emailAddress)
DistinguishedNameStruct *dn;
char *emailAddress;
{
  dn->AVATag[0] = ATTRTAG_IA5_STRING;
  strcpy (dn->AVAValues[0], emailAddress);
  dn->AVATypes[0] = ATTRTYPE_EMAILADDRESS;
  dn->RDNIndexStart[0] = dn->RDNIndexEnd[0] = 0;
}

/* Assume dn is already initialized.
   Returns NULL for success, else error string if user quits.
 */
static char *SetCustomizedName (dn, defaultCommonName)
DistinguishedNameStruct *dn;
char *defaultCommonName;
{
  char inputLine[MAX_NAME_LENGTH + 1], value[MAX_NAME_LENGTH + 1],
    *errorMessage;
  int iAVA, iRDN, type, tag;
  BOOL sameLevel;

  puts ("\n  This allows you to enter each attribute of the name, starting from the");
  puts ("  attribute of the most significant level, such as \"country\".");

  /* iRDN will automatically be incremented to 0 the first time. */
  iRDN = -1;

  iAVA = 0;
  while (iAVA < MAX_AVA) {
    if (iAVA > 0) {
      printf ("\nSo far, your distinguished name looks like this (printed with the\n  most significant level last):\n");
      WritePrintableName (stdout, dn);
      printf ("\n");
    }

    puts ("");
    puts ("C - country              O - organization         U - org. unit");
    puts ("N - common name          L - locality (city)      S - state or province");
    puts ("A - street address       T - title                Z - postal code (zip code)");
    puts ("P - phone number         E - email address        ! - Quit");

    if ((errorMessage = ReadInputLine
         (inputLine, sizeof (inputLine), iAVA == 0 ?
          "  Enter the type of attribute:" : "  Enter the type of attribute (blank if name is complete):"))
        != (char *)NULL)
      return (errorMessage);

    if (iAVA > 0 && *inputLine == '\0')
      /* Finished */
      break;
    else if (*inputLine == 'c' || *inputLine == 'C')
      type = ATTRTYPE_COUNTRYNAME;
    else if (*inputLine == 'o' || *inputLine == 'O')
      type = ATTRTYPE_ORGANIZATIONNAME;
    else if (*inputLine == 'u' || *inputLine == 'U')
      type = ATTRTYPE_ORGANIZATIONALUNITNAME;
    else if (*inputLine == 'n' || *inputLine == 'N')
      type = ATTRTYPE_COMMONNAME;
    else if (*inputLine == 'l' || *inputLine == 'L')
      type = ATTRTYPE_LOCALITYNAME;
    else if (*inputLine == 's' || *inputLine == 'S')
      type = ATTRTYPE_STATEPROVINCENAME;
    else if (*inputLine == 'a' || *inputLine == 'A')
      type = ATTRTYPE_STREETADDRESS;
    else if (*inputLine == 't' || *inputLine == 'T')
      type = ATTRTYPE_TITLE;
    else if (*inputLine == 'z' || *inputLine == 'Z')
      type = ATTRTYPE_POSTALCODE;
    else if (*inputLine == 'p' || *inputLine == 'P')
      type = ATTRTYPE_PHONENUMBER;
    else if (*inputLine == 'e' || *inputLine == 'E')
      type = ATTRTYPE_EMAILADDRESS;
    else {
      if ((errorMessage = ReadInputLine
           (inputLine, sizeof (inputLine), "  You entered an invalid type.  Hit ENTER to try again or ! to quit:"))
          != (char *)NULL)
        return (errorMessage);
      
      continue;
    }

    if (type == ATTRTYPE_COMMONNAME) {
      /* Special processing for common name to let them use the default.
       */
      printf ("Your default common name is \"%s\".\n", defaultCommonName);
      if ((errorMessage = ReadInputLine
           (inputLine, sizeof (inputLine),
            "  Enter your common name (blank to use the default):"))
          != (char *)NULL)
        return (errorMessage);

      strcpy (value, *inputLine ? inputLine : defaultCommonName);
    }
    else if (type == ATTRTYPE_COUNTRYNAME) {
      /* Special processing for country.
       */
      if ((errorMessage = ReadInputLine
           (inputLine, sizeof (inputLine),
            "  Enter your country name (blank to use the default of \"US\"):"))
          != (char *)NULL)
        return (errorMessage);

      strcpy (value, *inputLine ? inputLine : "US");
    }
    else {
      if ((errorMessage = ReadInputLine
           (inputLine, sizeof (inputLine), "  Enter the value of this attribute:"))
          != (char *)NULL)
        return (errorMessage);

      if (*inputLine == '\0') {
        if ((errorMessage = ReadInputLine
             (inputLine, sizeof (inputLine), "  You entered a blank value.  Hit ENTER to try again or ! to quit:"))
            != (char *)NULL)
          return (errorMessage);

        continue;
      }

      strcpy (value, inputLine);
    }

    if (type == ATTRTYPE_EMAILADDRESS)
      tag = ATTRTAG_IA5_STRING;
    else
      tag =
      (IsPrintableString ((unsigned char *)value, strlen (value)) ?
       ATTRTAG_PRINTABLE_STRING : ATTRTAG_T61_STRING);

    if (iAVA == 0)
      sameLevel = FALSE;
    else {
      puts("  Enter Y if this attribute is on the same level as the previous");
      if ((errorMessage = ReadInputLine
           (inputLine, sizeof (inputLine), "  attribute (or blank for default of putting it on a new level:"))
          != (char *)NULL)
        return (errorMessage);

      sameLevel = (*inputLine == 'y' || *inputLine == 'Y');
    }

    dn->AVATypes[iAVA] = type;
    dn->AVATag[iAVA] = tag;
    strcpy (dn->AVAValues[iAVA], value);

    if (!sameLevel) {
      ++iRDN;
      dn->RDNIndexStart[iRDN] = iAVA;
    }
    dn->RDNIndexEnd[iRDN] = iAVA;

    ++iAVA;
  }

  return ((char *)NULL);
}

/* Print the prompt, then read up to maxLineSize - 1 bytes and put into line,
     null terminated.  This is better than just calling gets, since gets
     does not check for overflow of the line buffer.
   This assumes maxLineSize is at least 1.
   This also strips whitespace from the beginning and end of the string.
   If the user enters !, this returns "Quitting at user's request",
     else this returns (char *)NULL.
 */
static char *ReadInputLine (line, maxLineSize, prompt)
char *line;
unsigned int maxLineSize;
char *prompt;
{
  unsigned int len, i, j;
  
  puts (prompt);  
  fflush (stdout);

  fgets (line, maxLineSize, stdin);

  for (len = 0; len < maxLineSize; ++len)
    if (line[len] == '\0')
      break;

  if (len == maxLineSize) {
    --len;
    line[len] = '\0';
  }

  /* Strip whitespace from the end of the line, including the '\n' that
       fgets always returns */
  while (len > 0) {
    if (IsWhitespace ((int)line[len - 1]))
      line[--len] = 0;
    else
      break;
  }

  for (i = 0; i < len; ++i)
    if (!IsWhitespace ((int)line[i]))
      break;

  if (i > 0) {
    /* Shift the line left to get rid of whitespace at the beginning. */
    j = 0;
    while (i < len)
      line[j++] = line[i++];

    line[j] = '\0';
  }

  if (*line == '!')
    return ("Quitting at user's request");

  return ((char *)NULL);
}

/* Write out each line in headerList to outStream, then a blank line.
 */
static void WritePrependedHeaders (headerList, outStream)
TypList *headerList;
FILE *outStream;
{
  TypListEntry *entry_ptr;
  long int nlines=0;
    
  for(entry_ptr=headerList->firstptr; entry_ptr; 
      entry_ptr = entry_ptr->nextptr) {
    fputs((char *)entry_ptr->dataptr,outStream);
    fputc ('\n', outStream);
    nlines++;
  }
  if(nlines)
    fputc ('\n', outStream);
}

/* Allocate a buffer and read stdin up to end of stream.
   While buffer is being resized, the previous memory for the buffer
     is zeroized so no sensitive data is left in memory.
   Return the alloced buffer in plaintext and its length in plaintextLen.
 */
static char *ReadPlaintextAlloc (plaintext, plaintextLen)
unsigned char **plaintext;
unsigned int *plaintextLen;
{
  unsigned char *newBuffer;
  unsigned int partInLen;
  
  *plaintext = (unsigned char *)NULL;
  *plaintextLen = 0;

  /* Keep expanding the buffer by a big chunk and read in more of the input.
   */
  while (1) {
    /* Leave an extra byte in case we need to append a \n at the very end. */
    if ((newBuffer = (unsigned char *)malloc
         (*plaintextLen + INPUT_BUFFER_SIZE + 1)) == (unsigned char *)NULL)
      return ("Cannot fit the input into memory. Try using a file for input.");

    /* Copy over contents from old buffer, zeroize and free the old buffer.
     */
    R_memcpy ((POINTER)newBuffer, (POINTER)*plaintext, *plaintextLen);
    R_memset ((POINTER)*plaintext, 0, *plaintextLen);
    free (*plaintext);

    *plaintext = newBuffer;

    /* Read the input into the newly allocated space. */
    partInLen = fread
      (*plaintext + *plaintextLen, 1, INPUT_BUFFER_SIZE, stdin);
    *plaintextLen += partInLen;

    if (partInLen < INPUT_BUFFER_SIZE) {
      /* fread returned less than the bytes requested, so end of stream */
      if (*plaintextLen > 0 && *(*plaintext + *plaintextLen - 1) != '\n')
        /* Make the last line end with a \n */
        *(*plaintext + ((*plaintextLen)++)) = '\n';

      return ((char *)NULL);
    }
  }
}

/* Read a header up to the first blank line.
   If headerList is not NULL, add header lines to the list.  The calling
     routine must initialize the list.
   If recipientNames is not NULL, add email addresses in all To: and
     Cc: fields.  The calling routine must initialize the list.
 */
static char *ReadEmailHeader (stream, headerList, recipientNames)
FILE *stream;
TypList *headerList;
TypList *recipientNames;
{
  unsigned char line[1024], *linecp;
  BOOL to_field = FALSE;
  char *errorMessage = (char *)NULL, *readStatus;

  /* For error, break to end of do while (0) block. */
  do {
    while ((readStatus = fgets ((char *)line, sizeof (line), stream))
           != NULL) {
      /* Strip end-of-line CR and/or NL */
      for (linecp=line; *linecp && *linecp!='\r' && *linecp!='\n'; linecp++);
      *linecp = '\0';
      
      if(line[0] == '\0')
        break;

      if (recipientNames != (TypList *)NULL) {
        if (matchn ((char *)line,"To:", 3) ||
            matchn ((char *)line,"cc:",3)) {
          to_field = TRUE;
          CrackRecipients ((char *)line + 3, recipientNames);
        } else if (to_field) {
          if (line[0] == ' ' || line[0] == '\t')
            CrackRecipients ((char *)line, recipientNames);
          else
            to_field = FALSE;
        }
      }
      if (headerList != (TypList *)NULL) {
        if ((errorMessage = AppendLineToList ((char *)line, headerList))
            != (char *)NULL)
          break;
      }
    }
    if (errorMessage != (char *)NULL)
      /* broke because of error */
      break;

    if (readStatus == (char *)NULL) {
      /* Make sure we got a NULL read status becuase of end of file. */
      if (!feof (stream)) {
        errorMessage = "Error reading header from stream";
        break;
      }

      /* Note: we have reached the end of stream before reading a blank line */
    }
  } while (0);

  /* Zeroize the line */
  R_memset ((POINTER)line, 0, sizeof (line));  
  return (errorMessage);
}

static int IsWhitespace (ch)
int ch;
{
  return (ch==' ' || ch=='\t' || ch=='\n');
}

#ifndef RIPEMSIG

/* Set recipientKeys to the keys for the recipients in RecipientList.
   If ripemFlags->myselfAsRecip is TRUE, add entry to the logged-in user
     using the smart name of ripemInfo->userDN.
   Next, look for keys in certificates.  Then, for compatibility with
     RIPEM 1.1, look for unsigned keys.
   recipientKeys must be a buffer with at least as many elements as
     in RecipientList plus an extra if ripemFlags->myselfAsRecip is TRUE.
   Also, print the recipient statuses to the certInfoStream.
   This sets recipientKeyCount to this number of keys found.
   If ripemFlags->abortIfRecipUnknown is TRUE and not all recipient keys are
     found, this returns an error.
 */
static char *GetRecipientKeys
  (ripemInfo, recipientKeys, recipientKeyCount, ripemFlags, certInfoStream,
   ripemDatabase)
RIPEMInfo *ripemInfo;
RecipientKeyInfo *recipientKeys;
unsigned int *recipientKeyCount;
RIPEMFlags *ripemFlags;
FILE *certInfoStream;
RIPEMDatabase *ripemDatabase;
{
  CertificateStruct *certStruct = (CertificateStruct *)NULL;
  TypList certChain, certs;
  TypListEntry *entry;
  TypUser *recipient;
  char *errorMessage = (char *)NULL;
  ChainStatusInfo chainStatus;

  /* Set to initial state so it is OK to free on error at any time. */
  InitList (&certChain);
  InitList (&certs);
  *recipientKeyCount = 0;

  /* For error, break to end of do while (0) block. */
  do {
    if (ripemFlags->myselfAsRecip) {
      recipientKeys[*recipientKeyCount].publicKey = ripemInfo->publicKey;
      recipientKeys[*recipientKeyCount].username =
        GetDNSmartNameValue (&ripemInfo->userDN);
      ++ (*recipientKeyCount);
    }

    /* Get the public keys of all the users first.
     * We do this first because we want to know whether some
     * of the keys are unavailable before we do a lot of
     * time-consuming RSA encryption.
     */
       
    /* Allocate cert struct on the heap since it is so big */
    if ((certStruct = (CertificateStruct *)malloc
         (sizeof (*certStruct))) == (CertificateStruct *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }
    
    /* Prepare to put recipient statuses to the certInfoStream. */
    fputs ("Recipient status:\n", certInfoStream);

    for(entry = RecipientList.firstptr; entry;
        entry = entry->nextptr) {
      recipient = (TypUser *)entry->dataptr;
      
      /* Prepare to get recipient chain by freeing content from
         previous iteration. */
      FreeList (&certs);
      FreeList (&certChain);
      
      if ((errorMessage = GetCertsBySmartname
           (ripemDatabase, &certs, recipient->emailaddr, ripemInfo))
          != (char *)NULL)
        break;
      if (!certs.firstptr)
        /* Couldn't find a certificate for this smartname, so try
             next recipient. */
        continue;
      if (DERToCertificate
          ((unsigned char *)certs.firstptr->dataptr, certStruct,
           (CertFieldPointers *)NULL) < 0) {
        if (ripemInfo->debug > 1)
          fprintf (ripemInfo->debugStream,
                   "Warning: Cannot decode certificate from database.\n");
        continue;
      }

      /* We have a cert with the full subject distinguished name, so
           select a chain.  Pass NULL for public key since we don't know
           now what the best public key is.  Also, set directCertOnly
           FALSE to allow any certificate chain. */
      if ((errorMessage = SelectCertChain
           (ripemInfo, &certChain, &chainStatus, &certStruct->subject,
            (R_RSA_PUBLIC_KEY *)NULL, FALSE, ripemDatabase)) != (char *)NULL)
        break;
      if (chainStatus.overall != 0) {
        /* Decode the certificate at the "bottom" of the chain.  Don't check
             for error decoding since it already decoded sucessfully. */
        DERToCertificate
          ((unsigned char *)certChain.firstptr->dataptr, certStruct,
           (CertFieldPointers *)NULL);

        fprintf (certInfoStream, "%s: ",
                 GetCertStatusString (chainStatus.overall));
        WritePrintableName (certInfoStream, &certStruct->subject);
        fprintf (certInfoStream, "\n");

        recipient->gotpubkey = TRUE;
        recipientKeys[*recipientKeyCount].publicKey = certStruct->publicKey;
        recipientKeys[*recipientKeyCount].username = recipient->emailaddr;
        ++ (*recipientKeyCount);
      }
    }
    if (errorMessage != (char *)NULL)
      break;

    /* Now try getting public keys from non-certificates, finger, etc.
       This is only to support the "pre-certificate" model of RIPEM 1.1. */
    for(entry = RecipientList.firstptr; entry;
        entry = entry->nextptr) {
      recipient = (TypUser *)entry->dataptr;

      if (recipient->gotpubkey)
        continue;

      if(ripemInfo->debug > 1) {
        fprintf(ripemInfo->debugStream,"== Getting public key for %s\n",
                recipient->emailaddr);
      }   

      if ((errorMessage = GetUnvalidatedPublicKey
           (recipient->emailaddr, &ripemDatabase->pubKeySource,
            &recipientKeys[*recipientKeyCount].publicKey,
            &recipient->gotpubkey, ripemInfo))
          != (char *)NULL)
        break;

      if (recipient->gotpubkey) {
        fprintf (certInfoStream,
                 "%s (on file but not validated)\n", recipient->emailaddr);
        recipientKeys[*recipientKeyCount].username = recipient->emailaddr;
        ++ (*recipientKeyCount);
      }
    }
    if (errorMessage != (char *)NULL)
      break;
    
    /* Put a blank line after the recipients */
    fputs ("\n", certInfoStream);           

    if (!CheckKeyList (&RecipientList, ripemFlags->abortIfRecipUnknown)) {
      errorMessage =  "Can't find some public keys; RIPEM aborting.";
      break;
    }
  } while (0);

  FreeList (&certChain);
  FreeList (&certs);
  free (certStruct);
  return (errorMessage);
}

/*--- function CheckKeyList ----------------------------------------
 *
 *  Check a list of users to make sure that we have a public key for
 *  each one.  
 *
 *  Entry:  userList is a list of TypUser types, containing
 *                   information on users (including whether
 *                   we know their public keys).
 *
 *  Exit:   Returns TRUE if it is OK to proceed, else FALSE.
 *          It's OK if we have the key of each user, or if the
 *          user has been prompted and has said it's OK to proceed
 *          even if some keys are unknown.
 */
static BOOL
CheckKeyList(userList, abortIfRecipUnknown)
TypList *userList;
{
  TypListEntry *entry_ptr;
  TypUser *recip_ptr;
  int bad_users = 0;
  BOOL ok = TRUE, asking=TRUE;
#define REPLY_BYTES 4
  unsigned char userbytes[REPLY_BYTES],timebytes[REPLY_BYTES];
  char reply;
  int n_userbytes, n_timebytes;
  
  for(entry_ptr = userList->firstptr; ok && entry_ptr;
      entry_ptr = entry_ptr->nextptr) {
    recip_ptr = (TypUser *)entry_ptr->dataptr;
    
    if(!recip_ptr->gotpubkey) bad_users++; 
  }        
  
  if(bad_users) {
    if(abortIfRecipUnknown) {
      ok = FALSE;
    } else {
      if(bad_users==1) {
        fprintf(stderr,"Could not find public keys for this user:\n");
      } else {
        fprintf(stderr,"Could not find public keys for these %d users:\n",
                bad_users);
      }
      for(entry_ptr = userList->firstptr; ok && entry_ptr;
          entry_ptr = entry_ptr->nextptr) {
        recip_ptr = (TypUser *)entry_ptr->dataptr;
        if(!recip_ptr->gotpubkey) {
          fprintf(stderr,"   %s\n",recip_ptr->emailaddr);
        }
      }
      do {
        fprintf(stderr,"Proceed anyway, deleting these users? ");
        n_userbytes = n_timebytes = REPLY_BYTES;
        GetUserInput(userbytes,&n_userbytes,timebytes,&n_timebytes,TRUE);
        reply = (char) userbytes[0];
        if(reply == 'y' || reply=='Y') {
          ok = TRUE;
          asking = FALSE;
        } else if(reply=='n' || reply=='N') {
          ok = FALSE;
          asking = FALSE;
        }
      } while(asking);
    }
  }
  return ok;
}

#endif

