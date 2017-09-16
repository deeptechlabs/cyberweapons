/* DHDEMO.C - demonstration program for Diffie-Hellman extensions to
              RSAREF
 */

/* Copyright (C) 1993 RSA Laboratories, a division of RSA Data
   Security, Inc. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "global.h"
#include "rsaref.h"

int main PROTO_LIST ((int, char **));
static int SetOptions PROTO_LIST ((int, char **));
static void InitRandomStruct PROTO_LIST ((R_RANDOM_STRUCT *));
static void DoSetupAgreement PROTO_LIST ((R_RANDOM_STRUCT *));
static void DoComputeAgreedKey PROTO_LIST ((void));
static void DoGenerateParams PROTO_LIST ((R_RANDOM_STRUCT *));
static void WriteParams2 PROTO_LIST ((void));
static void WriteBigInteger PROTO_LIST
  ((FILE *, unsigned char *, unsigned int));
static int ReadBlock PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned int, char *));
static int WriteBlock PROTO_LIST ((unsigned char *, unsigned int, char *));
static int GetParams PROTO_LIST ((R_DH_PARAMS **, char *));
static void PrintMessage PROTO_LIST ((char *));
static void PrintError PROTO_LIST ((char *, int));
static void GetCommand PROTO_LIST ((char *, unsigned int, char *));

static int SILENT_PROMPT = 0;

static unsigned char PRIME1[64] = {
  0xd0, 0x45, 0x1f, 0xfe, 0x2c, 0x64, 0xc4, 0xed, 0x6b, 0x0a, 0xe6,
  0x36, 0x5b, 0x7f, 0xef, 0x9c, 0x15, 0x42, 0x5e, 0x40, 0xa3, 0x7c,
  0xa5, 0xf8, 0x39, 0x86, 0x5e, 0x2c, 0xfb, 0x41, 0x69, 0xa0, 0xd8,
  0x25, 0xc9, 0x13, 0x0f, 0x88, 0x64, 0xff, 0xfc, 0xf3, 0xbf, 0xbe,
  0xb0, 0x27, 0x36, 0x60, 0x67, 0xaa, 0x27, 0xe2, 0x7b, 0xfc, 0xaf,
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static unsigned char GENERATOR1[64] = {
  0x0a, 0xcf, 0x95, 0x8c, 0x40, 0xd3, 0x01, 0xef, 0xc5, 0x15, 0x3e,
  0x7d, 0xcd, 0x5e, 0xf7, 0x5f, 0xec, 0x9e, 0x8f, 0xb0, 0xfa, 0xe6,
  0xa8, 0x0e, 0xe5, 0xc3, 0xb8, 0x4b, 0x9c, 0x0e, 0x51, 0x30, 0x51,
  0xb2, 0xb7, 0x54, 0x2e, 0x66, 0xb8, 0xd3, 0xa2, 0x5e, 0x93, 0x89,
  0x11, 0xad, 0x6b, 0xe5, 0xc2, 0x43, 0x95, 0x09, 0x9c, 0x6d, 0xda,
  0xa8, 0x6e, 0x18, 0x94, 0x2f, 0x29, 0x84, 0x27, 0x5a
};

static R_DH_PARAMS PARAMS1 = {
  PRIME1, sizeof (PRIME1), GENERATOR1, sizeof (GENERATOR1)
};
R_DH_PARAMS PARAMS2;
int PARAMS2_READY = 0;

int main (argc, argv)
int argc;
char *argv[];
{
  R_RANDOM_STRUCT randomStruct;
  char command[80];
  int done = 0;

  if (SetOptions (argc, argv))
    return (0);
  
  InitRandomStruct (&randomStruct);
  PrintMessage
    ("NOTE: When saving to a file, a filename of \"-\" will output to the screen.");

  while (!done) {
    PrintMessage ("");
    PrintMessage ("S - Set up a key agreement");
    PrintMessage ("C - Compute an agreed-upon key");
    PrintMessage ("G - Generate parameters (may take a long time)");
    PrintMessage ("Q - Quit");
    GetCommand (command, sizeof (command), "  Enter choice: ");
    
    switch (*command) {
    case '\0':
    case '#':
      /* entered a blank line or a comment */
      break;
      
    case 's':
    case 'S':
      DoSetupAgreement (&randomStruct);
      break;
      
    case 'c':
    case 'C':
      DoComputeAgreedKey ();
      break;

    case 'g':
    case 'G':
      DoGenerateParams (&randomStruct);
      break;
      
    case 'Q':
    case 'q':
      done = 1;
      break;
      
    default:
      PrintError ("ERROR: Unrecognized command.  Try again.", 0);
      break;
    }
  }
  
  R_RandomFinal (&randomStruct);
  return (0);
}

/* Set options from command line and return 0 for success, 1 for bad format.
 */
static int SetOptions (argc, argv)
int argc;
char *argv[];
{
  int i, status = 0;
  
  for (i = 1; i < argc; i++) {
    if (argv[i][0] != '-') {
      status = 1;
      break;
    }
    
    if (argv[i][1] == 's')
      SILENT_PROMPT = 1;
    else {
      status = 1;
      break;
    }
  }

  if (status)
    puts ("Usage: dhdemo [-s]\n\
  -s silent prompts");

  return (status);
}

/* Initialize the random structure with all zero seed bytes for test purposes.
   NOTE that this will cause the output of the "random" process to be
     the same every time.  To produce random bytes, the random struct
     needs random seeds!
 */
static void InitRandomStruct (randomStruct)
R_RANDOM_STRUCT *randomStruct;
{
  static unsigned char seedByte = 0;
  unsigned int bytesNeeded;
  
  R_RandomInit (randomStruct);
  
  /* Initialize with all zero seed bytes, which will not yield an actual
       random number output.
   */
  while (1) {
    R_GetRandomBytesNeeded (&bytesNeeded, randomStruct);
    if (bytesNeeded == 0)
      break;
    
    R_RandomUpdate (randomStruct, &seedByte, 1);
  }
}

static void DoSetupAgreement (randomStruct)
R_RANDOM_STRUCT *randomStruct;
{
  R_DH_PARAMS *params;
  char command[80];
  int status;
  unsigned char *privateValue, *publicValue;
  unsigned int privateValueLen;

  if (GetParams
      (&params, "  Set up with parameters 1 or 2? (blank to cancel): "))
    return;

  GetCommand
    (command, sizeof (command),
     "  Enter length in bytes of private value (blank to cancel): ");
  if (! *command)
    return;
  sscanf (command, "%d", &privateValueLen);

  privateValue = (unsigned char *)malloc (privateValueLen);
  publicValue = (unsigned char *)malloc (params->primeLen);

  /* Set up a break point with a do {} while (0) so that we can
       zeroize the sensitive buffers before exiting.
   */
  do {
    if (status = R_SetupDHAgreement
        (publicValue, privateValue, privateValueLen, params, randomStruct)) {
      PrintError ("setting up key agreement", status);
      break;
    }
  
    if (WriteBlock
        (publicValue, params->primeLen,
         "  Enter filename to save the public value (blank to cancel): "))
      break;
  
    if (WriteBlock
        (privateValue, privateValueLen,
         "  Enter filename to save the private value (blank to cancel): "))
      break;
  } while (0);

  memset ((POINTER)privateValue, 0, privateValueLen);
  free (privateValue);
  free (publicValue);
}

static void DoComputeAgreedKey ()
{
  R_DH_PARAMS *params;
  int status;
  unsigned char *agreedKey, *otherPublicValue, *privateValue;
  unsigned int otherPublicValueLen, privateValueLen;

  if (GetParams
      (&params, "  Compute with parameters 1 or 2? (blank to cancel): "))
    return;

  otherPublicValue = (unsigned char *)malloc (params->primeLen);
  privateValue = (unsigned char *)malloc (params->primeLen);
  agreedKey = (unsigned char *)malloc (params->primeLen);

  /* Set up a break point with a do {} while (0) so that we can
       zeroize the sensitive buffers before exiting.
   */
  do {
    if (ReadBlock
        (otherPublicValue, &otherPublicValueLen, params->primeLen,
         "  Enter filename of other party's public value (blank to cancel): "))
      break;
    if (otherPublicValueLen != params->primeLen) {
      PrintError ("ERROR: Other party's public value has wrong length", 0);
      break;
    }

    if (ReadBlock
        (privateValue, &privateValueLen, params->primeLen,
         "  Enter filename of private value (blank to cancel): "))
      break;
  
    if (status = R_ComputeDHAgreedKey
        (agreedKey, otherPublicValue, privateValue, privateValueLen, params)) {
      PrintError ("computing agreed-upon key", status);
      break;
    }
  
    if (WriteBlock
        (agreedKey, params->primeLen,
         "  Enter filename to save the agreed-upon key (blank to cancel): "))
      break;
  } while (0);
  
  memset ((POINTER)privateValue, 0, privateValueLen);
  memset ((POINTER)agreedKey, 0, params->primeLen);
  free (otherPublicValue);
  free (privateValue);
  free (agreedKey);
}

static void DoGenerateParams (randomStruct)
R_RANDOM_STRUCT *randomStruct;
{
  char command[80];
  int status, primeBits, subPrimeBits;

  GetCommand
    (command, sizeof (command),
     "  Enter prime size in bits, (16 to 1024) (blank to cancel): ");
  if (! *command)
    return;
  sscanf (command, "%d", &primeBits);

  GetCommand
    (command, sizeof (command),
     "  Enter subprime size in bits, (16 to 1024) (blank to cancel): ");
  if (! *command)
    return;
  sscanf (command, "%d", &subPrimeBits);

  if (PARAMS2_READY) {
    free (PARAMS2.prime);
    free (PARAMS2.generator);
  }
  PARAMS2.prime = (unsigned char *)malloc (DH_PRIME_LEN (primeBits));
  PARAMS2.generator = (unsigned char *)malloc (DH_PRIME_LEN (primeBits));
  
  if (status = R_GenerateDHParams
      (&PARAMS2, primeBits, subPrimeBits, randomStruct)) {
    PrintError ("generating parameters", status);
    return;
  }

  PrintMessage ("Parameters 2 are now ready to use.");
  PARAMS2_READY = 1;
  
  WriteParams2 ();
}

static void WriteParams2 ()
{
  FILE *file;
  char filename[256];
  
  while (1) {
    GetCommand
      (filename, sizeof (filename),
       "Enter filename to save the parameters (blank to not save): ");
    if (! *filename)
      return;
    
    if (filename[0] == '-' && filename[1] == '\0') {
      /* use stdout */
      file = stdout;
      break;
    }
    if ((file = fopen (filename, "w")) != NULL)
      /* successfully opened */
      break;
    
    PrintError ("ERROR: Cannot open a file with that name.  Try again.", 0);
  }

  fprintf (file, "Parameters:\n");
  fprintf (file, "  prime: ");
  WriteBigInteger (file, PARAMS2.prime, PARAMS2.primeLen);
  fprintf (file, "  generator: ");
  WriteBigInteger (file, PARAMS2.generator, PARAMS2.generatorLen);

  if (file != stdout)
    fclose (file);
}

/* Write the byte string 'integer' to 'file', skipping over leading zeros.
 */
static void WriteBigInteger (file, integer, integerLen)
FILE *file;
unsigned char *integer;
unsigned int integerLen;
{
  while (*integer == 0 && integerLen > 0) {
    integer++;
    integerLen--;
  }
  
  if (integerLen == 0) {
    /* Special case, just print a zero. */
    fprintf (file, "00\n");
    return;
  }
  
  for (; integerLen > 0; integerLen--)
    fprintf (file, "%02x ", (unsigned int)(*integer++));

  fprintf (file, "\n");
}

/* Use the prompt to ask the user to use parameters 1 or 2 and
     point params to the answer.
   Return 0 on success or 1 if user cancels by entering a blank.
 */
static int GetParams (params, prompt)
R_DH_PARAMS **params;
char *prompt;
{
  char command[80];
  
  while (1) {
    GetCommand (command, sizeof (command), prompt);

    switch (*command) {
    case '\0':
      return (1);
      
    case '1':
      *params = &PARAMS1;
      return (0);
      
    case '2':
      if (!PARAMS2_READY) {
        PrintError
          ("ERROR: Parameters 2 have not been generated yet.  Try Again.", 0);
        break;
      }
      else {
        *params = &PARAMS2;
        return (0);
      }
      
    default:
      if (PARAMS2_READY)
        PrintError ("ERROR: Please enter 1 or 2.  Try again.", 0);
      else
        PrintError ("ERROR: Please enter 1.  Try again.", 0);
      break;
    }
  }
}

/* Read a file of up to length maxBlockLen bytes, storing it in
     block and returning its length in blockLen.
   Ask for the filename using the given prompt string.
   Return 0 on success or 1 if error or if user cancels by entering a blank.
 */
static int ReadBlock (block, blockLen, maxBlockLen, prompt) 
unsigned char *block;
unsigned int *blockLen;
unsigned int maxBlockLen;
char *prompt;
{
  FILE *file;
  int status;
  char filename[256];
  unsigned char dummy;
  
  while (1) {
    GetCommand (filename, sizeof (filename), prompt);
    if (! *filename)
      return (1);
    
    if ((file = fopen (filename, "rb")) != NULL)
      /* successfully opened */
      break;
    
    PrintError ("ERROR: Cannot open a file with that name.  Try again.", 0);
  }
  
  /* fread () returns the number of items read in.  Expect an end of file
       after the read.
   */
  *blockLen = fread (block, 1, maxBlockLen, file);
  if (*blockLen == maxBlockLen)
    /* Read exactly maxBlockLen bytes, so reading one more will set 
         end of file if there were exactly maxBlockLen bytes in the file.
     */
    fread (&dummy, 1, 1, file);
  
  if (!feof (file)) {
    PrintError ("ERROR: Cannot read file or file is too large.", 0);
    status = 1;
  }
  else
    status = 0;
  
  fclose (file);
  return (status);
}

/* Write block oflength blockLen to a file.
   Ask for the filename using the given prompt string.
   Return 0 on success or 1 if error or if user cancels by entering a blank.
 */
static int WriteBlock (block, blockLen, prompt) 
unsigned char *block;
unsigned int blockLen;
char *prompt;
{
  FILE *file;
  int status;
  char filename[256];
  
  while (1) {
    GetCommand (filename, sizeof (filename), prompt);
    if (! *filename)
      return (1);
    
    if (filename[0] == '-' && filename[1] == '\0') {
      /* use stdout */
      file = stdout;
      break;
    }
    if ((file = fopen (filename, "wb")) != NULL)
      /* successfully opened */
      break;
    
    PrintError ("ERROR: Cannot open a file with that name.  Try again.", 0);
  }
  
  status = 0;
  if (fwrite (block, 1, blockLen, file) < blockLen) {
    PrintError ("ERROR: Cannot write file.", 0);
    status = 1;
  }
  else {
    if (file == stdout)
      /* Printing to screen, so print a new line. */
      printf ("\n");
  }

  if (file != stdout)
    fclose (file);
  return (status);
}

static void PrintMessage (message)
char *message;
{
  if (!SILENT_PROMPT) {
    puts (message);
    fflush (stdout);
  }
}

/* If type is zero, simply print the task string, otherwise convert the
     type to a string and print task and type.
 */
static void PrintError (task, type)
char *task;
int type;
{
  char *typeString, buf[80];

  if (type == 0) {
    puts (task);
    return;
  }
  
  /* Convert the type to a string if it is recognized.
   */
  switch (type) {
  case RE_CONTENT_ENCODING:
    typeString = "(Encrypted) content has RFC 1113 encoding error";
    break;
  case RE_DIGEST_ALGORITHM:
    typeString = "Message-digest algorithm is invalid";
    break;
  case RE_KEY:
    typeString = "Recovered DES key cannot decrypt encrypted content or encrypt signature";
    break;
  case RE_KEY_ENCODING:
    typeString = "Encrypted key has RFC 1113 encoding error";
    break;
  case RE_MODULUS_LEN:
    typeString = "Modulus length is invalid";
    break;
  case RE_NEED_RANDOM:
    typeString = "Random structure is not seeded";
    break;
  case RE_PRIVATE_KEY:
    typeString = "Private key cannot encrypt message digest, or cannot decrypt encrypted key";
    break;
  case RE_PUBLIC_KEY:
    typeString = "Public key cannot encrypt DES key, or cannot decrypt signature";
    break;
  case RE_SIGNATURE:
    typeString = "Signature on content or block is incorrect";
    break;
  case RE_SIGNATURE_ENCODING:
    typeString = "(Encrypted) signature has RFC 1113 encoding error";
    break;
    
  default:
    sprintf (buf, "Code 0x%04x", type);
    typeString = buf;
  }

  printf ("ERROR: %s while %s\n", typeString, task);  
  fflush (stdout);
}

static void GetCommand (command, maxCommandSize, prompt)
char *command;
unsigned int maxCommandSize;
char *prompt;
{
  unsigned int i;
  
  if (!SILENT_PROMPT) {
    printf ("%s\n", prompt);  
    fflush (stdout);
  }

  fgets (command, maxCommandSize, stdin);
  
  /* Replace the line terminator with a '\0'.
   */
  for (i = 0; command[i] != '\0'; i++) {
    if (command[i] == '\012' || command[i] == '\015' ||
        i == (maxCommandSize - 1)) {
      command[i] = '\0';
      return;
    }
  }
}
