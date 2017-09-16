#define MIMIC_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/
#if defined(THINK_C)
#include <console.h>
#endif

#include "global.h"

#include "getopt.h"
#include "words.h"
#include "table.h"
#include "random.h"
#include "outsplit.h"
#include "parser.h"
#include "utl.h"

static BoolType decoding;

/* Does the opening headaches. */
#if defined(FLG_PROTOTYPE)
static void InitEverything(void)
#else
static void InitEverything()
#endif
{
InitRandomBits();
InitializeScanHashTable();
AddCarriageReturns = TRUE;
RightMargin = 50;

OpenGrammarName[0] = '\0';
OpenGrammarFile = NULL;
OpenMimicryName[0] = '\0';
OpenSourceName[0] = '\0';
OpenSourceFile = NULL;
TableDebugFile[0] = '\0';
decoding = FALSE;  /* default is to encode */
}

#if defined(FLG_PROTOTYPE)
static void usage(void)
#else
static void usage()
#endif
{
fprintf(stderr, "Usage: mimic grammarFile [-cde] [-m mimicryFile]\n");
fprintf(stderr, "         [-r rightMargin] [-s plainTextFile]\n");
fprintf(stderr, "         [-p key] [-t tableDebugFile]\n");
fprintf(stderr, "\n-c don't add carriage returns\n");
fprintf(stderr,   "-d decode\n");
fprintf(stderr,   "-e encode (default)\n");
exit(1);
}

#if defined(FLG_PROTOTYPE)
static void GetArgs(int argc, char *argv[])
#else
static void GetArgs(argc, argv)
int argc;
char *argv[];
#endif
{
int i;

while ((i = getopt(argc, argv,"cdehm:p:r:s:t:")) != EOF) {
  switch (i) {
    case 'c':
      AddCarriageReturns = !AddCarriageReturns;
      break;

    case 'd':
      decoding = TRUE;
      break;

    case 'e':
      decoding = FALSE;
      break;

    case 'm':
      strcpy(OpenMimicryName, optarg);
      break;

    case 'p':
      SetKey(optarg);
      SyncRandomBits();
      break;

    case 'r': 
      if (sscanf(optarg, "%d", &RightMargin) != 1 ||
	  RightMargin < 20) { /* don't be ridiculous! */
        fprintf(stderr, "Illegal right margin %s specified\n", optarg);
        exit(1);
        }
      break;

    case 's':
      strcpy(OpenSourceName, optarg);
      break;

    case 't':
      strcpy(TableDebugFile, optarg);
      break;

    case 'h':
    default:
      usage();
      break; /* for clarity */
    }
  }
}

#if defined(FLG_PROTOTYPE)
typedef void coolFuncType(void);
#else
typedef void coolFuncType();
#endif

/* Checks to make sure that the grammar is cool enough to allow this to
   happen.  */

/* mimicmaster */
#if defined(FLG_PROTOTYPE)
int main(int argc, char *argv[])
#else
int main(argc, argv)
int argc;
char *argv[];
#endif
{
/* The Top, The Tower of Pizza, The Top, The Smile on the Mona Lisa. */
InitEverything();

#if defined(THINK_C)
argc = ccommand(&argv);
#endif

if (argc < 2)
  usage();
if (argv[1][0] == '-') {
  fprintf(stderr, "No grammar file specified\n");
  usage();
  }
strcpy(OpenGrammarName, argv[1]); /* required argument */
argv[1] = argv[0]; /* to make getopt happier */
GetArgs(argc - 1, &argv[1]);

if (!LoadTable()) {
  fprintf(stderr, "An error-free grammar has not been loaded.\n");
  exit(1);
  }
if (decoding) {
  DoItAllLoop();
  }
else { /* encoding */
  DoSomeMimicry();
  }

FreeTable();
return 0;
}
