#define OUTSPLIT_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

#include "global.h"
#include "outsplit.h"
#include "random.h"
#include "table.h"
#include "utl.h"

static BoolType AtTheEndOfFile;
			/* This is set to be true when we get to the end... */
static long SourceBits; /* The current longint read in from the file. */
static int SourcePosition; /* The next bit to be read. */
static MimicProdNode *TheOutputStack;
                        /* This is the stack of variables that are
			   un produced... */
static int CarriagePosition;
			/* This is the location of the last character printed
			   out on the page. For justification. */

/* We write the size of the output file as a line at the beginning
   of the file. */
static word sizeString;
static char *sizeStringPtr;

#if defined(FLG_PROTOTYPE)
static void DoStack(MimicProdNode *s);
#else
static void DoStack();
#endif


/* This opens up a pair of files for producing mimicry. */
#if defined(FLG_PROTOTYPE)
static void OpenForOutput(void)
#else
static void OpenForOutput()
#endif
{
if (OpenSourceName[0] == '\0') {
  OpenSourceFile = stdin;
  strcpy(sizeString, "-1\n");
  }
else {
  OpenSourceFile = fopen(OpenSourceName, "r");
  if (OpenSourceFile == NULL) {
    perror(OpenSourceName);
    exit(1);
    }
#if defined(THINK_C)
  /* No fstat() call! Have to fake it! */
  fseek(OpenSourceFile, 0, SEEK_END);
  sprintf(sizeString, "%ld\n", ftell(OpenSourceFile));
  fseek(OpenSourceFile, 0, SEEK_SET);
#else
{
  struct stat buf;
  
  if (fstat(fileno(OpenSourceFile), &buf) == -1) {
    fprintf(stderr, "stat(%s) failure\n", OpenSourceName);
    perror("fstat");
    exit(1);
    }
  sprintf(sizeString, "%ld\n", buf.st_size);
}
#endif /* THINK_C */
  }

SourcePosition = 7;
CarriagePosition = 0;
sizeStringPtr = &sizeString[0];
SourceBits = *(sizeStringPtr ++);
TheOutputStack = NULL;
if (OpenMimicryName[0] == '\0')
  OpenMimicryFile = stdout;
else {
  OpenMimicryFile = fopen(OpenMimicryName, "w");
  if (OpenMimicryFile == NULL) {
    perror(OpenMimicryName);
    exit(1);
    }
  }
}

#if defined(FLG_PROTOTYPE)
void nextChar(void)
#else
void nextChar()
#endif
{
if (*sizeStringPtr != '\0') {
  SourceBits = *(sizeStringPtr ++);
  }
else
if (AtTheEndOfFile)
  SourceBits = ReserveBits;
else {
  SourceBits = fgetc(OpenSourceFile);
  if (SourceBits == -1) {
    AtTheEndOfFile = TRUE;
    SourceBits = ReserveBits;
    }
  }
SourcePosition = 7;
}

/* Pulls off the next bit... */
#if defined(FLG_PROTOTYPE)
static BoolType NextBit(void)
#else
static BoolType NextBit()
#endif
{
/* Following table provides efficiency of shift and mask */
static const unsigned char masks[8] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

if (SourcePosition == -1)
  nextChar();
return (SourceBits & masks[SourcePosition --]) != 0;
}

/* This baby takes a variable and follows its way down to the production
   using the bit tree. */
#if defined(FLG_PROTOTYPE)
static ProductionNode *VariableToProduction(VariableNode *v)
#else
static ProductionNode *VariableToProduction(v)
VariableNode *v;
#endif
{
BitNode *Bitto; /* This is the position that the bit tree should follow. */

UpdateRandomBits(); /* Cycle the random number generator. */
Bitto = v->itsBitRoot;
while (Bitto->theProductionNode == NULL) {
  if (NextBit()) {
    if (RandomBit(Bitto->bitNumber))
      Bitto = Bitto->right;
    else
      Bitto = Bitto->left;
    }
  else {
    if (RandomBit(Bitto->bitNumber))
      Bitto = Bitto->left;
    else
      Bitto = Bitto->right;
    }
  }
return Bitto->theProductionNode; /* TheAnswer. */
}

/* This will do the correct thing with the word node w.
   If it is a terminal, it will write it out. Otherwise it will start a new
   frame... */
#if defined(FLG_PROTOTYPE)
static void DoWord(WordNode *w)
#else
static void DoWord(w)
WordNode *w;
#endif
{
MimicProdNode *StackFrame; /* For creating new ones... */

if (w->w1[0] == VariableSignifier) {
  NEW(MimicProdNode, StackFrame);
  StackFrame->next = TheOutputStack;
  TheOutputStack = StackFrame;
  StackFrame->ww = VariableToProduction(FindVariable(w->w1))->theWords;
  DoStack(StackFrame);
  }
else {
  /* Write it out... */
  fprintf(OpenMimicryFile, "%s", w->w1);
  /* Assuming there is a space at the end of each word. */
  if (AddCarriageReturns) {
    CarriagePosition += strlen(w->w1);
    if (CarriagePosition > RightMargin) {
      fprintf(OpenMimicryFile, "\n");
      CarriagePosition = 0;
      }
    }
  }
}

/* This just goes through the list of words on the stack until they are gone. */
#if defined(FLG_PROTOTYPE)
static void DoStack(MimicProdNode *s)
#else
static void DoStack(s)
MimicProdNode *s;
#endif
{
WordNode *wurds;
MimicProdNode *junk;

wurds = s->ww;
while (wurds != NULL) {
  DoWord(wurds);
  wurds = wurds->next;
  }
junk = TheOutputStack;
TheOutputStack = TheOutputStack->next;
free(junk);
}


/* This keeps it all going until the end... */
#if defined(FLG_PROTOTYPE)
void DoSomeMimicry(void)
#else
void DoSomeMimicry()
#endif
{
SyncRandomBits();
OpenForOutput();
while (!AtTheEndOfFile) {
  NEW(MimicProdNode, TheOutputStack);
  TheOutputStack->ww = VariableToProduction(GetStartVariable())->theWords;
  DoStack(TheOutputStack);
  }
if (OpenSourceFile != stdin)
  fclose(OpenSourceFile);
OpenSourceFile = NULL;
if (OpenMimicryFile == stdout)
  fflush(OpenMimicryFile);
else
  fclose(OpenMimicryFile);
OpenMimicryFile = NULL;
}
