#define PARSER_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/
#include "global.h"

#include <setjmp.h>

#include "words.h"
#include "table.h"
#include "random.h"
#include "utl.h"

#include "parser.h"

/* #define ParserDebug TRUE for debugging */

#define MaxLookAhead 200
#define StandardLookAhead 20
    /* MaxLookAhead is the absolute maximum permitted by the sizes of the array.
       StandardLookAhead is the usual amount to search. Note that the running
       time is potentially exponential in the LookAhead... Don't be greedy.
       Sorry I didn't write a better algorithm. */

typedef int LookAheadAddress; /* 0 .. MaxLookAhead */
    /* This is the range of numbers kept for the lookahead table. */

static char LookAheadTable[MaxLookAhead + 1][MaxLettersPerWord + 1];
    /* The next MaxLookAhead words are kept in this circular array.
       When the end of file is found, the table contains NullWord. */

static int LookAheadOffset;
    /* Keeps track of where the first word will be. */

static long TempWord;
    /* This is where the bits are stored before they are written away... */

static int TempPosition;
    /* Starts at zero and works up to 31. */

static BoolType FoundAmbiguity;
    /* When the machine starts to do some parsing and discovers that there
       are two different paths for each production, this baby is set to true. */

static int SoftMaxLookAhead;
    /* This allows the parser to set its lookahead on the fly if it wants to
	increase it. */

static BoolType ReachedEndOfFile;
    /* Set true when everything is exhausted... */

static word firstLine;
static char *firstLinePtr;
static BoolType doneFirstLine;
static long expectedFileSize, actualCharsWritten;

#if defined(FLG_PROTOTYPE)
static BoolType CheckWordList(LookAheadAddress *MoreOffset, WordNode *www);
#else
static BoolType CheckWordList();
#endif

jmp_buf LABEL_199;

/* Sets up the lookahead buffer to keep all of the words in place. */
#if defined(FLG_PROTOTYPE)
static void InitLookAhead(void)
#else
static void InitLookAhead()
#endif
{
int i;
char Stopper; /* to be ignored. */

LookAheadOffset = 0;
for (i = 0; i <= MaxLookAhead - 1; i ++)
  strcpy(&LookAheadTable[i][0], NextWord(&Stopper));
}

/* This returns the next word in time delay. */
#if defined(FLG_PROTOTYPE)
static char *TimeDelayNextWord(void)
#else
static char *TimeDelayNextWord()
#endif
{
char stopper; /* The end... */
static word result;

strcpy(&result[0], LookAheadTable[LookAheadOffset]);
strcpy(LookAheadTable[LookAheadOffset], NextWord(&stopper));
if (stopper == EndOfFileSignifier)
  ReachedEndOfFile = TRUE;

#if defined(ParserDebug)
printf("TimeDelayNextWord (%d) = %s\n", LookAheadOffset, result);
#endif

LookAheadOffset = (LookAheadOffset + 1) % MaxLookAhead;
return result;
}

/* Sets up the file where the outputted bits will go... */
#if defined(FLG_PROTOTYPE)
static void OpenOutputFile(void)
#else
static void OpenOutputFile()
#endif
{
if (OpenSourceName[0] == '\0')
  OpenSourceFile = stdout;
else {
  OpenSourceFile = fopen(OpenSourceName, "w");
  if (OpenSourceFile == NULL) {
    perror(OpenSourceName);
    exit(1);
    }
  }

TempWord = 0;
TempPosition = 7;
ReachedEndOfFile = FALSE;
doneFirstLine = FALSE;
actualCharsWritten = 0;
firstLinePtr = &firstLine[0];
memset(firstLine, 0, sizeof(firstLine));
if (OpenMimicryName[0] == '\0')
  OpenGrammarFile = stdin;
else {
  /* Set to be OpenGrammarFile because that is what the WordEater is programmed
     to recognize. */
  OpenGrammarFile = fopen(OpenMimicryName, "r");
  if (OpenGrammarFile == NULL) {
    perror(OpenMimicryName);
    exit(1);
    }
  }

LastCharacter = Space;
  /* This is for initializing the WordEater. It must come BEFORE InitLookAHEAD
  */
InitLookAhead();
}

#if 0 /* not used? */
/* This stores the next bit. Note that they are coming off in reverse order
   this time... */
#if defined(FLG_PROTOTYPE)
static void StoreBit(BoolType b)
#else
static void StoreBit(b)
BoolType b;
#endif
{
if (TempPosition == 8) {
  }
if (b)
  TempWord |= 1 << TempPosition;
TempPosition ++;
}
#endif

/* This stores away a word in the right place... */
#if defined(FLG_PROTOTYPE)
static void StoreWord(long TheBits, int LastPos)
#else
static void StoreWord(TheBits, LastPos)
long TheBits;
int LastPos;
#endif
{
if (LastPos < TempPosition) {
  TempWord |= TheBits << (TempPosition - LastPos);
  TempPosition = TempPosition - LastPos - 1;
  }
else {
  TempWord |= TheBits >> (LastPos - TempPosition);
#if 0
  if (TempWord == 0x74202f2f)
    Error("Weird");
  printf("If Tempword=%x then a smaller version is: %x\n", &TempWord, TempWord);
#endif
  if (doneFirstLine) {
    if (expectedFileSize >= 0 && actualCharsWritten == expectedFileSize)
      longjmp(LABEL_199, TRUE);
				  /* this cast is needed by THINK_C!!! */
    fprintf(OpenSourceFile, "%c", (int)TempWord);
    actualCharsWritten ++;
    }
  else {
    *(firstLinePtr) ++ = TempWord;
    if (firstLinePtr >= &firstLine[sizeof(firstLine)]) {
      /* bogus, must be data */
      fprintf(OpenSourceFile, "%s", firstLine);
      expectedFileSize = -1;
      doneFirstLine = TRUE;
      }
    else
    if (TempWord == '\n') { /* first line is done */
      if (sscanf(firstLine, "%ld", &expectedFileSize) != 1 ||
	  expectedFileSize < 0) { /* weirdness, just output */
	fprintf(OpenSourceFile, "%s", firstLine);
        expectedFileSize = -1;
        }
      doneFirstLine = TRUE;
      }
    }

  TempWord = (TheBits & 0xff) << (8 - LastPos + TempPosition);
  TempPosition = 7 - LastPos + TempPosition;
  }
}

/* This returns the bits associated with a particular production by following
   the path up the root to the variable.
   Note that the bits will come off in the reverse order in which they were
   generated.
*/
#if defined(FLG_PROTOTYPE)
static void ProductionToBits(ProductionNode *p)
#else
static void ProductionToBits(p)
ProductionNode *p;
#endif
{
BitNode *BitPointer; /* This will lead the way. */
long TempBit; /* This will hold the bits... */
int BitCounter; /* This is position of the next bit to be stored. */

UpdateRandomBits();
/* Get a new group of random bits for the random generator... */
TempBit = 0;
BitCounter = 0;
BitPointer = p->itsBit;  /* We're not concerned about the first node because
			    it is just an interface. */
while (BitPointer->up != NULL) {
  if (BitPointer->polarity) {
    if (RandomBit(BitPointer->up->bitNumber))
      TempBit |= 1 << BitCounter;
    }
  else {
    if (!RandomBit(BitPointer->up->bitNumber))
      TempBit |= 1 << BitCounter;
    }
  BitPointer = BitPointer->up;
  BitCounter ++;
  if (BitCounter == 8) {
    StoreWord(TempBit, BitCounter - 1);
    TempBit = 0;
    BitCounter = 0;
    }
  }
StoreWord(TempBit, BitCounter - 1);
}


/* Imagine this case. You are now trying to decide whether the next token,
   say "Ernest" came for the production of a variable "*Dudes" or "*Duds". It
   could be from either. This tries to lookahead and see if there is any clue
   that says, "Hey, it can't be "*Dudes" because the production of the token
   "Ernest" is always followed by the token "Rex" to indicate his stature. */
#if defined(FLG_PROTOTYPE)
static ProductionNode *TokenInVariable(LookAheadAddress *MoreOffset,
    VariableNode *v)
#else
static ProductionNode *TokenInVariable(MoreOffset, v)
LookAheadAddress *MoreOffset;
VariableNode *v;
#endif
{
ProductionNode *ProductionNumber; /* Well not as much a number as a pun. */
BoolType OneFound;
    /* This is just set to look for ambiguities...Problems, you know.... */
LookAheadAddress tempOffset, RealOffset;
    /* This holds the temporary Offset that is passed to the CheckWordList
       function. */
ProductionNode *result = NULL;

ProductionNumber = v->productions;
OneFound = FALSE;
RealOffset = *MoreOffset;
while (ProductionNumber != NULL && !OneFound) {
  tempOffset = RealOffset;
  if (CheckWordList(&tempOffset, ProductionNumber->theWords)) {
#if defined(ParserDebug)
{
		WordNode *temp = ProductionNumber->theWords;

    printf("TokenInVariable found production of %s (%d): ", v->w1, tempOffset);
    while (temp != NULL) {
      printf("%s", temp->w1);
      temp = temp->next;
      }
    printf("\n");
}
#endif
    OneFound = TRUE;
    *MoreOffset = tempOffset - 1;
    result = ProductionNumber;
    }
  ProductionNumber = ProductionNumber->next;
  }
return result;
}

/* This compares the words in the word list with the words in the lookahead
   buffer.  If they all match, then BINGO! */
#if defined(FLG_PROTOTYPE)
static BoolType CheckWordList(LookAheadAddress *MoreOffset, WordNode *www)
#else
static BoolType CheckWordList(MoreOffset, www)
LookAheadAddress *MoreOffset;
WordNode *www;
#endif
{
WordNode *this = www;
LookAheadAddress newOffset = *MoreOffset;

while (newOffset < SoftMaxLookAhead && this != NULL) {
  if (this->w1[0] == VariableSignifier) {
    if (TokenInVariable(&newOffset, FindVariable(this->w1)) == NULL) {
      *MoreOffset = newOffset;
      return FALSE;
      }
    newOffset ++;
    this = this->next;
    }
  else
  if (CompareStrings(
      LookAheadTable[(newOffset + LookAheadOffset) % MaxLookAhead],
      this->w1) != 0) {
		*MoreOffset = newOffset;
    return FALSE;
    }
  else {
    newOffset ++;
    this = this->next;
    }
  }
#if defined(ParserDebug)
{
this = www;
printf("CheckWordList: match found (%d:%d), ", *MoreOffset, newOffset);
while (this != NULL) {
  printf("%s", this->w1);
  this = this -> next;
  }
printf("\n");

}
#endif
*MoreOffset = newOffset;
return TRUE;
}


/* Imagine this case. You are now trying to decide whether the next token,
   say "Ernest" came for the production of a variable "*Dudes" or "*Duds". It
   could be from either. This tries to lookahead and see if there is any clue
   that says, "Hey, it can't be "*Dudes" because the production of the token
   "Ernest" is always followed by the token "Rex" to indicate his stature. */

/* The Serious Version Checks for Parsing Ambiguities.... This is only done on
   the first call. You could get rid of this and just let the program choose
   the first production it finds. This will be faster, but it might lead to
   errors. I've chosen to include this because it is computationally difficult
   (at least for now) to ensure that CFLs are non-ambiguous. */
#if defined(FLG_PROTOTYPE)
static ProductionNode *SeriousTokenInVariable(LookAheadAddress *MoreOffset,
    VariableNode *v)
#else
static ProductionNode *SeriousTokenInVariable(MoreOffset, v)
LookAheadAddress *MoreOffset;
VariableNode *v;
#endif
{
ProductionNode *ProductionNumber; /* Well not as much a number as a pun. */
BoolType OneFound;
    /* This is just set to look for ambiguities...Problems, you know.... */
LookAheadAddress tempOffset, RealOffset, bestOffset;
    /* This holds the temporary Offset that is passed to the CheckWordList
       function. */
ProductionNode *result = NULL;

ProductionNumber = v->productions;
OneFound = FALSE;
RealOffset = *MoreOffset;
while (ProductionNumber != NULL) {
  tempOffset = RealOffset;
  if (OneFound) {
    if (CheckWordList(&tempOffset, ProductionNumber->theWords)) {
      if (tempOffset == bestOffset) {
	Error("Parsing Ambiguity Here!!! Try growing the lookahead. ");
	FoundAmbiguity = TRUE;
	return NULL;
	}
      else
      if (tempOffset > bestOffset) {
	bestOffset = tempOffset;
	result = ProductionNumber;
	}
      /* else ignore shorter match */
      }
    }
  else
  if (CheckWordList(&tempOffset, ProductionNumber->theWords)) {
    OneFound = TRUE;
    *MoreOffset = bestOffset = tempOffset;
    result = ProductionNumber;
    }
  ProductionNumber = ProductionNumber->next;
  }
return result;
}

/* This routine takes the frame and figures out which pointer would match... */
#if defined(FLG_PROTOTYPE)
static void DoFrame(MimicParseFrame *f)
#else
static void DoFrame(f)
MimicParseFrame *f;
#endif
{
ProductionNode *Prod;  /* This is the location of the pointer... */
MimicParseFrame *NewFrame; /* If a new frame is needed... */
LookAheadAddress CurrentDepth; /* Used to halt the spread of the search. */

FoundAmbiguity = FALSE;
SoftMaxLookAhead = StandardLookAhead;
CurrentDepth = 0;
Prod = SeriousTokenInVariable(&CurrentDepth, f->theVariable);
/* I realize that it is a bit of an overkill to use a big hammer like
   SeriousTokenInVariable, but it is late at night and I don't want to bother
   writing an elegant method that uses breadth first instead of depth-first. */
if (FoundAmbiguity) {
  FoundAmbiguity = FALSE;
  SoftMaxLookAhead = MaxLookAhead;
      /* This just doubles the lookahead for the fun of it... */
  CurrentDepth = 0;
  Prod = SeriousTokenInVariable(&CurrentDepth, f->theVariable);
  }
if (Prod == NULL) {
  Error("Problems in parsing.");
  Prod = SeriousTokenInVariable(&CurrentDepth, f->theVariable);
  longjmp(LABEL_199, TRUE);
  }
else
if (!FoundAmbiguity) { /* We've found something.... */
  ProductionToBits(Prod); /* Store the bits... */
  NEW(MimicParseFrame, NewFrame);
  f->theWordsToMatch = Prod->theWords;
  while (f->theWordsToMatch != NULL) {
    if (f->theWordsToMatch->w1[0] == VariableSignifier) {
      NewFrame->theVariable = FindVariable(f->theWordsToMatch->w1);
      DoFrame(NewFrame);
      }
    else {
      char *theOther = TimeDelayNextWord();

      if (CompareStrings(f->theWordsToMatch->w1, theOther) != 0) {
	fprintf(stderr,
	 "Problem in parsing the file.  The Word \"%s\" doesn't belong here.\n",
	   f->theWordsToMatch->w1);
	Error("well?");
	longjmp(LABEL_199, TRUE);
	}
      }
    f->theWordsToMatch = f->theWordsToMatch->next;
    }
  free(NewFrame);
  }
}

/* This sucker just keeps going... */
#if defined(FLG_PROTOTYPE)
void DoItAllLoop(void)
#else
void DoItAllLoop()
#endif
{
MimicParseFrame *BaseFrame; /* This is the first frame allocated. */

if (setjmp(LABEL_199) == 0) {
  SyncRandomBits();
  OpenOutputFile();
  NEW(MimicParseFrame, BaseFrame);
  BaseFrame->theVariable = GetStartVariable();
  do {
    DoFrame(BaseFrame);
    } while (!
        (ReachedEndOfFile && strcmp(LookAheadTable[LookAheadOffset], NullWord) == 0));
  free(BaseFrame);
  }
if (OpenSourceFile == stdout)
  fflush(stdout);
else
  fclose(OpenSourceFile);
OpenSourceFile = NULL;
if (OpenGrammarFile != stdin)
  fclose(OpenGrammarFile);
OpenGrammarFile = NULL;
}
