#define WORDS_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/
#include "global.h"

#include "words.h"

/* #define DebugNextWord TRUE for debugging */

/* The Scanning Hash Table has 256 entries. They identify a character as
   either, letter, stop character, a space or a comment. */
#if defined(FLG_PROTOTYPE)
void InitializeScanHashTable(void)
#else
void InitializeScanHashTable()
#endif
{
int i;

LastCharacter = Space;
for (i = 14; i <= 255; i ++)
  ScanTable[i] = Normal;
for (i = 0; i <= 13; i ++)
  ScanTable[i] = Spacer;
ScanTable['\n'] = Spacer;
ScanTable[EqualityCharacter] = Stopper;
ScanTable[StoppingCharacter] = Stopper;
ScanTable[' '] = Spacer;
}

/* Find the next word... */
#if defined(FLG_PROTOTYPE)
char *NextWord(char *StopChar)
#else
char *NextWord(StopChar)
char *StopChar;
#endif
{
#if 0
#define Space ' '  /* for clarity? */
#endif

int CurPos;
    /* This is the current position to be filled in the answer.... */
char CurLet; /* What comes out of the read. */
static word answer;

if (feof(OpenGrammarFile)) {
  *StopChar = EndOfFileSignifier;
  strcpy(answer, " ");
  }
else {
  CurPos = 0;
  memset(answer, 0, sizeof(answer));
  CurLet = LastCharacter;
  while (!feof(OpenGrammarFile) && ScanTable[CurLet] == Spacer)
    CurLet = fgetc(OpenGrammarFile);

  while (!feof(OpenGrammarFile) && ScanTable[CurLet] == Normal
      && CurPos < MaxLettersPerWord) {
    answer[CurPos] = CurLet;
    CurPos ++;
    CurLet = fgetc(OpenGrammarFile);
    }
  answer[CurPos] = Space;

  while (ScanTable[CurLet] == Spacer && !feof(OpenGrammarFile))
    CurLet = fgetc(OpenGrammarFile);

  if (feof(OpenGrammarFile)) {
    *StopChar = EndOfFileSignifier;
        /* If it is an end of file, return that as the end.... */
    }
  else
  if (CurPos == MaxLettersPerWord) { /* Ignore The Extra */
    while (!feof(OpenGrammarFile) && CurLet != Space)
      CurLet = fgetc(OpenGrammarFile);
    *StopChar = Space;
    }
  else {
    if (ScanTable[CurLet] == Normal) {
      LastCharacter = CurLet;
      *StopChar = Space;
        /* Just in case a return or line-feed enters the process. */
      }
    else {
      LastCharacter = Space;
      *StopChar = CurLet;
      }
    }
  }
#ifdef DebugNextWord
  printf("NW: %20s SC: %c\n", answer, *StopChar);
#endif
return answer;
}
