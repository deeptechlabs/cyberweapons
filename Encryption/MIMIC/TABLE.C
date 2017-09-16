#define TABLE_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/
#include "global.h"
#include "table.h"
#include "words.h"
#include "utl.h"

static BoolType WasThereNoError;
  /* Kept locally to determine if there was an error or not. */

#if defined(FLG_PROTOTYPE)
static void PrintWordList(FILE *f, WordNode *w)
#else
static void PrintWordList(f, w)
FILE *f;
WordNode *w;
#endif
{
while (w != NULL) {
  fprintf(f, "%s,", w->w1);
  w = w->next;
  }
fprintf(f, "\n");
}

#if defined(FLG_PROTOTYPE)
static void PrintProductionList(FILE *f, ProductionNode *p)
#else
static void PrintProductionList(f, p)
FILE *f;
ProductionNode *p;
#endif
{
while (p != NULL) {
  fprintf(f, "Production with P=%f:", p->probability);
  PrintWordList(f, p->theWords);
  p = p->next;
  }
fprintf(f, "---------------%%---------------\n");
}

#if defined(FLG_PROTOTYPE)
static void PrintVariableList(FILE *f, VariableNode *v)
#else
static void PrintVariableList(f, v)
FILE *f;
VariableNode *v;
#endif
{
while (v != NULL) {
  fprintf(f, "<><>Starting Variable: %20s <><><><><><><><>\n");
  PrintProductionList(f, v->productions);
  v = v->next;
  }
fprintf(f, "<><><><><><><><><><><><><><><><><><><>\n");
}

/* Prints out the grammar table so people can see what got read in correctly
   and what wasn't. */
#if defined(FLG_PROTOTYPE)
void PrintTable(void)
#else
void PrintTable()
#endif
{
FILE *f;

if (TableDebugFile[0] == '\0')
  return;
f = fopen(TableDebugFile, "w");
if (f == NULL) {
  perror(TableDebugFile);
  return;
  }
PrintVariableList(f, VariableListRoot);
fclose(f);
f = NULL;
}

#if defined(FLG_PROTOTYPE)
static void InitLoader(void)
#else
static void InitLoader()
#endif
{
VariableListRoot = NULL;
WasThereNoError = TRUE;
}

/* This procedure just keeps hitting NextWord until it hits the double
   StoppingCharacter, which when I wrote this line was defined to be '//'. */
#if defined(FLG_PROTOTYPE)
static void SkipToEnd(void)
#else
static void SkipToEnd()
#endif
{
word wa; /* For local reasons... */
char previous, stopper; /* To see why it ended... */

WasThereNoError = FALSE;

strcpy(wa, NextWord(&stopper));
do {
  previous = stopper;
  strcpy(wa, NextWord(&stopper));
  } while (! ((strcmp(wa, " ") == 0 &&
      previous == StoppingCharacter && stopper == StoppingCharacter)
    || stopper == EndOfFileSignifier));
}

/* This procedure prints out the message and then prints out the rest of the
   line. */
#if defined(FLG_PROTOTYPE)
static void LocalMinorError(char message[])
#else
static void LocalMinorError(message)
char message[];
#endif
{
word wa; /* For local reasons... */
char previous, stopper; /* To see why it ended... */

WasThereNoError = FALSE;

fprintf(stderr, "%s\n", message);
strcpy(wa, NextWord(&stopper));
do {
  printf("%s%c", wa, stopper);
  previous = stopper;
  strcpy(wa, NextWord(&stopper));
  } while (!((strcmp(wa, " ") == 0 &&
        previous == StoppingCharacter && stopper == StoppingCharacter)
     || stopper == EndOfFileSignifier));
fprintf(stderr, "%s%c\n", wa, stopper);
fprintf(stderr, "That line was ignored.\n");
}

/* This procedure prints out the message and then prints out the rest of the
   line. */
#if defined(FLG_PROTOTYPE)
static void LocalMinorErrorNoPrint(char message[])
#else
static void LocalMinorErrorNoPrint(message)
char message[];
#endif
{
word wa; /* For local reasons... */
char previous, stopper; /* To see why it ended... */

WasThereNoError = FALSE;

fprintf(stderr, "%s\n", message);
strcpy(wa, NextWord(&stopper));
do {
  previous = stopper;
  strcpy(wa, NextWord(&stopper));
  } while (!( (strcmp(wa, " ") == 0 && previous == StoppingCharacter &&
       stopper == StoppingCharacter) || stopper == EndOfFileSignifier));
fprintf(stderr, "The rest of the line was ignored.\n");
}

/* Returns -1 if st1<st2, 0 if st1=st2 and 1 if st1>st2. Assumes they end with
   a space. */
#if defined(FLG_PROTOTYPE)
int CompareStrings(char st1[], char st2[])
#else
int CompareStrings(st1, st2)
char st1[];
char st2[];
#endif
{
int i;

i = 0;
while (st1[i] == st2[i] && st1[i] != ' ')
  i++;
if (st1[i] == st2[i])
  return 0;
if (st1[i] < st2[i])
  return -1;
return 1;
}

/* This adds it to the root. */
#if defined(FLG_PROTOTYPE)
static void AddVariable(VariableNode *v)
#else
static void AddVariable(v)
VariableNode *v;
#endif
{
VariableNode *previous, *node; /* For scanning along the list. */
int Relativity;

node = VariableListRoot;
if (VariableListRoot == NULL) {
  VariableListRoot = v;
  v->next = NULL;
  }
else
if (CompareStrings(node->w1, v->w1) == 1) {
  VariableListRoot = v;
  v->next = node;
  }
else {
  while (node != NULL) {
    Relativity = CompareStrings(node->w1, v->w1);
    if (Relativity == -1) {
      previous = node;
      node = node->next;
      }
    else
    if (Relativity == 0) {
      char junk[256];

      sprintf(junk, "\"%s\" has Been previously defined.", v->w1);
      LocalMinorError(junk);
      }
    else {
      previous->next = v;
      v->next = node;
      node = NULL;
      v = NULL; /* To signal that it was added... */
      }
    }
  if (v != NULL) {
    previous->next = v;
    v->next = NULL;
    }
  }
}

/* Looks up the list and finds the variable corresponding to it.
   Note that everything is extremely slow to just keep this in a list! */
#if defined(FLG_PROTOTYPE)
VariableNode *FindVariable(char name[])
#else
VariableNode *FindVariable(name)
char name[];
#endif
{
VariableNode *temp; /* Sort of a stunt double for FindVariable. */
int relativity; /* Just for storing the relative differences between strings. */

temp = VariableListRoot; /* Start at the very beginning. */
while (temp != NULL) {
  relativity = CompareStrings(name, temp->w1);
  if (relativity > 0)
    temp = temp->next;
  else
  if (relativity == 0)
    return temp;
  else 
    return NULL;
  }
return NULL;
}

/* The first word in a line must be a variable. This will be used to set up
   the variable list... */
#if defined(FLG_PROTOTYPE)
static BoolType HandleFirst(void)
#else
static BoolType HandleFirst()
#endif
{
VariableNode *v; /* This is what is going to get built... */
word wa; /* For local reasons... */
char stopper; /* To see why it ended... */

strcpy(wa, NextWord(&stopper));
if (stopper == EndOfFileSignifier) {
  if (strcmp(wa, NullWord) != 0)
    Error("Unexpected end of the file.");
  return FALSE;
  }
if (strcmp(wa, " ") == 0 || wa[0] != VariableSignifier)
  LocalMinorError("Expected a variable name at the beginning of the line:");
else {
  NEW(VariableNode, v);
  strcpy(v->w1, wa);
  v->productions = NULL;
  v->itsBitRoot = NULL;
  /* Now add it to the list in the right place... */
  AddVariable(v);
  CurrentVariable = v;
  }
if (stopper != EqualityCharacter) {
  do {
    strcpy(wa, NextWord(&stopper));
    } while (stopper == Space && strcmp(wa, NullWord) == 0);
  if (strcmp(wa, NullWord) != 0) {
    char junk[256];

    sprintf(junk,
"The Variable should only be one word.  \"%s\" is too much.  Error in line:",
        wa);
    LocalMinorError(junk);
    }
  }
return TRUE;
}

/* Returns the real value of the string contained in w. Signals an error if
   there is a problem. */
#if defined(FLG_PROTOTYPE)
static double WordToValue(char w[], BoolType *Error)
#else
static double WordToValue(w, Error)
char w[];
BoolType *Error;
#endif
{
double temp;

*Error = FALSE;
if (sscanf(w, "%lf", &temp) == 1)
  return temp;
*Error = TRUE;
return 0.0;
}

/* Keeps Adding Production until it encounters a double Stopping Character. */
#if defined(FLG_PROTOTYPE)
static BoolType HandleProduction(void)
#else
static BoolType HandleProduction()
#endif
{
WordNode *LastAddedWord;
  /* This is just a place keeper which points to the last word added so the
     next can be updated when another one is added. */
ProductionNode *TheProduction; /* This is where the info goes... */
word wa; /* For local reasons... */
char stopper; /* To see why it ended... */
BoolType startedVariables;
  /* Variables can only come at the end of productions... */
BoolType isError; /* If there is a problem this get's set to be true. */

LastAddedWord = NULL;
TheProduction = NULL;
do {
  do {
    strcpy(wa, NextWord(&stopper));
    if (stopper == EndOfFileSignifier) {
      if (LastAddedWord != NULL) {
	fprintf(stderr, 
            "Just parsed something left incomplete by the end of the file:\n");
	PrintWordList(stderr, LastAddedWord);
	Error("Unexpected end of the file.");
	return FALSE;
	}
      return TRUE;
      }
    if (strcmp(wa, NullWord) != 0) {
      if (LastAddedWord == NULL) { /* Start a new production... */
	if (wa[0] == VariableSignifier) {
          char junk[256];

	  sprintf(junk, "The first word of a production, \"%s\", cannot be a variable.  Ignoring Production.", wa);
	  Error(junk);
	  SkipToEnd();
	  stopper = StoppingCharacter;
	  strcpy(wa, NullWord);
	  }
	else {
	  NEW(ProductionNode, TheProduction);
	  TheProduction->next = CurrentVariable->productions;
	  CurrentVariable->productions = TheProduction;
		/* Put it at the beginning of the list... */
	  NEW(WordNode, LastAddedWord);
	  TheProduction->theWords = LastAddedWord;
	  strcpy(LastAddedWord->w1, wa);
	  startedVariables = FALSE;
	  }
	}
      else {
    NEW(WordNode, LastAddedWord->next);
	LastAddedWord = LastAddedWord->next;
	strcpy(LastAddedWord->w1, wa);
	if (wa[0] == VariableSignifier)
	  startedVariables = TRUE;
	else
        if (startedVariables) {
	  LocalMinorError("The format of a production is terminal, terminal ... terminal, variable... variable. A terminal comes before the variable in line:");
	  CurrentVariable->productions = NULL;
		/* Clean out this baby to signal a problem. */
	  }
	}
      }
    } while (stopper != StoppingCharacter);
  if (LastAddedWord != NULL) {
    LastAddedWord->next = NULL;
    LastAddedWord = NULL;
    }

  if (strcmp(wa, NullWord) != 0) {
    /* At this point a production has been stored away. Now get its
       probability... */
    strcpy(wa, NextWord(&stopper));
    if (stopper == EndOfFileSignifier) {
      Error("Unexpected end of the file.");
      return FALSE;
      }
    TheProduction->probability = WordToValue(wa, &isError);
    if (isError) {
      char junk[256];

      sprintf(junk, "The word \"%s\" does not translate into a number.", wa);
      LocalMinorErrorNoPrint(junk);
      fprintf(stderr, "The error occurs in production:");
      PrintWordList(stderr, LastAddedWord);
      }
    else
    if (stopper != StoppingCharacter) {
      char junk[256];

      strcpy(wa, NextWord(&stopper));
      sprintf(junk, "The word \"%s\" does not belong in the probability field.",
          wa);
      LocalMinorErrorNoPrint(junk);
      fprintf(stderr, "The error occurs in production:");
      PrintWordList(stderr, LastAddedWord);
      }
    }
  } while (strcmp(wa, NullWord) != 0);
return TRUE;
}

/* This is just a temporary procedure that maintains a list of BitNodes
   Sorted by Probability. */
#if defined(FLG_PROTOTYPE)
static void InsertIntoBitList(BitNode *node, BitNode **ListStart)
#else
static void InsertIntoBitList(node, ListStart)
BitNode *node;
BitNode **ListStart;
#endif
{
BitNode *previous, *Scanner; /* For scanning along the list. */

if (*ListStart == NULL) {
  *ListStart = node;
  node->up = NULL;
  }
else
if (node->probability <= (*ListStart)->probability) {
  node->up = *ListStart;
  *ListStart = node;
  }
else {
  Scanner = *ListStart;
  while (Scanner != NULL) {
    if (node->probability > Scanner->probability) {
      previous = Scanner;
      Scanner = Scanner->up;
      }
    else {
      previous->up = node;
      node->up = Scanner;
      Scanner = NULL;
      node = NULL; /* To signal that it was added... */
      }
    }
  if (node != NULL) {
    previous->up = node;
    node->up = NULL;
    }
  }
}


/* It is important that there be a tree that describes how the bits are
   assigned to each production... */
#if defined(FLG_PROTOTYPE)
static void BuildBitTable(void)
#else
static void BuildBitTable()
#endif
{
BitNode *IntermediateBitList;
    /* This contains the list of bit nodes that don't have a root. When there
       is only one left, then this is crowned king and assigned to the
       variable's ItsBitRoot. */
BitNode *TempBit; /* Used in the building... */
ProductionNode *productionList;
    /* This is the list of productions that the bit list will be built out
	of... */
int NextBitNumber;
    /* This is used for assigning a unique number to each node... */
VariableNode *v;
    /* This is so the list can do this for every variable... */

v = VariableListRoot;
while (v != NULL) {
  productionList = v->productions; /* This is the list... */
  IntermediateBitList = NULL;
  NextBitNumber = 0;
  while (productionList != NULL) {
    NEW(BitNode, TempBit);
    TempBit->probability = productionList->probability;
    TempBit->left = NULL;
    TempBit->right = NULL;
    TempBit->polarity = TRUE;
    TempBit->bitNumber = -1;
    TempBit->theProductionNode = productionList;

    productionList->itsBit = TempBit;
    InsertIntoBitList(TempBit, &IntermediateBitList);
    productionList = productionList->next;
    }
/* Now one bit for each production list, let's start making pairs... */
  while (IntermediateBitList->up != NULL) {
    /* While there is more than one node in the list... */
    NEW(BitNode, TempBit);
    TempBit->probability = IntermediateBitList->probability +
	IntermediateBitList->up->probability;
    TempBit->left = IntermediateBitList;
    TempBit->right = IntermediateBitList->up;
    TempBit->bitNumber = NextBitNumber;
    TempBit->polarity = TRUE;
    NextBitNumber++;
    TempBit->theProductionNode = NULL;

    IntermediateBitList = IntermediateBitList->up->up;
	/* Get Rid of the top two... */
    TempBit->left->polarity = FALSE;
	/* Flip one... One son should be true and the other false. */
    TempBit->left->up = TempBit;
    TempBit->right->up = TempBit;
    InsertIntoBitList(TempBit, &IntermediateBitList);
    }
/* There should only be one left at this point... */
  v->itsBitRoot = IntermediateBitList;
  IntermediateBitList->up = NULL;
  v = v->next;
  }
}


/* This returns the variable that starts out every production.
   This is just set to be the first one in the list. The first alphabetically.
   It would be possible to put some sort of random selection here too if
   you wanted to add an additional signifier that said "I'm a good candidate
   to start a production." */
#if defined(FLG_PROTOTYPE)
VariableNode *GetStartVariable(void)
#else
VariableNode *GetStartVariable()
#endif
{
return VariableListRoot;
}


/* This function tries to load the information from the currently opened file
   into table.
   Returns true if it succeeds. False if it signals an error. */
#if defined(FLG_PROTOTYPE)
BoolType LoadTable(void)
#else
BoolType LoadTable()
#endif
{
BoolType looping;

InitLoader();
OpenGrammarFile = fopen(OpenGrammarName, "r");
if (OpenGrammarFile == NULL) {
  perror(OpenGrammarName);
  return FALSE;
  }
VariableListRoot = NULL;
looping = TRUE;
while (looping)
  if (HandleFirst())
    looping = HandleProduction();
  else
    looping = FALSE;
BuildBitTable();
PrintTable();
fclose(OpenGrammarFile);
OpenGrammarFile = NULL;
return WasThereNoError;
}

#if defined(FLG_PROTOTYPE)
static void freeBitNodes(BitNode *b)
#else
static void freeBitNodes(b)
BitNode *b;
#endif
{
if (b->left != NULL) {
  freeBitNodes(b->left);
  free(b->left);
  b->left = NULL;
  }
if (b->right != NULL) {
  freeBitNodes(b->right);
  free(b->right);
  b->right = NULL;
  }
b->theProductionNode = NULL; /* for completeness */
}

#if defined(FLG_PROTOTYPE)
static void freeProductionNode(ProductionNode *p)
#else
static void freeProductionNode(p)
ProductionNode *p;
#endif
{
WordNode *thisw = p->theWords;
WordNode *nextw;

/* Clear word list */
while (thisw != NULL) {
  nextw = thisw->next;
  thisw->next = NULL;
  free(thisw);
  thisw = nextw;
  }
p->itsBit = NULL; /* for cleanness */
}

#if defined(FLG_PROTOTYPE)
static void freeVariableNode(VariableNode *v)
#else
static void freeVariableNode(v)
VariableNode *v;
#endif
{
ProductionNode *thisp = v->productions;
ProductionNode *nextp;

/* Remove production nodes */
while (thisp != NULL) {
  freeProductionNode(thisp);
  nextp = thisp->next;
  thisp->next = NULL;
  free(thisp);
  thisp = nextp;
  }
/* remove bit tree */
if (v->itsBitRoot != NULL) {
  freeBitNodes(v->itsBitRoot);
  free(v->itsBitRoot);
  v->itsBitRoot = NULL;
  }
v->productions = NULL;
}

#if defined(FLG_PROTOTYPE)
void FreeTable(void)
#else
void FreeTable()
#endif
{
VariableNode *v, *next;

v = VariableListRoot;
while (v != NULL) {
  freeVariableNode(v);
  next = v->next;
  v->next = NULL;
  free(v);
  v = next;
  }
}
