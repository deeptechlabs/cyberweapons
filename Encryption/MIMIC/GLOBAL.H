#if !defined(GLOBAL_H)
#define GLOBAL_H TRUE

/* This file contains global includes.  It must be the FIRST file included
   by all .c files!!!!!
*/

/* 
   Copyright 1991 Peter Wayner
   The copyright holds for each file individually and for the collection as a
   whole.
   All rights reserved.

   This code is NOT in the public domain, but you are free
   to make duplicates and share it with friends (and enemies)
   as long as you meet the following conditions:

   1) No charge is made for the copy beyond the cost of the
   media and the shipping. Any handling charges must be below $3.00
   per disk.

   2) The software is distributed with this copyright notice intact.

   3) Any modifications are clearly marked with the date, time and
   author of the changes.

   4) No charge is made for any derivative work.

   5) Any derivative works contains this copyright notice intact.

   6) Any derivative work cannot contain more restrictive covenants than
   the one I have provided here. You can, for instance, place your
   modifications in the public domain, but you cannot restrict your
   version to the state of Utah.

   7) No attempt is made to export the software outside of the United
   States. Although I think that MimicFunctions might be considered more
   a parlour trick than a legitimate threat to DES, it is unclear what
   the government will think, feel or do about it. Even though these
   rules may seem silly in the age of peristroika and the global community
   brought about by lightening fast networks, the law is slower to
   change.

   There are additional notes at the beginning of MimicGlobals.p
*/

/*
If you make any substantial changes or enhance the capabilities of the system,
please send me a copy of the new version. I'd like to keep track of the system
and keep the best version available to everyone. Also, if you write good
grammars I would like to receive copies of them. I plan to maintain a bit of
an archive so people can get plenty of neat grammars.

My addresses are:
Peter Wayner , 116 Oak Avenue, Ithaca, New York 14850
 or Department of Computer Science, Cornell University, Ithaca, NY 14853
My phone numbers are: 607-277-6678 or 607-255-9202
My electronic address is: wayner@cs.cornell.edu (prefered)
 or "pwayner" on BIX.
You can reach me via Compuserve by sending mail to :
  "INTERNET>wayner@cs.cornell.edu"
*/

#include <stdio.h>
#include <sys/types.h>

#if defined(THINK_C)
#include <unix.h>
#include <string.h>
#include <stdlib.h>
#else
#include <sys/stat.h>
#endif /* THINK_C */

#if defined(__GNUC__) || defined(MSDOS) || defined(THINK_C)
/* ANSI C */
#define FLG_PROTOTYPE TRUE

#if defined(THINK_C)
#define const
#define volatile
#endif /* THINK_C */

#else
/* K&R C */
#define const
#define volatile
#endif

typedef unsigned char BoolType;
#if !defined(FALSE)
#define FALSE 0
#define TRUE 1
#endif

#if defined(FLG_PROTOTYPE)
void exit(int status);
#else
void exit();
#endif

#if defined(FLG_PROTOTYPE)
int fgetc(FILE *f);
#else
int fgetc();
#endif

#if defined(FLG_PROTOTYPE)
int fclose(FILE *f);
#else
int fclose();
#endif

#if defined(FLG_PROTOTYPE)
int fflush(FILE * f);
#else
int fflush();
#endif

#if defined(FLG_PROTOTYPE)
int fprintf(FILE *f, const char controlStr[], ...);
#else
int fprintf();
#endif

#if defined(FLG_PROTOTYPE)
void free(void *ptr);
#else
void free();
#endif

#if !defined(THINK_C)
#if defined(FLG_PROTOTYPE)
void *malloc(unsigned int size);
#else
int malloc();
#endif
#endif /* THINK_C */

#if !defined(THINK_C)
#if defined(FLG_PROTOTYPE)
void *memset(void *s, int character, unsigned int size);
#else
char *memset();
#endif
#endif /* THINK_C */

#if defined(FLG_PROTOTYPE)
void perror(const char msg[]);
#else
void perror();
#endif

#if defined(FLG_PROTOTYPE)
int printf(const char controlStr[], ...);
#else
int printf();
#endif

#if 0
#if !defined(ultrix) 
#if defined(FLG_PROTOTYPE)
int sprintf(char target[], const char controlStr[], ...);
#else
int sprintf(); 
#endif
#endif 
#endif

#if defined(FLG_PROTOTYPE)
int sscanf(const char theStr[], const char controlStr[], ...);
#else
int sscanf();
#endif

#if defined(FLG_PROTOTYPE)
int fstat(int fd, struct stat * buf);
#else
int fstat();
#endif

#if defined(FLG_PROTOTYPE)
int strcmp(const char str1[], const char str2[]);
#else
int strcmp();
#endif

#if defined(FLG_PROTOTYPE)
char *strcpy(char target[], const char src[]);
#else
char *strcpy();
#endif

#if !defined(THINK_C)
#if defined(FLG_PROTOTYPE)
int strlen(const char str[]);
#else
int strlen();
#endif
#endif /* THINK_C */

#if !defined(THINK_C)
#if defined(FLG_PROTOTYPE)
int strncmp(const char str1[], const char str2[], unsigned int len);
#else
int strncmp();
#endif
#endif /* THINK_C */

#define NEW(type, ptr) { \
  ptr = (type *)malloc(sizeof(type)); \
  if (ptr == NULL) { \
     fprintf(stderr, "malloc failure\n"); \
     exit(1); \
     } \
   }

/* This section contains all of the global definitions that are necessary to
   run the Mimic Function Generator/Parser. */

#define MaxLettersPerWord 40
  /* The maximum letters in each word. This might be better left large,
     although it does waste space in these cases. */

#define	StoppingCharacter '/'
  /* In the definition of section where the grammar is defined, this character
     is used to separate the different productions that could occur. When it
     occurs twice, it signifies the end of the production... */

#define	VariableSignifier  '*'
  /* If the first character of a word equals this then the program shall treat
     the word as a variable which will undergo more transformations. Note the
     program ASSUMES that a variable is one word. */

#define	EqualityCharacter  '='
  /* There is a character which signifies the equality between a variable and
     set of productions. */

#define	EndOfFileSignifier '\0'
  /* This is passed back from NextWord when it finds it is at the end of the
     file... */

#define	NullWord  " "
  /* This is what comes back from NextWord if it can't find something... */

#define	Space ' '
  /* This is something different, but the same. It is the same thing, but used
     in a different fashion. */

#define ReserveBits  0x55
  /* When MimicMan runs out of bits in the file, he still might need to finish
     up a production.  ReserveBits let this be done... */

typedef char word[MaxLettersPerWord + 1]; /* This is the standard unit... */

typedef enum {Normal, Stopper, Spacer} ScanTableResponses;
    /* Used in NextWord to make quick decisions about character. */


/* These are the node types constructed for the table
   which holds the grammar. */
typedef struct _wordnode {
  word w1; /* The word stored at this point... */
  struct _wordnode *next; /* The Next in the list... */
  } WordNode;


typedef struct _bitnode {
  int bitNumber;  /* This is the number of a central registers of bits. */
  BoolType polarity;
		  /* If True, then it is the same as Bits[BitNumber]
		     otherwise it is reversed. */
  double probability;
		  /* This is the total probability of all subordinate nodes. */
  struct _bitnode *up; /* This is the precursor... */
  struct _bitnode *left, *right; /* Because This is a tree... */
  struct _productionnode *theProductionNode;
		  /* Well, technically, I could get away with storing this
		     pointer in either left or right because left and right
		     will equal nil if and only if TheProductionNode <> nil,
		     but I don't feel like packing this too tightly right now.
		     I'm being lavish with memory. */
  } BitNode;


typedef struct _productionnode {
  double probability;
      /* The Probability that this particular production will be chosen. */
  BitNode *itsBit;
      /* Follow this up to the root to find the bits associated with this
	 production. */
  WordNode *theWords;
      /* This is the list of words that come from the Production. Variables
	 are at the end. */
  struct _productionnode *next; /* This is the next in the list... */
  } ProductionNode;

typedef struct _variablenode {
  word w1; 	/* This is the identity of the variable... */
  ProductionNode *productions; /* This is the list of productions.... */
  BitNode *itsBitRoot;
	  /* This is the top of the bit tree. When random characters are being
	     generated, it follows this down to the bottom... */
  struct _variablenode *next; /* One thing before the other... */
  } VariableNode;

typedef struct _mimicprodnode {
  WordNode *ww; /* This is where the next word to be dealt with... */
  struct _mimicprodnode *next; /* The next one down. */
  } MimicProdNode;

typedef struct {
  VariableNode *theVariable;
      /* This is the variable that is being considered at this point... */
  WordNode *theWordsToMatch;
      /*Once a production is matched, this baby is loaded with words to check.*/
  } MimicParseFrame;

#if defined(THINK_C)
#if defined(MIMIC_C)
#define VAR
#else
#define VAR extern
#endif /* MIMIC_C */
#else
#define VAR
#endif

VAR FILE *OpenGrammarFile; /* This is the file that is opened at the time. */
VAR char OpenGrammarName[255 + 1]; /* This is the name of the file. */

VAR FILE *OpenMimicryFile;
    /* This is the file that Mimicry will either be read out of or pushed into
       in the process of parsing or producing text. */
VAR char OpenMimicryName[255 + 1]; /* This is the name of the file. */

VAR FILE *OpenSourceFile; 
    /* This is the file of data that is used to generate the mimicry.
       Originally this was a file of long integers but sometimes there are an
       odd number of bytes in a file and this got munged. For some reason, the
       type "byte" doesn't work here. "QDbyte" seems to work, even though I
       can't seem to find the word in the documentation. */

VAR char OpenSourceName[255 + 1]; /* This is the name of the file. */


VAR ScanTableResponses ScanTable[256];
    /* Used by NextWord to speed up the classification procedure. */

VAR VariableNode *VariableListRoot;
    /* This is the list of variables contained in the list... */

VAR VariableNode *CurrentVariable;
    /* This is a global containing the current variable that productions are
       being added to... */

VAR char LastCharacter; /* This is last character read in NextWord. */

VAR BoolType AddCarriageReturns;
    /*Set to true if the program should insert carriage returns in the output.*/

VAR int RightMargin;
    /* When this boundary is crossed, the carriage returns will be included. */

#undef VAR

#endif /* GLOBAL_H */
