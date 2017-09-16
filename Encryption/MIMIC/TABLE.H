#if !defined(TABLE_H)
#define TABLE_H TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

#if defined(THINK_C)
#if defined(TABLE_C)
#define VAR
#else
#define VAR extern
#endif /* TABLE_C */
#else
#define VAR
#endif /* THINK_C */

VAR char TableDebugFile[255 + 1]; /* This is the name of the file. */

#if defined(FLG_PROTOTYPE)
BoolType LoadTable(void);
#else
BoolType LoadTable();
#endif
  /* This function tries to load the information from the currently opened
     file into table.  Returns true if it succeeds. False if it signals an
     error. */

#if defined(FLG_PROTOTYPE)
VariableNode *FindVariable(char Name[]);
#else
VariableNode *FindVariable();
#endif
  /* Looks up the list and finds the variable corresponding to it.
     Note that everything is extremely slow to just keep this in a list! */

#if defined(FLG_PROTOTYPE)
void PrintTable(void);
#else
void PrintTable();
#endif
  /* Prints out the grammar table so people can see what got read in correctly
     and what wasn't. */

#if defined(FLG_PROTOTYPE)
int CompareStrings(char st1[], char st2[]);
#else
int CompareStrings();
#endif
  /* Returns -1 if st1<st2, 0 if st1=st2 and 1 if st1>st2. Assumes they end
     with a space. */

#if defined(FLG_PROTOTYPE)
VariableNode *GetStartVariable(void);
#else
VariableNode *GetStartVariable();
#endif
  /* This returns the variable that starts out every production.
     This is just set to be the first one in the list. The first
     alphabetically.

     It would be possible to put some sort of random selection here too if
     you wanted to add an additional signifier that said "I'm a good candidate
     to start a production." */

#if defined(FLG_PROTOTYPE)
void FreeTable(void);
#else
void FreeTable();
#endif

#undef VAR

#endif /* TABLE_H */
