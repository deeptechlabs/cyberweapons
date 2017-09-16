#if !defined(WORDS_H)
#define WORDS_H TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

/* I've named this section Wordeater because
  it contains the basic file operations that must be done to look around and
  keep pulling off words. */

#if defined(FLG_PROTOTYPE)
char *NextWord(char *StopChar);
#else
char *NextWord();
#endif
  /* This function reads the next word from the currently opened file. */

#if defined(FLG_PROTOTYPE)
void InitializeScanHashTable(void);
#else
void InitializeScanHashTable();
#endif
  /* The Scanning Hash Table has 256 entries. They identify a character as
      either, letter, stop character, a space or a comment. */

#endif /* WORDS_H */
