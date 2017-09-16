#if !defined(RANDOM_H)
#define RANDOM_H TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/

/* This is a customized version of a random number generator.
   It is based on a cellular automaton version of a random number
   generator written by Steve Wolfram.

   There are some indications that this is hard to break, but it is unclear
   just how difficult it is. */


#if defined(FLG_PROTOTYPE)
void SetKey(const char keyStr[]);
#else
void SetKey();
#endif
  /* This is just a routine to turn a password into a key. */

#if defined(FLG_PROTOTYPE)
void InitRandomBits(void);
#else
void InitRandomBits();
#endif
  /* This is just for setting everything up at the beginning. */

#if defined(FLG_PROTOTYPE)
void SyncRandomBits(void);
#else
void SyncRandomBits();
#endif
  /* Starts the ball rolling. */

#if defined(FLG_PROTOTYPE)
BoolType RandomBit(int bitter);
#else
BoolType RandomBit();
#endif
  /* Returns a specific random bit. */

#if defined(FLG_PROTOTYPE)
void UpdateRandomBits(void);
#else
void UpdateRandomBits();
#endif
  /* This cycles the random number generator. */

#endif /* RANDOM_H */
