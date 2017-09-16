#define RANDOM_C TRUE
/*
   Copyright 1991 Peter Wayner
   All rights reserved.

   See global.h for a full copyright notice.
*/
#include "global.h"
#include "random.h"
#include "utl.h"

/* #define NoRandomness TRUE for debugging */

#define MaxRandomBit 32
    /* This is just a local boundary. This should not effect the user of this
       module. */

static long RandomBits; /* This is the register. */
static long InitialKey; /* This is for resetting... */

/* This is just a routine to turn a password into a key. */
#if defined(FLG_PROTOTYPE)
void SetKey(const char keyStr[])
#else
void SetKey(keyStr)
char keyStr[];
#endif
{
long tempor;

if (sscanf(keyStr, "%ld", &tempor) != 1) {
  fprintf(stderr, "Illegal key \"%s\"\n", keyStr);
  exit(1);
  }
InitialKey = 0xdeadbeef ^ tempor;
}

/* Starts the ball rolling. */
#if defined(FLG_PROTOTYPE)
void InitRandomBits(void)
#else
void InitRandomBits()
#endif
{
InitialKey = 0xbaadfaad;
RandomBits = InitialKey;
}

/* Starts the ball rolling. */
#if defined(FLG_PROTOTYPE)
void SyncRandomBits(void)
#else
void SyncRandomBits()
#endif
{
#ifdef NoRandomness
  RandomBits = 0;
#else
  RandomBits = InitialKey;
#endif
}

/* This cycles the random number generator. */
#if defined(FLG_PROTOTYPE)
void UpdateRandomBits(void)
#else
void UpdateRandomBits()
#endif
{

#ifdef NoRandomness
  RandomBits = 0;
#else
{
  unsigned long rotl, rotr;

  rotl = RandomBits << 1;
  if (RandomBits & 0x80000000)
    rotl |= 1;
  rotr = RandomBits >> 1;
  if (RandomBits & 1)
    rotr |= 0x80000000;
  RandomBits = rotl ^ (RandomBits | rotr);
}
#endif
}

/* Returns a specific random bit. */
#if defined(FLG_PROTOTYPE)
BoolType RandomBit(int bitter)
#else
BoolType RandomBit(bitter)
int bitter;
#endif
{
BoolType result;

bitter = bitter % MaxRandomBit;
result = ((RandomBits >> bitter) & 1) != 0;
#if 0
printf("Testing bit: %3d of %x and the result is %d\n",
  bitter, RandomBits, result);
#endif
return result;
}
