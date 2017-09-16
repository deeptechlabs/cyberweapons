/******************************************************************************/
/*                                                                            */
/*               C R Y P T O G R A P H I C - A L G O R I T H M S              */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ethz.ch)                   */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Last Edition: 23 April 1992                                                */
/* System:       SUN SPARCstation, SUN cc C-Compiler, SUN-OS 4.1.1            */
/******************************************************************************/

/* Formatting edits and change of Mul to take & return u_int16 by             */
/* Colin Plumb, 14 June 1992, Amiga.                                          */
/* Optimisation to Mul to use a better algorithm, August 1992, Colin          */
/* Complete rewrite in 68000 assembler achieved, 4 Sept 1992, Colin           */

#include "crypt.h"

#define mulMod        0x10001 /* 2**16 + 1                                    */
#define addMod        0x10000 /* 2**16                                        */
#define ones           0xFFFF /* 2**16 - 1                                    */

#define nofKeyPerRound      6 /* number of used keys per round                */
#define nofRound            8 /* number of rounds                             */

/******************************************************************************/
/*                          A L G O R I T H M                                 */
/******************************************************************************/
/* multiplication                                                             */
/* Multiply two number in the range of 1..0x10000, modulo 0x10001.            */
/* 0x10000 is represented as 0.                                               */

u_int16 Mul( register u_int16 a, register u_int16 b )
{
  register int32 p;
  register u_int32 q;
  
  if (a == 0)
    return 1 - b; 
  else if (b == 0)
    return 1 - a;
  else {
     q = (u_int32)a * b;
     a = q;
     b = q>>16;
     return a - b + (a <= b);
  }
} /* Mul */

/******************************************************************************/
/* compute inverse of 'x' by Euclidean gcd algorithm                          */

u_int16 MulInv( u_int16 x )
{
  int32 n1, n2, q, r, b1, b2, t;

  if (x == 0) return 0;
  n1 = mulMod;
  n2 = (int32)x;
  b2 = 1;
  b1 = 0;
  do {
    r = (n1 % n2);
    q = (n1 - r) / n2;
    if (r == 0) {
      if (b2 < 0)
        b2 = mulMod + b2;
    } else {
      n1 = n2;
      n2 = r;
      t = b2;
      b2 = b1 - q * b2;
      b1 = t;
    }
  } while (r != 0);
  return (u_int16)b2;
} /* MulInv */

/******************************************************************************/
/* encryption and decryption algorithm IDEA                                   */

void  Idea(u_int16 *dataIn, u_int16 *dataOut, u_int16 *key)
{
  register u_int16 round, x0, x1, x2, x3, t0, t1, t2;

  x0 = *dataIn++; x1 = *dataIn++; x2 = *dataIn++; x3 = *dataIn;

  for (round = nofRound; round > 0; round--) {
    x0 = Mul(*key++, x0);
    x1 += *key++;
    x2 += *key++;
    x3 = Mul(*key++, x3);

    t0 = Mul(*key++, x0 ^ x2);      
    t1 = Mul(*key++, t0 + (x1 ^ x3));
    t0 += t1;

    x0 ^= t1;
    x3 ^= t0;

    t0 ^= x1;
    x1 = x2 ^ t1;
    x2 = t0;
  }
  *dataOut++ = Mul(*key++, x0);
  *dataOut++ = x2 + *key++;
  *dataOut++ = x1 + *key++;
  *dataOut = Mul(*key, x3);
} /* Idea */
 
/******************************************************************************/
/* invert decryption / encrytion key for IDEA                                 */

void InvertIdeaKey( u_int16 *key, u_int16 *invKey)
{
  register int  i;
  KeyT(dk);

  dk[nofKeyPerRound * nofRound + 0] = MulInv(*key++);
  dk[nofKeyPerRound * nofRound + 1] = (addMod - *key++) & ones;
  dk[nofKeyPerRound * nofRound + 2] = (addMod - *key++) & ones;
  dk[nofKeyPerRound * nofRound + 3] = MulInv(*key++);
  for (i = nofKeyPerRound * (nofRound - 1); i >= 0; i -= nofKeyPerRound) {
    dk[i + 4] = *key++;
    dk[i + 5] = *key++;
    dk[i + 0] = MulInv(*key++);
    if (i > 0) {
      dk[i + 2] = (addMod - *key++) & ones;
      dk[i + 1] = (addMod - *key++) & ones;
    } else {
      dk[i + 1] = (addMod - *key++) & ones;
      dk[i + 2] = (addMod - *key++) & ones;
    }
    dk[i + 3] = MulInv(*key++);
  }
  for (i = 0; i < keyLen; i++)
    invKey[i] = dk[i]; 
} /* InvertIdeaKey */


/******************************************************************************/
/* expand user key of 128 bits to full key of 832 bits                        */

void ExpandUserKey( u_int16 *userKey, u_int16 *key)
{
  register int i;

  for (i = 0; i < userKeyLen; i++) key[i] = userKey[i];
  /* shifts */
  for (i = userKeyLen; i < keyLen; i++) {
    if ((i + 2) % 8 == 0)                    /* for key[14],key[22],..  */
      key[i] = ((key[i - 7] & 127) << 9) ^ (key[i - 14] >> 7); 
    else if ((i + 1) % 8 == 0)               /* for key[15],key[23],..  */
      key[i] = ((key[i - 15] & 127) << 9) ^ (key[i - 14] >> 7); 
    else
      key[i] = ((key[i - 7] & 127) << 9 ) ^ (key[i - 6] >> 7);
   }
} /* ExpandUserKey */
