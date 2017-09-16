/*
*--------------------------------------------------------------------------*
* (C) Copyright 1990, RSA Data Security, Inc.  All rights reserved.        *
* License to copy and use this software is granted provided it is          *
* identified as the "RSA Data Security, Inc. MD4 message digest algorithm" *
* in all material mentioning or referencing this software or function.     *
*                                                                          *
* License is also granted to make and use derivative works provided such   *
* works are identified as "derived from the RSA Data Securitry, Inc. MD4   *
* message digest algorithm" in all material mentioning or referencing the  *
* derived work.                                                            *
*                                                                          *
* RSA Data Security, Inc. makes no representations concerning the          *
* merchantability of this software or the suitability of the software      *
* for any particular purpose.  It is provided "as is" without express      *
* or implied warranty of any kind.                                         *
*                                                                          *
* These notices must be retained in any copies of any part of this         *
* documentation and/or software.                                           *
*--------------------------------------------------------------------------*
** ********************************************************************
** md4.c -- Implementation of MD4 Message Digest Algorithm           **
** Updated: 1991.12.12 Jouko Holopainen                              **
** (C) 1990 RSA Data Security, Inc.                                  **
** ********************************************************************
*/

#include "md4.h"

#define C2  013240474631     /* round 2 constant = sqrt(2) in octal */
#define C3  015666365641     /* round 3 constant = sqrt(3) in octal */
/* C2 and C3 are from Knuth, The Art of Programming, Volume 2
** (Seminumerical Algorithms), Second Edition (1981), Addison-Wesley.
** Table 2, page 660.
*/

#define fs1  3               /* round 1 shift amounts */
#define fs2  7
#define fs3 11
#define fs4 19
#define gs1  3               /* round 2 shift amounts */
#define gs2  5
#define gs3  9
#define gs4 13
#define hs1  3               /* round 3 shift amounts */
#define hs2  9
#define hs3 11
#define hs4 15

/* Compile-time macro declarations for MD4.
** Note: The "rot" operator uses the variable "tmp".
** It assumes tmp is declared as unsigned int, so that the >>
** operator will shift in zeros rather than extending the sign bit.
*/
#define f(X,Y,Z)             ((X&Y) | ((~X)&Z))
#define g(X,Y,Z)             ((X&Y) | (X&Z) | (Y&Z))
#define h(X,Y,Z)             (X^Y^Z)

#define ff(A,B,C,D,i,s)      A = rot((A + f(B,C,D) + X[i]),s)
#define gg(A,B,C,D,i,s)      A = rot((A + g(B,C,D) + X[i] + C2),s)
#define hh(A,B,C,D,i,s)      A = rot((A + h(B,C,D) + X[i] + C3),s)

static WORD pascal rot(X,S)
WORD X;
int S;
{
  WORD tmp;

  tmp=X;

  return (tmp<<S) | (tmp>>(32-S));
}

/* MDblock(MDp,X)
** Update message digest buffer MDp->buffer using 16-word data block X.
** Assumes all 16 words of X are full of data.
** Does not update MDp->count.
** This routine is not user-callable.
*/
void MDblock(MDp,X)
MDptr MDp;
WORD *X;
{
  static WORD A, B, C, D;

  A = MDp->buffer[0];
  B = MDp->buffer[1];
  C = MDp->buffer[2];
  D = MDp->buffer[3];
  /* Update the message digest buffer */
  ff(A , B , C , D ,  0 , fs1); /* Round 1 */
  ff(D , A , B , C ,  1 , fs2);
  ff(C , D , A , B ,  2 , fs3);
  ff(B , C , D , A ,  3 , fs4);
  ff(A , B , C , D ,  4 , fs1);
  ff(D , A , B , C ,  5 , fs2);
  ff(C , D , A , B ,  6 , fs3);
  ff(B , C , D , A ,  7 , fs4);
  ff(A , B , C , D ,  8 , fs1);
  ff(D , A , B , C ,  9 , fs2);
  ff(C , D , A , B , 10 , fs3);
  ff(B , C , D , A , 11 , fs4);
  ff(A , B , C , D , 12 , fs1);
  ff(D , A , B , C , 13 , fs2);
  ff(C , D , A , B , 14 , fs3);
  ff(B , C , D , A , 15 , fs4);
  gg(A , B , C , D ,  0 , gs1); /* Round 2 */
  gg(D , A , B , C ,  4 , gs2);
  gg(C , D , A , B ,  8 , gs3);
  gg(B , C , D , A , 12 , gs4);
  gg(A , B , C , D ,  1 , gs1);
  gg(D , A , B , C ,  5 , gs2);
  gg(C , D , A , B ,  9 , gs3);
  gg(B , C , D , A , 13 , gs4);
  gg(A , B , C , D ,  2 , gs1);
  gg(D , A , B , C ,  6 , gs2);
  gg(C , D , A , B , 10 , gs3);
  gg(B , C , D , A , 14 , gs4);
  gg(A , B , C , D ,  3 , gs1);
  gg(D , A , B , C ,  7 , gs2);
  gg(C , D , A , B , 11 , gs3);
  gg(B , C , D , A , 15 , gs4);
  hh(A , B , C , D ,  0 , hs1); /* Round 3 */
  hh(D , A , B , C ,  8 , hs2);
  hh(C , D , A , B ,  4 , hs3);
  hh(B , C , D , A , 12 , hs4);
  hh(A , B , C , D ,  2 , hs1);
  hh(D , A , B , C , 10 , hs2);
  hh(C , D , A , B ,  6 , hs3);
  hh(B , C , D , A , 14 , hs4);
  hh(A , B , C , D ,  1 , hs1);
  hh(D , A , B , C ,  9 , hs2);
  hh(C , D , A , B ,  5 , hs3);
  hh(B , C , D , A , 13 , hs4);
  hh(A , B , C , D ,  3 , hs1);
  hh(D , A , B , C , 11 , hs2);
  hh(C , D , A , B ,  7 , hs3);
  hh(B , C , D , A , 15 , hs4);
  MDp->buffer[0] += A;
  MDp->buffer[1] += B;
  MDp->buffer[2] += C;
  MDp->buffer[3] += D;
}
