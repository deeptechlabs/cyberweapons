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

/*
** To use MD4:
**   -- Include md4.h in your program
**   -- Declare an MDstruct MD to hold the state of the digest
**          computation.
**   -- Initialize MD using MDbegin(&MD)
**   -- For each full block (64 bytes) X you wish to process, call
**          MDupdate(&MD,X,512)
**      (512 is the number of bits in a full block.)
**   -- For the last block (less than 64 bytes) you wish to process,
**          MDupdate(&MD,X,n)
**      where n is the number of bits in the partial block. A partial
**      block terminates the computation, so every MD computation
**      should terminate by processing a partial block, even if it
**      has n = 0.
**   -- The message digest is available in MD.buffer[0] ...
**      MD.buffer[3].  (Least-significant byte of each word
**      should be output first.)
**   -- You can print out the digest using MDprint(&MD)
*/

/* Implementation notes:
** This implementation assumes DOS 80?86 with Microsoft C and ASM.
*/

/* Compile-time includes
*/
#include <stdio.h>
#include "md4.h"

#define TRUE  1
#define FALSE 0

/* Compile-time declarations of MD4 "magic constants".
*/
#define I0  0x67452301       /* Initial values for MD buffer */
#define I1  0xefcdab89
#define I2  0x98badcfe
#define I3  0x10325476

/* MDprint(MDp)
** Print message digest buffer MDp as 32 hexadecimal digits.
** Order is from low-order byte of buffer[0] to high-order byte of
** buffer[3].
** Each byte is printed with high-order hexadecimal digit first.
** This is a user-callable routine.
*/
void
MDprint(MDp)
MDptr MDp;
{ int i,j;
  for (i=0;i<4;i++)
    for (j=0;j<32;j=j+8)
      printf("%02x",(MDp->buffer[i]>>j) & 0xFF);
}

/* MDbegin(MDp)
** Initialize message digest buffer MDp.
** This is a user-callable routine.
*/
void
MDbegin(MDp)
MDptr MDp;
{ int i;
  MDp->buffer[0] = I0;
  MDp->buffer[1] = I1;
  MDp->buffer[2] = I2;
  MDp->buffer[3] = I3;
  for (i=0;i<8;i++) MDp->count[i] = 0;
  MDp->done = 0;
}

/* MDupdate(MDp,X,count)
** Input: MDp -- an MDptr
**        X -- a pointer to an array of unsigned characters.
**        count -- the number of bits of X to use.
**          (if not a multiple of 8, uses high bits of last byte.)
** Update MDp using the number of bits of X given by count.
** This is the basic input routine for an MD4 user.
** The routine completes the MD computation when count < 512, so
** every MD computation should end with one call to MDupdate with a
** count less than 512.  A call with count 0 will be ignored if the
** MD has already been terminated (done != 0), so an extra call with
** count 0 can be given as a "courtesy close" to force termination
** if desired.
*/
void
MDupdate(MDp,X,count)
MDptr MDp;
unsigned char *X;
unsigned int count;
{ unsigned int i, tmp, bit, byte;
  unsigned char XX[64], mask;
  unsigned char *p;
  /* return with no error if this is a courtesy close with count
  ** zero and MDp->done is true.
  */
  if (count == 0 && MDp->done) return;
  /* check to see if MD is already done and report error */
  if (MDp->done)
         { printf("\nError: MDupdate MD already done."); return; }
  /* Add count to MDp->count */
  tmp = count;
  p = MDp->count;
  while (tmp)
    { tmp += (unsigned int)(*p);
      *p++ = (unsigned char)(tmp & 0xFF);
      tmp = tmp >> 8;
    }
  /* Process data */
  if (count == 512)
    { /* Full block of data to handle */
      MDblock(MDp,(WORD *)X);
    }
  else if (count > 512) /* Check for count too large */
    { printf("\nError: MDupdate called with illegal count value %d."
             ,count);
      return;
    }
  else /* partial block -- must be last block so finish up */
    { /* Find out how many bytes and residual bits there are */
      byte = count >> 3;
      bit =  count & 7;
      /* Copy X into XX since we need to modify it */
      for (i=0;i<=byte;i++)   XX[i] = X[i];
      for (i=byte+1;i<64;i++) XX[i] = 0;
      /* Add padding '1' bit and low-order zeros in last byte */
      mask = 1 << (7 - bit);
      XX[byte] = (XX[byte] | mask) & ~(mask - 1);
      /* If room for bit count, finish up with this block */
      if (byte <= 55)
        { for (i=0;i<8;i++) XX[56+i] = MDp->count[i];
          MDblock(MDp,(WORD *)XX);
        }
      else /* need to do two blocks to finish up */
        { MDblock(MDp,(WORD *)XX);
          for (i=0;i<56;i++) XX[i] = 0;
          for (i=0;i<8;i++)  XX[56+i] = MDp->count[i];
          MDblock(MDp,(WORD *)XX);
        }
      /* Set flag saying we're done with MD computation */
      MDp->done = 1;
    }
}

/*
** End of md4.c
*/
