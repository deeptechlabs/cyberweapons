/*--- uucode.c -- File containing uuencode/uudecode routines.
 *
 *  Adapted from Berkeley code by Mark Riordan   12 August 1990.
 */

#include "uucodepr.h"

#if 0
int uuencode(unsigned char *bufin,unsigned int nbytes,
  unsigned char *bufcoded);
int uudecode(unsigned char *bufcoded,unsigned char *bufplain);
#endif

/*--- function uuencode -----------------------------------------------
 *
 *   Encode a single line of binary data to a standard format that
 *   uses only printing ASCII characters (but takes up 33% more bytes).
 *
 *    Entry    bufin    points to a buffer of bytes.
 *             nbytes   is the number of bytes in that buffer.
 *                      This cannot be more than 62, and
 *                      by convention it should be no more than 45.
 *             bufcoded points to an output buffer.  Be sure that this
 *                      can hold at least 2 + (4*nbytes)/3 characters.
 *
 *    Exit     bufcoded contains the coded line.  The first byte
 *                      contains the (encoded) number of bytes that
 *                      were encoded.  The following 4*nbytes/3 bytes
 *                      contain printing ASCII characters representing
 *                      those binary bytes, followed by a zero byte.
 *             Returns the number of ASCII characters in "bufcoded".
 */
int
uuencode(bufin, nbytes, bufcoded)
unsigned char *bufin;
unsigned int nbytes;
unsigned char *bufcoded;
{
/* ENC is the basic 1 character encoding function to make a char printing */
#define ENC(c) ((unsigned char) ((c) ? ((c) & 077) + ' ': '`') )

   register unsigned char *outptr = bufcoded;
   register unsigned char *inptr  = bufin;
   unsigned int i;

   *(outptr++) = ENC(nbytes);

   for (i=0; i<nbytes; i += 3) {
      *(outptr++) = ENC(*bufin >> 2);            /* c1 */
      *(outptr++) = ENC((*bufin << 4) & 060 | (bufin[1] >> 4) & 017);  /* c2 */
      *(outptr++) = ENC((bufin[1] << 2) & 074 | (bufin[2] >> 6) & 03); /* c3 */
      *(outptr++) = ENC(bufin[2] & 077);         /* c4 */

      bufin += 3;
   }

   /* If nbytes was not a multiple of 3, then we have encoded too
    * many characters.  Adjust appropriately.
    */
   if(i == nbytes+1) {
      outptr -= 1;
   } else if(i == nbytes+2) {
      outptr -= 2;
   }
   *outptr = '\0';
   return(outptr - bufcoded);
}

/*--- function uudecode ------------------------------------------------
 *
 *  Decode an ASCII-encoded buffer back to its original binary form.
 *
 *    Entry    bufcoded    points to a uuencoded string.  The first
 *                         character of this string is the encoded
 *                         number of original bytes in the buffer.
 *                         (Can't be more than 62.)
 *             bufplain    points to the output buffer; must be big
 *                         enough to hold the decoded string (generally
 *                         shorter than the encoded string).
 *             Both buffers may be overrun a bit (less than 4 bytes)
 *             during the decoding process, so leave a room for
 *             a few extra bytes at the end.
 *
 *    Exit     Returns the number of binary bytes decoded.
 *             bufplain    contains these bytes.
 */
int
uudecode(bufcoded,bufplain)
unsigned char *bufcoded;
unsigned char *bufplain;
{
/* single character decode */
#define DEC(c) ((unsigned char) (((c) - ' ') & 077) )

   int nbytes, nbytes2;
   register unsigned char *bufin = bufcoded;
   register unsigned char *bufout = bufplain;

   nbytes2 = nbytes = DEC(bufcoded[0]);

   bufin = &bufcoded[1];
   while (nbytes > 0) {
      *(bufout++) = DEC(*bufin) << 2 | DEC(bufin[1]) >> 4;
      *(bufout++) = DEC(bufin[1]) << 4 | DEC(bufin[2]) >> 2;
      *(bufout++) = DEC(bufin[2]) << 6 | DEC(bufin[3]);
      bufin += 4;
      nbytes -= 3;
   }
   return(nbytes2);
}


/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if 0
static char sccsid[] = "@(#)uuencode.c 5.6 (Berkeley) 7/6/88";
#endif /* not lint */
