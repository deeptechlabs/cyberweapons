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
** md4.h -- Header file for implementation of                        **
** MD4 Message Digest Algorithm                                      **
** Updated: 1991.12.12 Jouko Holopainen                              **
** (C) 1990 RSA Data Security, Inc.                                  **
** ********************************************************************
*/

#define WORD unsigned long   /* 32 bit (unsigned) quantity */

/* MDstruct is the data structure for a message digest computation.
*/
typedef struct {
  WORD buffer[4];         /* Holds 4-word result of MD computation */
  unsigned char count[8]; /* Number of bits processed so far */
  unsigned int done;      /* Nonzero means MD computation finished */
} MDstruct, *MDptr;

/* MDbegin(MD)
** Input: MD -- an MDptr
** Initialize the MDstruct prepatory to doing a message digest
** computation.
*/
extern void MDbegin();

/* MDupdate(MD,X,count)
** Input: MD -- an MDptr
**        X -- a pointer to an array of unsigned characters.
**        count -- the number of bits of X to use (an unsigned int).
** Updates MD using the first "count" bits of X.
** The array pointed to by X is not modified.
** If count is not a multiple of 8, MDupdate uses high bits of
** last byte.
** This is the basic input routine for a user.
** The routine terminates the MD computation when count < 512, so
** every MD computation should end with one call to MDupdate with a
** count less than 512.  Zero is OK for a count.
*/
extern void MDupdate();

/* MDprint(MD)
** Input: MD -- an MDptr
** Prints message digest buffer MD as 32 hexadecimal digits.
** Order is from low-order byte of buffer[0] to high-order byte
** of buffer[3].
** Each byte is printed with high-order hexadecimal digit first.
*/
extern void MDprint();

/*
** End of md4.h
*/
