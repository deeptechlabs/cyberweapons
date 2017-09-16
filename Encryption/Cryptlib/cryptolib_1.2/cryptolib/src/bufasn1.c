/*
 * This is version 1.2 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

/*
 *	X.409 - marshalling and unmarshalling primtive data types
 *	D. P. Mitchell  90/03/05.
 */
#include "libcrypt.h"
#include <assert.h>

#define BUFGETC(S) (octet_counter++,*(*S)++ & 0xff)
#define BUFPUTC(C, S) (*(*S)++ = C)

static int	octet_counter = 0;

#ifdef K_AND_R
_TYPE( long )
bufGetLength(buffer)
  unsigned char **buffer;
#else
_TYPE( long ) bufGetLength(unsigned char **buffer)
#endif
{
	int octet;
	long length;
	int lengthlength;
	
	octet = BUFGETC(buffer);
	assert(octet != EOF);
	if (octet < 128)
		return octet;
	lengthlength = (octet & 0x7F);
	if (lengthlength == 0)
		return INDEFINITE;
	length = 0;
	do {
		octet = BUFGETC(buffer);
		length = (length << 8) | octet;
	} while (--lengthlength);
	return length;
}

#ifdef K_AND_R
_TYPE( void )
bufPutLength(length, buffer)
  long length;
  unsigned char **buffer;
#else
_TYPE( void ) bufPutLength(long length,
			unsigned char **buffer)
#endif
{
	int octet;
	int lengthlength;
	
	if (length == INDEFINITE) {
		(void) BUFPUTC(128, buffer);
		return;
	}
	if (length < 128) {
		(void) BUFPUTC((int)length, buffer);
		return;
	}
	if (length < 256)
		lengthlength = 1;
	else if (length < 65536L)
		lengthlength = 2;
	else if (length < 16777216L)
		lengthlength = 3;
	else
		lengthlength = 4;
	octet = 128 + lengthlength;
	(void) BUFPUTC(octet, buffer);
	switch (lengthlength) {
		
	    case 4:	octet = (int)((length >> 24) & 0xFF);
		(void) BUFPUTC(octet, buffer);
	    case 3:	octet = (int)((length >> 16) & 0xFF);
		(void) BUFPUTC(octet, buffer);
	    case 2:	octet = (int)((length >>  8) & 0xFF);
		(void) BUFPUTC(octet, buffer);
	    case 1:	octet = (int)((length      ) & 0xFF);
		(void) BUFPUTC(octet, buffer);
	}
}

#ifdef K_AND_R
_TYPE( int )
bufGetBoolean(buffer, form)
  unsigned char **buffer;
  int form;
#else
_TYPE( int ) bufGetBoolean(unsigned char **buffer,
			int form)
#endif
{
	
	if (form == EXPLICIT)
		assert(BUFGETC(buffer) == BOOLEAN);	/* tag */
	assert(BUFGETC(buffer) == 1);			/* length */
	return BUFGETC(buffer);
}

#ifdef K_AND_R
_TYPE( void )
bufPutBoolean(value, buffer, form)
  int value;
  unsigned char **buffer;
  int form;
#else
_TYPE( void ) bufPutBoolean(int value,
			 unsigned char **buffer,
			 int form)
#endif
{
	
	if (form == EXPLICIT)
		(void) BUFPUTC(BOOLEAN, buffer);
	(void) BUFPUTC(1, buffer);
	if (value)
		(void) BUFPUTC(0xFF, buffer);
	else
		(void) BUFPUTC(0x00, buffer);
}

#ifdef K_AND_R
_TYPE( long )
bufGetInteger(buffer, form)
  unsigned char **buffer;
  int form;
#else
_TYPE( long ) bufGetInteger(unsigned char **buffer,
			 int form)
#endif
{
	long value;
	int octet;
	int length;
	
	if (form == EXPLICIT) {
		octet = BUFGETC(buffer);
		assert(octet == INTEGER);
	}
	length = (int)bufGetLength(buffer);
	if (length > 4) {
		handle_exception(CRITICAL, "asn1: bufGetInteger: integer too long\n");
	}
	value = 0;
	if (length) {
		octet = BUFGETC(buffer);
		if (octet & 0x80)
			value = ~0;
		for (;;) {
			value = (value << 8) + (long)octet;
			if (--length)
				octet = BUFGETC(buffer);
			else
				break;
		}
	}
	return value;
}

#ifdef K_AND_R
_TYPE( void )
bufPutInteger(value, buffer, form)
  long value;
  unsigned char **buffer;
  int form;
#else
_TYPE( void ) bufPutInteger(long value,
			 unsigned char **buffer,
			 int form)
#endif
{
	int octet;
	
	if (form == EXPLICIT)
		(void) BUFPUTC(INTEGER, buffer);
	if (value >= -128 && value <= 127) {
		(void) BUFPUTC(1, buffer);			/* length */
		goto bufPut1;
	}
	if (value >= -32768L && value <= 32767L) {
		(void) BUFPUTC(2, buffer);
		goto bufPut2;
	}
	if (value >= -8388608L && value <= 8388607L) {
		(void) BUFPUTC(3, buffer);
		goto bufPut3;
	}
	(void) BUFPUTC(4, buffer);
	octet = (int)((value >> 24) & 0xFF);			/* bufPut*/
	(void) BUFPUTC(octet, buffer);
    bufPut3:	octet = (int)((value >> 16) & 0xFF);
	(void) BUFPUTC(octet, buffer);
    bufPut2:	octet = (int)((value >>  8) & 0xFF);
	(void) BUFPUTC(octet, buffer);
    bufPut1:	octet =  (int)(value        & 0xFF);
	(void) BUFPUTC(octet, buffer);
}

/*
 *	bufGet OCTETSTRING, PRINTABLESTRING, NUMERICSTRING
 */

/*unsigned char ***/
#ifdef K_AND_R
_TYPE( long )
bufGetString(string, limit, buffer, form)
  unsigned char *string;
  int limit;
  unsigned char **buffer;
  int form;
#else
_TYPE( long ) bufGetString(unsigned char *string,
			int limit,
			unsigned char **buffer,
			int form)
#endif
{
	long length;
	unsigned char *cp;
	int octet, i;
	
	cp = string;
	if (form == EXPLICIT)
		(void) BUFGETC(buffer);			/* tag */
	length = bufGetLength(buffer);
	for (i = 0; i < length; i++) {
		octet = BUFGETC(buffer);
		if (i < limit)
			*cp++ = octet;
	}
	if (i < limit)
		*cp++ = 0;
	/*	return string;*/
	return length;
}

#ifdef K_AND_R
_TYPE( void )
bufPutString(cp, length, buffer, form, stringtype)
  unsigned char *cp;
  long length;
  unsigned char **buffer;
  int form;
  int stringtype;
#else
_TYPE( void ) bufPutString(unsigned char *cp,
			long length,
			unsigned char **buffer,
			int form,
			int stringtype)
#endif
{
	int octet, i;
	
	if (form == EXPLICIT)
		(void) BUFPUTC(stringtype, buffer);
	bufPutLength(length, buffer);
	for (i = 0; i < length; i++) {
		octet = *cp++;
		(void) BUFPUTC(octet, buffer);
	}
}

#ifdef K_AND_R
_TYPE( unsigned char * )
bufGetBitString(bstring, limit, buffer, form)
  unsigned char *bstring;
  int limit;
  unsigned char **buffer;
  int form;
#else
_TYPE( unsigned char *) bufGetBitString(unsigned char *bstring,
				     int limit,
				     unsigned char **buffer,
				     int form)
#endif
{
	int octet, i, offset, blength;
	int length, unused;
	
	if (form == EXPLICIT)
		assert(BUFGETC(buffer) == BITSTRING);
	length = (int)bufGetLength(buffer);
	unused = BUFGETC(buffer);
	blength = 8*(length - 1) - unused;
	for (i = 0; i < blength; i++) {
		offset = 7 - (i & 7);
		if (offset == 7)
			octet = BUFGETC(buffer);
		if (i < limit)
			bstring[i] = (octet >> offset) & 1;
	}
	return bstring;
}

#ifdef K_AND_R
_TYPE( void )
bufPutBitString(bstring, blength, buffer, form)
  unsigned char *bstring;
  int blength;
  unsigned char **buffer;
  int form;
#else
_TYPE( void ) bufPutBitString(unsigned char *bstring,
			   int blength,
			   unsigned char **buffer,
			   int form)
#endif
{
	int i, offset, octet;
	int length;
	int unused;
	
	if (form == EXPLICIT)
		(void) BUFPUTC(BITSTRING, buffer);
	length = (blength + 7) / 8 + 1;
	unused = 8*(length - 1) - blength;
	bufPutLength(length, buffer);
	(void) BUFPUTC(unused, buffer);
	offset = 0;
	for (i = 0; i < blength; i++) {
		offset = 7 - (i & 7);
		if (offset == 7)
			octet = 0;
		octet |= bstring[i] << offset;
		if (offset == 0)
			(void) BUFPUTC(octet, buffer);
	}
	if (offset != 0)
		(void) BUFPUTC(octet, buffer);
}

#ifdef K_AND_R
_TYPE( int )
bufEatDataUnit(buffer, form, tag)
  unsigned char **buffer;
  int form;
  int tag;
#else
_TYPE( int ) bufEatDataUnit(unsigned char **buffer,
			 int form,
			 int tag)
#endif
{
	int i, length;
	
	if (form == EXPLICIT)
		tag = BUFGETC(buffer);
	if ((tag & 0x1F) == 31)			/* bufEat long tag */
		do {
			tag = BUFGETC(buffer);
		} while (tag & 0x80);
	length = (int)bufGetLength(buffer);
	if (length != INDEFINITE) {
		for (i = 0; i < length; i++)
			(void) BUFGETC(buffer);
	} else {
		while (bufEatDataUnit(buffer, EXPLICIT, 0) != EOC)
			;
	}
	return tag;
}

#ifdef K_AND_R
_TYPE( void )
bufGetEOC(buffer, form)
  unsigned char **buffer;
  int form;
#else
_TYPE( void ) bufGetEOC(unsigned char **buffer,
		     int form)
#endif
{
	
	if (form == EXPLICIT)
		assert(BUFGETC(buffer) == EOC);
	assert(BUFGETC(buffer) == 0);
}

#ifdef K_AND_R
_TYPE( void )
bufPutEOC(buffer)
  unsigned char **buffer;
#else
  _TYPE( void ) bufPutEOC(unsigned char **buffer)
#endif
{
	
	(void) BUFPUTC(EOC, buffer);
	(void) BUFPUTC(0, buffer);
}
