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

#define FGETC(S) (octet_counter++, fgetc(S))
#define FPUTC(L, B) (putc(L, B))

static int	octet_counter = 0;


#ifdef K_AND_R
_TYPE( long )
fgetLength(stream)
  FILE *stream;
#else
_TYPE( long ) fgetLength(FILE *stream)
#endif
{
	int octet;
	long length;
	int lengthlength;
	
	octet = FGETC(stream);
	if (octet == EOF)
		handle_exception(CRITICAL, "fgetLength: octet == EOF unexpectedly\n");
	if (octet < 128)
		return octet;
	lengthlength = (octet & 0x7F);
	if (lengthlength == 0)
		return INDEFINITE;
	length = 0;
	do {
		octet = FGETC(stream);
		length = (length << 8) | octet;
	} while (--lengthlength);
	return length;
}

#ifdef K_AND_R
_TYPE( void )
fputLength(length, stream)
  long length;
  FILE *stream;
#else
_TYPE( void ) fputLength(long length,
			FILE *stream)
#endif
{
	int octet;
	int lengthlength;
	
	if (length == INDEFINITE) {
		(void) FPUTC((unsigned char)128, stream);
		return;
	}
	if (length < 128) {
		(void) FPUTC((int)length, stream);
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
	(void) FPUTC(octet, stream);
	switch (lengthlength) {
		
	    case 4:	octet = (int)((length >> 24) & 0xFF);
		(void) FPUTC(octet, stream);
	    case 3:	octet = (int)((length >> 16) & 0xFF);
		(void) FPUTC(octet, stream);
	    case 2:	octet = (int)((length >>  8) & 0xFF);
		(void) FPUTC(octet, stream);
	    case 1:	octet = (int)((length      ) & 0xFF);
		(void) FPUTC(octet, stream);
	}
}

#ifdef K_AND_R
_TYPE( int )
fgetBoolean(stream, form)
  FILE *stream;
  int form;
#else
_TYPE( int ) fgetBoolean(FILE *stream,
			int form)
#endif
{
	
	if (form == EXPLICIT) {
		if (FGETC(stream) != BOOLEAN)
			handle_exception(CRITICAL, "fgetBoolean: expected BOOLEAN\n");
	}
	if (FGETC(stream) != 1) {
		handle_exception(CRITICAL, "fgetBoolean: length should be 1\n");
	}
	return FGETC(stream);
}

#ifdef K_AND_R
_TYPE( void )
fputBoolean(value, stream, form)
  int value;
  FILE *stream;
  int form;
#else
_TYPE( void ) fputBoolean(int value,
			 FILE *stream,
			 int form)
#endif
{
	
	if (form == EXPLICIT)
		(void) FPUTC(BOOLEAN, stream);
	(void) FPUTC(1, stream);
	if (value)
		(void) FPUTC((unsigned char)0xFF, stream);
	else
		(void) FPUTC(0x00, stream);
}

#ifdef K_AND_R
_TYPE( long )
fgetInteger(stream, form)
  FILE *stream;
  int form;
#else
_TYPE( long ) fgetInteger(FILE *stream,
			 int form)
#endif
{
	long value;
	int octet;
	int length;
	
	if (form == EXPLICIT) {
		octet = FGETC(stream);
		if (octet != INTEGER) {
			printf("octet = %x\n", octet);
			handle_exception(CRITICAL, "fasn1: fgetInteger: expected integer type\n");
		}
	}
	length = (int)fgetLength(stream);
	if (length > 4) {
		printf("PROBLEM length = %d\n", length);
		handle_exception(CRITICAL, "asn1: fgetInteger: integer too long\n");
	}
	value = 0;
	if (length) {
		octet = FGETC(stream);
		if (octet & 0x80)
			value = ~0;
		for (;;) {
			value = (value << 8) + (long)octet;
			if (--length)
				octet = FGETC(stream);
			else
				break;
		}
	}
	return value;
}

#ifdef K_AND_R
_TYPE( void )
fputInteger(value, stream, form)
  long value;
  FILE *stream;
  int form;
#else
_TYPE( void ) fputInteger(long value,
			 FILE *stream,
			 int form)
#endif
{
	int octet;
	
	if (form == EXPLICIT)
		(void) FPUTC(INTEGER, stream);
	if (value >= -128 && value <= 127) {
		(void) FPUTC(1, stream);			/* length */
		goto fput1;
	}
	if (value >= -32768L && value <= 32767L) {
		(void) FPUTC(2, stream);
		goto fput2;
	}
	if (value >= -8388608L && value <= 8388607L) {
		(void) FPUTC(3, stream);
		goto fput3;
	}
	(void) FPUTC(4, stream);
	octet = (int)((value >> 24) & 0xFF);			/* fput*/
	(void) FPUTC(octet, stream);
    fput3:	octet = (int)((value >> 16) & 0xFF);
	(void) FPUTC(octet, stream);
    fput2:	octet = (int)((value >>  8) & 0xFF);
	(void) FPUTC(octet, stream);
    fput1:	octet =  (int)(value        & 0xFF);
	(void) FPUTC(octet, stream);
}

/*
 *	fget OCTETSTRING, PRINTABLESTRING, NUMERICSTRING
 */

/*IO_TYPE **/
#ifdef K_AND_R
_TYPE( long )
fgetString(string, limit, stream, form)
  unsigned char *string;
  int limit;
  FILE *stream;
  int form;
#else
_TYPE( long ) fgetString(unsigned char *string,
			int limit,
			FILE *stream,
			int form)
#endif
{
	long length;
	unsigned char *cp;
	int octet, i;
	
	cp = string;
	if (form == EXPLICIT)
		(void) FGETC(stream);			/* tag */
	length = fgetLength(stream);
	for (i = 0; i < length; i++) {
		octet = FGETC(stream);

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
fputString(cp, length, stream, form, stringtype)
  unsigned char *cp;
  long length;
  FILE *stream;
  int form;
  int stringtype;
#else
_TYPE( void ) fputString(unsigned char *cp,
			long length,
			FILE *stream,
			int form,
			int stringtype)
#endif
{
	int octet, i;
	
	if (form == EXPLICIT)
		(void) FPUTC(stringtype, stream);
	fputLength(length, stream);
	for (i = 0; i < length; i++) {
		octet = *cp++;
		(void) FPUTC(octet, stream);
	}
}

#ifdef K_AND_R
_TYPE( unsigned char * )
fgetBitString(bstring, limit, stream, form)
  unsigned char *bstring;
  int limit;
  FILE *stream;
  int form;
#else
_TYPE( unsigned char *) fgetBitString(unsigned char *bstring,
				     int limit,
				     FILE *stream,
				     int form)
#endif
{
	int octet, i, offset, blength;
	int length, unused;
	
	if (form == EXPLICIT) {
		if (FGETC(stream) != BITSTRING)
			handle_exception(CRITICAL, "fgetBitString: type not BITSTRING\n");
	}
	length = (int)fgetLength(stream);
	unused = FGETC(stream);
	blength = 8*(length - 1) - unused;
	for (i = 0; i < blength; i++) {
		offset = 7 - (i & 7);
		if (offset == 7)
			octet = FGETC(stream);
		if (i < limit)
			bstring[i] = (octet >> offset) & 1;
	}
	return bstring;
}

#ifdef K_AND_R
_TYPE( void )
fputBitString(bstring, blength, stream, form)
  unsigned char *bstring;
  int blength;
  FILE *stream;
  int form;
#else
_TYPE( void ) fputBitString(unsigned char *bstring,
			   int blength,
			   FILE *stream,
			   int form)
#endif
{
	int i, offset, octet;
	int length;
	int unused;
	
	if (form == EXPLICIT)
		(void) FPUTC(BITSTRING, stream);
	length = (blength + 7) / 8 + 1;
	unused = 8*(length - 1) - blength;
	fputLength(length, stream);
	(void) FPUTC(unused, stream);
	offset = 0;
	for (i = 0; i < blength; i++) {
		offset = 7 - (i & 7);
		if (offset == 7)
			octet = 0;
		octet |= bstring[i] << offset;
		if (offset == 0)
			(void) FPUTC(octet, stream);
	}
	if (offset != 0)
		(void) FPUTC(octet, stream);
}

#ifdef K_AND_R
_TYPE( int )
featDataUnit(stream, form, tag)
  FILE *stream;
  int form;
  int tag;
#else
_TYPE( int ) featDataUnit(FILE *stream,
			 int form,
			 int tag)
#endif
{
	int i, length;
	
	if (form == EXPLICIT)
		tag = FGETC(stream);
	if ((tag & 0x1F) == 31)			/* feat long tag */
		do {
			tag = FGETC(stream);
		} while (tag & 0x80);
	length = (int)fgetLength(stream);
	if (length != INDEFINITE) {
		for (i = 0; i < length; i++)
			(void) FGETC(stream);
	} else {
		while (featDataUnit(stream, EXPLICIT, 0) != EOC)
			;
	}
	return tag;
}

#ifdef K_AND_R
_TYPE( void )
fgetEOC(stream, form)
  FILE *stream;
  int form;
#else
_TYPE( void ) fgetEOC(FILE *stream,
		     int form)
#endif
{
	
	if (form == EXPLICIT) {
		if (FGETC(stream) != EOC)
			handle_exception(CRITICAL, "fgetEOC: type not EOC\n");
	}
	if (FGETC(stream) != 0)
		handle_exception(CRITICAL, "fgetEOC: value not 0\n");
}

#ifdef K_AND_R
_TYPE( void )
fputEOC(stream)
  FILE *stream;
#else
  _TYPE( void ) fputEOC(FILE *stream)
#endif
{
	
	(void) FPUTC(EOC, stream);
	(void) FPUTC(0, stream);
}
