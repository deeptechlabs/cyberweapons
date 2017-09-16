/*
 * Copyright (c) 1991 David G. Koontz.
 * All rights reserved.
 *
 * Redistribution and use in  source and binary  forms  are permitted
 * provided that the  above copyright  notice  and this paragraph are
 * duplicated in all  such forms.  Inclusion  in a product or release
 * as part of  a  package  for  sale is not  agreed to.  Storing this
 * software in a  nonvolatile  storage  device  characterized  as  an 
 * integrated circuit providing  read  only  memory (ROM), either  as
 * source code or  machine executeable  instructions is similarly not
 * agreed to.  THIS  SOFTWARE IS  PROVIDED ``AS IS'' AND  WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT  LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE
 */
/*
 *	hex.c - string[8] to hex[16] and hex[16] to string[8] conversion
 */
#include <stdio.h>

void
strxtoc(hexstr,charstr)  /* converts 16 hex digit strings to char strings */
unsigned char *hexstr,*charstr;
{
#define UPPER_NYBBLE	( !(val & 1) )

    unsigned char c;
    int val;
    for (val = 0; val < 16;val++) {
	if ((hexstr[val] >= '0') && (hexstr[val] <= '9'))
	    if (UPPER_NYBBLE)
	        c = (hexstr[val] - '0') << 4;
	    else
		c += hexstr[val] - '0';
	else
	if ((hexstr[val] >= 'A') && (hexstr[val] <= 'F'))
	    if (UPPER_NYBBLE)
	        c = (hexstr[val] - 'A' +10) << 4;
	    else
		c += hexstr[val] - 'A' +10;
	else
	if ((hexstr[val] >= 'a') && (hexstr[val] <= 'f'))
	    if (UPPER_NYBBLE)
	        c = (hexstr[val] - 'a' +10) << 4;
	    else
		c += hexstr[val] - 'a' +10;
	else {
	    fprintf(stderr,"hex conversion error: %s - char %d\n",hexstr,val);
	    if ((val = strlen(hexstr)) != 16)
		fprintf(stderr,"hex string length != 16\n");
	    exit(1);
	}
	if ( UPPER_NYBBLE)
	    charstr[val>>1] = 0;
	else
	    charstr[val>>1] = c;
    }
}
void
strctox(charstr,hexstr)  /* converts 8 char string to 16 hex digit string */
unsigned char *charstr,*hexstr;
{
    unsigned char c;
    int i;
    for (i = 0; i < 8; i++) {
	c = charstr[i] >> 4;  /* uppper nybble */
	if ( c <= 9)
	    *hexstr++ = c + '0';
	else
	    *hexstr++ = c + '7';
	    
	c = (charstr[i] & 0xf);
	if ( c <= 9)
	    *hexstr++ = c + '0';
	else
	    *hexstr++ = c + '7';
    }
    *hexstr = 0;
}
