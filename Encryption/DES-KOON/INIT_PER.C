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
#ifndef lint
char Copyright[]=
    "@(#) Copyright (c) 1991 David G. Koontz\n All rights reserved.\n";
#endif
/*
 *     init_perm.c - inverse permutation table generation program.
 *		     the table (unsigned long IIP[16][256]) converts the
 *		     input.string[8] to the block LR.
 */
/* IP converts bytes to bit in Longs, and has no concept of ENDIAN */

static unsigned int ip[8][8] = { /* map input Bytes to L and R longs */
/* numbers in array are bit positions in either L or R longs */
/* long	--->	 L  R  L  R  L  R  L  R */
/* Byte */
/*  0	*/	 0, 0,24,24,16,16, 8, 8,	/* A Block bytes 0-3 */
/*  1   */      31,31,23,23,15,15, 7, 7,
/*  2   */      30,30,22,22,14,14, 6, 6,
/*  3   */	29,29,21,21,13,13, 5, 5,
/*  4   */      28,28,20,20,12,12, 4, 4,	/* B Block bytes 0-3 */
/*  5   */      27,27,19,19,11,11, 3, 3,
/*  6   */      26,26,18,18,10,10, 2, 2,
/*  7   */	25,25,17,17, 9, 9, 1, 1,
};

#define BIT(x)	(1 << (x))

main(argc,argv) 
int argc;
char **argv;
{
int byte;
int value;
int bit;
unsigned long temp;
    printf(" /*\tip.h    -  initial permutation lookup table,\n");
    printf("\t\t\t long aligned char string (AB block) to L and R\n*/\n");
    printf("static unsigned long IP[16][256] = { \n");
	
    for ( byte = 0; byte < 8; byte++) {
        printf("/* Byte %d to R long */\n{\t",byte);
	for (value = 0; value < 256; value++) {
	    temp = 0;
	    for ( bit = 1; bit < 8; bit += 2 ) {  /* RIGHT */

		if ( value & BIT(bit))
		    temp |= BIT(ip[byte][bit]);
	    }
	    printf("  %#10x,  ",temp);
	    if ((value & 3) == 3)
		printf("\n\t");
	}
	printf("},\n");
    }
    for ( byte = 0; byte < 8; byte++) {
        printf(" /* Byte %d to L long */\n{\t",byte);

	for (value = 0; value < 256; value++) {  
	    temp = 0;
	    for ( bit = 0; bit < 8; bit += 2 ) {  /* LEFT */

		if ( value & BIT(bit))
		    temp |= BIT(ip[byte][bit]);
	    }
	    printf("  %#10x,  ",temp);
	    if ((value & 3) == 3)
		printf("\n\t");
	}
	printf("},\n");
    }    
    printf("};\n");
    exit(0);
}
