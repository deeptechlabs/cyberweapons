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
 *	inv_perm.c - inverse permutation table generation program.
 *		     the table (unsigned long IIP[16][256]) converts the
 *		     LR data.string[8]  to the block AB.
 */

#ifndef LITTLE_ENDIAN	/* BIG_ENDIAN */

static unsigned int iip[8][8] = { /* map L&R to A&B longs in two long array */
/* numbers in array are bit positions in either A or B longs */
/* long	--->	       B	  A	*/
/* Byte */ /*	 A  B  B  B  B  A  A  A  */
#ifdef LR_ORDER
/*  0	*/	26, 0, 8,16,24, 0, 8,16,	/* Left Block bytes 0-3 */
/*  1   */      28, 2,10,18,26, 2,10,18,
/*  2   */      30, 4,12,20,28, 4,12,20,
/*  3   */	24, 6,14,22,30, 6,14,22,
/*  4   */      27, 1, 9,17,25, 1, 9,17,	/* Right Block bytes 0-3 */
/*  5   */      29, 3,11,19,27, 3,11,19,
/*  6   */      31, 5,13,21,29, 5,13,21,
/*  7   */	25, 7,15,23,31, 7,15,23,
#else	/* Put L where R belongs and vis versa */
/*  4   */      27, 1, 9,17,25, 1, 9,17,	/* Right Block bytes 0-3 */
/*  5   */      29, 3,11,19,27, 3,11,19,
/*  6   */      31, 5,13,21,29, 5,13,21,
/*  7   */	25, 7,15,23,31, 7,15,23,
/*  0	*/	26, 0, 8,16,24, 0, 8,16,	/* Left Block bytes 0-3 */
/*  1   */      28, 2,10,18,26, 2,10,18,
/*  2   */      30, 4,12,20,28, 4,12,20,
/*  3   */	24, 6,14,22,30, 6,14,22,
#endif
};
#else		      /* LITTLE_ENDIAN */
static unsigned int iip[8][8] = { 
/* NOTE: Byte order in LONG reversed for little endian was 0123 is 3210 */
/* long	--->	       B	  A	*/
/* Byte */ /*	 A  B  B  B  B  A  A  A  */
#ifdef LR_ORDER
/*  0   */	 0,30,22,14, 6,30,22,14,	/* Left Block bytes 0-3 */
/*  1   */       6,28,20,12, 4,28,20,12,
/*  2   */       4,26,18,10, 2,26,18,10,
/*  3	*/	 2,24,16, 8, 0,24,16, 8,
/*  4   */	 1,31,23,15, 7,31,23,15,	/* Right Block bytes 0-3 */
/*  5   */       7,29,21,13, 5,29,21,13,
/*  6   */       5,27,19,11, 3,27,19,11,
/*  7   */       3,25,17, 9, 1,25,17, 9,
#else	/* Put L where R belongs and vis versa */
/*  4   */	 1,31,23,15, 7,31,23,15,	/* Right Block bytes 0-3 */
/*  5   */       7,29,21,13, 5,29,21,13,
/*  6   */       5,27,19,11, 3,27,19,11,
/*  7   */       3,25,17, 9, 1,25,17, 9,
/*  0   */	 0,30,22,14, 6,30,22,14,	/* Left Block bytes 0-3 */
/*  1   */       6,28,20,12, 4,28,20,12,
/*  2   */       4,26,18,10, 2,26,18,10,
/*  3	*/	 2,24,16, 8, 0,24,16, 8,
#endif
};
#endif
#define BIT(x)	(1 << (x))

main(argc,argv) 
int argc;
char **argv;
{
int byte,value,bit;
unsigned long temp;
    printf(" /*\tiip.h  - inverse initial permutation lookup table,\n");
    printf("\t\t\t L and R blocks to long aligned char string \n*/\n");
    printf("static unsigned long IIP[16][256] = { \n");

    for ( byte = 0; byte < 8; byte++) {
        printf("/* B long Byte %d */\n{\t",byte);
	for (value = 0; value < 256; value++) {
	    temp = 0;
	    for ( bit = 1; bit < 5; bit++) {

		if ( value & BIT(bit))
		    temp |= BIT(iip[byte][bit]);
	    }
	    printf("  %#10x,  ",temp);
	    if ((value & 3) == 3)
		printf("\n\t");
	}
	printf("},\n");
    }
    
    for ( byte = 0; byte < 8; byte++) {
        printf(" /* A long Byte %d */\n{\t",byte);

	for (value = 0; value < 256; value++) {
	    temp = 0;
	    for ( bit = 5; bit < 8; bit++) {

		if ( value & BIT(bit))
		    temp |= BIT(iip[byte][bit]);
	    }
	    if (value & BIT(0))
		    temp | = BIT(iip[byte][0]);	    /* handle bit 0 special */

	    printf("  %#10x,  ",temp);
	    if ((value & 3) == 3)
		printf("\n\t");
	}
	printf("},\n");
    }    
    printf("};\n");
    exit(0);
}
