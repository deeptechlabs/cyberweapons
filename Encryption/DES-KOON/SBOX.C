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
 * sbox.c - S box and P permutation table lookup generation program
 *
 */

#define BIT(x)	( 1 << x )

unsigned long sbox_P[8][64];

static long S[8][64] = { 14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
			  0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
			  4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
			 15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,

			 15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
			  3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
			  0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
			 13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,

			 10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
			 13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
			 13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
			  1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,

			  7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
			 13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
			 10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
			  3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,

			  2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
			 14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
			  4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
			 11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,

			 12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
			 10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
			  9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
			  4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,

			  4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
			 13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
			  1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
			  6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,

			 13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
			  1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
			  7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
			  2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11
};

static int SBITS[8][4]   = {  1 <<  9, 1 << 17, 1 << 23, 1 << 31,
			      1 << 13, 1 << 28, 1 <<  2, 1 << 18,
			      1 << 24, 1 << 16, 1 << 30, 1 <<  6,
			      1 << 26, 1 << 20, 1 << 10, 1 <<  1,
			      1 <<  8, 1 << 14, 1 << 25, 1 <<  3,
			      1 <<  4, 1 << 29, 1 << 11, 1 << 19,
			      1 <<  0, 1 << 12, 1 << 22, 1 <<  7,
			      1 <<  5, 1 << 27, 1 << 15, 1 << 21
};

main (argc,argv)
int argc;
char **argv;
{
    int sbox,index,bit,sin;

    for (sbox=0; sbox < 8; sbox++) {

	for ( index=0; index< 64; index++) {
	    sin = 0;

	    if (index & BIT(0))
		sin |= BIT(4);
	    if (index & BIT(1))
		sin |= BIT(3);
	    if (index & BIT(2))
		sin |= BIT(2);
	    if (index & BIT(3))
		sin |= BIT(1);
	    if (index & BIT(4))
		sin |= BIT(5);
	    if (index & BIT(5))
		sin |= BIT(0);

	    sbox_P[sbox][sin] = 0;

	    for ( bit = 0; bit < 4; bit++)
		if ( S[sbox][index] & BIT(bit))
		    sbox_P[sbox][sin] |= SBITS[sbox][3-bit];
	}
    }

    printf("/*\n");
    printf(" * s_p.h - contains combined Sbox and P permutation table\n");
    printf(" */\n\n");

    printf("static unsigned long S_P[8][64] = {\n");
    for ( sbox = 0; sbox < 8; sbox++ ) {
	printf("/* SBOX %d */ \n",sbox+1);
	for(sin = 0; sin < 64; sin++) {
	    printf("\t%#10x,",sbox_P[sbox][sin]);
	    if ((sin & 3) == 3)
	        printf("\n");
	}
    }
    printf("};\n");
    exit(0);
}
