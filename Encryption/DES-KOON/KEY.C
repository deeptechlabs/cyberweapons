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
 *  key.c   - key schedule look up table generation program
 *		for each of 8 byte locations of an input string,
 *		each of 128 possible input values have their values
 *		mapped into 16 (key schedule number) pairs of Longs
 *		(number of Longs in block_48).
 */

#define BIT(x)	( 1 << x )

#define KEY_BYTES		8
#define CD_BITS			28
#define KEY_SCHEDULE		16
#define AA 0
#define BB 1
#define RR 1
#define LL 0

union block_48 {
	unsigned char string[9];
	unsigned short SxSy[4];
	unsigned long AB[2];
};

/* Key Schedule permuted for S Box input: */


union block_48 K_S[16];

/* PC1_C/D are ByteBit indexes into an key input as a string of 8 chars */

static int PC1_C[28] = {
	        0x77, 0x67, 0x57, 0x47, 0x37, 0x27, 0x17, 0x07,
		0x76, 0x66, 0x56, 0x46, 0x36, 0x26, 0x16, 0x06,
		0x75, 0x65, 0x55, 0x45, 0x35, 0x25, 0x15, 0x05,
		0x74, 0x64, 0x54, 0x44
		};
static int PC1_D[28] = {
		0x71, 0x61, 0x51, 0x41, 0x31, 0x21, 0x11, 0x01,
		0x72, 0x62, 0x52, 0x42, 0x32, 0x22, 0x12, 0x02,
		0x73, 0x63, 0x53, 0x43, 0x33, 0x23, 0x13, 0x03,
		                        0x34, 0x24, 0x14, 0x04 
		};

/* Key Schedule shifts*/
static int leftshift[] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

/* PC2 has been converted to C and D lookups, 6 bits input to 8 s boxes
 * Column and row straightened out LSB to MSB.  Bit 0 - 5 order.
 */
/* S1 thru S4 from C, S5 thru S8 from D */
 static int PC2_S18[8][6] = {
	   13,  16,  10,  23,   0,   4,	    /* S1 */
	    2,  27,  14,   5,  20,   9,	    /* S2 */
	   22,  18,  11,   3,  25,   7,	    /* S3 */
	   15,   6,  26,  19,  12,   1,	    /* S4 */
	   12,  23,   2,   8,  18,  26,	    /* S5 */
	    1,  11,  22,  16,   4,  19,     /* S6 */
	   15,  20,  10,  27,   5,  24,	    /* S7 */
	   17,  13,  21,   7,   0,   3	    /* S8 */
};

#ifndef LITTLE_ENDIAN  /* BIG_ENDIAN */
static int byte_order[8] = {3,7,2,6,1,5,0,4};
#else		       /* LITTLE_ENDIAN */
static int byte_order[8] = {0,4,1,5,2,6,3,7};
#endif

void
fsetkey(key)
unsigned char *key;
{
    register int i,Key,sbox,bit, C_carry,D_carry;
    register unsigned long C = 0;
    register unsigned long D = 0;

    for (i=0;i < KEY_BYTES;i++)  /* ascii keys -  save bit 0 */
	key[i] = key[i] << 1;

    for (i=0;i< CD_BITS;i++) {		/* load C and D registers  */
	if( key[PC1_C[i] >> 4] & BIT((PC1_C[i] & 0xf)))
	    C |= BIT(i);
	if( key[PC1_D[i] >> 4] & BIT((PC1_D[i] & 0xf)))
	    D |= BIT(i);
    }

    for(i=0;i< KEY_BYTES+1;i++)	  /* erase key source */
	key[i] = 0;

    for ( Key = 0; Key < KEY_SCHEDULE; Key++) {
	for ( i = 0; i < leftshift[Key];i++) {
	    C_carry = C & 1;
	    D_carry = D & 1;
	    C = C >> 1;		/* rotate C and D */
	    D = D >> 1;
	    if (C_carry)
		C |= BIT(27);
	    if (D_carry)
		D |= BIT(27);
	}

	K_S[Key].AB[1] = K_S[Key].AB[0] = 0;

	for (sbox = 0; sbox < 8; sbox++){  /* load Key S Box Key_Scheds */

	    for (bit = 0; bit < 6; bit++){

		if ( sbox < 4) {
		    if ( C & BIT(PC2_S18[sbox][bit]) )
			K_S[Key].string[byte_order[sbox]] |= BIT(bit);
		}
		else {
		    if ( D & BIT(PC2_S18[sbox][bit]) )
			K_S[Key].string[byte_order[sbox]] |= BIT(bit);
		}
	    }
	}
    }
}

main(argc, argv)
int	argc;
char	*argv[];
{
    register unsigned int byte,value,schedule;
    register union block_48 data;
    printf("/*\n *\tkey.h -\tbyte to key schedule[16][2]\n");
    printf(" *\t\tproduces: unsigned long KEY[8][128][16][2]\n *\n */\n");

    printf("static unsigned long KEY[8][128][16][2] = \n{\n");

	data.AB[1] = data.AB[0] = 0;
    for (byte = 0;byte < 8; byte++) {

	printf("/* Byte Location %d */\n",byte);
	
	for(value = 0;value <  128;value++) {
	    data.string[byte] = value;
	    fsetkey(data.string);
	    for(schedule = 0; schedule < 16;schedule++){
		printf("  %#10x,  ",K_S[schedule].AB[0]);
		printf("  %#10x,  ",K_S[schedule].AB[1]);
		if(schedule & 1)
		    printf("\n");
	    }
	}
    }
    printf("\n};\n");
    exit(0);
}
