/*
 *	loki.i - contains the fixed permutation and substitution tables 
 *			for a 64 bit LOKI89 & LOKI91 implementations.
 *
 *  Modifications:
 *	v1.0	original tables                       	Aug 1989 lpb
 *	v2.0	add various speed/size versions		Apr 1990 lpb
 *	v2.1	install into RCS system for production control 5/90 lpb
 *	v3.0	LOKI89 & LOKI91 now supported		10/92 lpb
 *
 *  Author:	Lawrence Brown <lpb@csadfa.oz>		Aug 1989
 *		Computer Science, UC UNSW, ADFA, Canberra, ACT 2600, Australia.
 *
 *  Copyright 1989 by Lawrence Brown and UNSW. All rights reserved.
 *      This program may not be sold or used as inducement to buy a
 *      product without the written permission of the author.
 */

/* 32-bit permutation function P */
/*   specifies which input bit is permuted to output bits */
/*   31 30 29 ... 2 1 0 respectively (ie in MSB to LSB order) */
char P[32] = {
	31, 23, 15, 7, 30, 22, 14, 6,
	29, 21, 13, 5, 28, 20, 12, 4,
	27, 19, 11, 3, 26, 18, 10, 2,
	25, 17, 9, 1, 24, 16, 8, 0
	};

/*
 *	sfn_desc - a desriptor table specifying which irreducible polynomial
 *		and exponent is to be used for each of the 16 S functions in
 *		the Loki S-box
 */
typedef	struct {
	short	gen;		/* irreducible polynomial used in this field */
	short	exp;		/* exponent used to generate this s function */
	} sfn_desc;

/*
 *	sfn - the table specifying the irreducible polys & exponents used
 *		in the Loki S-boxes for the Loki algorithm
 */
sfn_desc sfn[] = {
	{ /* 101110111 */ 375, 31},
	{ /* 101111011 */ 379, 31},
	{ /* 110000111 */ 391, 31},
	{ /* 110001011 */ 395, 31},
	{ /* 110001101 */ 397, 31},
	{ /* 110011111 */ 415, 31},
	{ /* 110100011 */ 419, 31},
	{ /* 110101001 */ 425, 31},
	{ /* 110110001 */ 433, 31},
	{ /* 110111101 */ 445, 31},
	{ /* 111000011 */ 451, 31},
	{ /* 111001111 */ 463, 31},
	{ /* 111010111 */ 471, 31},
	{ /* 111011101 */ 477, 31},
	{ /* 111100111 */ 487, 31},
	{ /* 111110011 */ 499, 31},
	{ 00, 00}
	};
