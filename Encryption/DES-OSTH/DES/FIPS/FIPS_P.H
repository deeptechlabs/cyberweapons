/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 * Additional restrictions due to national laws governing the use, import or
 * export of cryptographic software is the responsibility of the software user,
 * importer or exporter to follow.
 *
 *					     _
 *					Stig Ostholm
 *					Department of Computer Engineering
 *					Chalmers University of Technology
 */

/*
 * The permutation P as described in FIPS 46 1977 January 15.
 *
 * The permuted input has bit 16 pf the input block as its first bit,
 * bit 7 as it second bit, and so on with bit 25 as its last bit.
 */

#define P_ROWS		8
#define P_COLUMNS	4

CONST unsigned char	p[P_ROWS][P_COLUMNS] = {
				{ 16,  7, 20, 21 },
				{ 29, 12, 28, 17 },
				{  1, 15, 23, 26 },
				{  5, 18, 31, 10 },
				{  2,  8, 24, 14 },
				{ 32, 27,  3,  9 },
				{ 19, 13, 30,  6 },
				{ 22, 11,  4, 25 }
			};
