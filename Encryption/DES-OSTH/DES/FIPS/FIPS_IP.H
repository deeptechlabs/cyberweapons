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
 * The initial permutation IP as described in FIPS 46 1977 January 15.
 *
 * The permuted input has bit 58 pf the input block as its first bit,
 * bit 50 as it second bit, and so on with bit 7 as its last bit.
 */

#define IP_ROWS		8
#define IP_COLUMNS	8

CONST unsigned char	ip[IP_ROWS][IP_COLUMNS] = {
				{ 58, 50, 42, 34, 26, 18, 10,  2 },
				{ 60, 52, 44, 36, 28, 20, 12,  4 },
				{ 62, 54, 46, 38, 30, 22, 14,  6 },
				{ 64, 56, 48, 40, 32, 24, 16,  8 },
				{ 57, 49, 41, 33, 25, 17,  9,  1 },
				{ 59, 51, 43, 35, 27, 19, 11,  3 },
				{ 61, 53, 45, 37, 29, 21, 13,  5 },
				{ 63, 55, 47, 39, 31, 23, 15,  7 }
			};
