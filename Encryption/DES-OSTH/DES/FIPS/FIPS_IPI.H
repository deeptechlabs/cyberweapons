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
 *			     -1
 * The initial permutation IP   as described in FIPS 46 1977 January 15.
 *
 * The permuted input has bit 40 of the input block as its first bit,
 * bit 8 as it second bit, and so on with bit 25 as its last bit.
 */

#define IPinv_ROWS	8
#define IPinv_COLUMNS	8

CONST unsigned char	ip_inv[IPinv_ROWS][IPinv_COLUMNS] = {
				{ 40,  8, 48, 16, 56, 24, 64, 32 },
				{ 39,  7, 47, 15, 55, 23, 63, 31 },
				{ 38,  6, 46, 14, 54, 22, 62, 30 },
				{ 37,  5, 45, 13, 53, 21, 61, 29 },
				{ 36,  4, 44, 12, 52, 20, 60, 28 },
				{ 35,  3, 43, 11, 51, 19, 59, 27 },
				{ 34,  2, 42, 10, 50, 18, 58, 26 },
				{ 33,  1, 41,  9, 49, 17, 57, 25 }
			};
