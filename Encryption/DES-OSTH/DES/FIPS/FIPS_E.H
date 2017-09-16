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
 * The bit slection E as described in FIPS 46 1977 January 15.
 *
 * The selected input has bit 32 pf the input block as its first bit,
 * bit 1 as it second bit, and so on with bit 1 as its last bit.
 */

#define E_ROWS		8
#define E_COLUMNS	6

CONST unsigned char	e[E_ROWS][E_COLUMNS] = {
				{ 32,  1,  2,  3,  4,  5 },
				{  4,  5,  6,  7,  8,  9 },
				{  8,  9, 10, 11, 12, 13 },
				{ 12, 13, 14, 15, 16, 17 },
				{ 16, 17, 18, 19, 20, 21 },
				{ 20, 21, 22, 23, 24, 25 },
				{ 24, 25, 26, 27, 28, 29 },
				{ 28, 29, 30, 31, 32,  1 }
			};
