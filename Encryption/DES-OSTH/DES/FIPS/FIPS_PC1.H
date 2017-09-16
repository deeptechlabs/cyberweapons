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
 * The permutation choise 1 PC1 as described in FIPS 46 1977 January 15.
 *
 * The bits of KEY is numberd 1 .. 64. The bits of C0 are
 * 57, 49, ... 36 of KEY. The bits of D0 are 63, 55, .. 4
 * of KEY.
 */

#define PC1_ROWS	8
#define PC1_COLUMNS	7

CONST unsigned char	pc1[PC1_ROWS][PC1_COLUMNS] = {
				/* C0 */
				{ 57, 49, 41, 33, 25, 17,  9 },
				{  1, 58, 50, 42, 34, 26, 18 },
				{ 10,  2, 59, 51, 43, 35, 27 },
				{ 19, 11,  3, 60, 52, 44, 36 },

				/* D0 */
				{ 63, 55, 47, 39, 31, 23, 15 },
				{  7, 62, 54, 46, 38, 30, 22 },
				{ 14,  6, 61, 53, 45, 37, 29 },
				{ 21, 13,  5, 28, 20, 12,  4 }
			};
