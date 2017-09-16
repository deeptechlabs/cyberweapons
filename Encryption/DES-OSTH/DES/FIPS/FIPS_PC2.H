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
 * The permuted coise 2 PC2 as decriped in FIPS 46 1977 January 15.
 *
 * The first bit of Kn is the 14th bit of CnDn the second is  th 17th
 * and so on with the 48th bit th 32nd.
 */

#define PC2_ROWS	8
#define PC2_COLUMNS	6

CONST unsigned char	pc2[PC2_ROWS][PC2_COLUMNS] = {
				{ 14, 17, 11, 24,  1,  5 },
				{  3, 28, 15,  6, 21, 10 },
				{ 23, 19, 12,  4, 26,  8 },
				{ 16,  7, 27, 20, 13,  2 },
				{ 41, 52, 31, 37, 47, 55 },
				{ 30, 40, 51, 45, 33, 48 },
				{ 44, 49, 39, 56, 34, 53 },
				{ 46, 42, 50, 36, 29, 32 },
			};
