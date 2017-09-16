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
 * Key generation left shift table as described in FIPS 46 1977 January 15.
 */

CONST unsigned char	ls[DES_ITERATIONS] = {
				1, /* Iteration  1 */
				1, /* Iteration  2 */
				2, /* Iteration  3 */
				2, /* Iteration  4 */
				2, /* Iteration  5 */
				2, /* Iteration  6 */
				2, /* Iteration  7 */
				2, /* Iteration  8 */
				1, /* Iteration  9 */
				2, /* Iteration 10 */
				2, /* Iteration 11 */
				2, /* Iteration 12 */
				2, /* Iteration 13 */
				2, /* Iteration 14 */
				2, /* Iteration 15 */
				1  /* Iteration 16 */
			};
