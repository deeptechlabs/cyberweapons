#include	"fips_def.h"
#include	"fips_LS.h"

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
 * Macro to shift (rotate) the 28 least significant bits of `CD'.
 * Max two left shift step is valid.
 */

#define LS(n, CD) \
	if (CD & 0x1l) \
		CD |= 0x10000000l; \
	if (ls[n] == 2) { \
		if (CD & 0x2l) \
			CD |= 0x20000000l; \
		CD >>= 2; \
	} else \
		CD >>= 1
