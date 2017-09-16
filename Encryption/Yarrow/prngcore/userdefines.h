/*
	userdefines.h

	Header file that contains the major user-defineable quantities for the Counterpane PRNG.
*/
#ifndef YARROW_USER_DEFINES_H
#define YARROW_USER_DEFINES_H

/* User-alterable define statements */
#define STRICT				/* Define to force strict type checking */
#define K 0					/* How many sources should we ignore when calculating total entropy? */
#define THRESHOLD 100		/* Minimum amount of entropy for a reseed */
#define BACKTRACKLIMIT 500	/* Number of outputed bytes after which to generate a new state */
#define COMPRESSION_ON		/* Define this variable to add on-the-fly compression (recommended) */
							/* for user sources */
#define WIN_95				/* Choose an OS: WIN_95, WIN_NT */

/* Setup Microsoft flag for NT4.0 */
#ifdef WIN_NT
#define _WIN32_WINNT 0x0400
#endif

#endif