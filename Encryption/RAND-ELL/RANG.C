/***************************************************************************/
/* ranG {MD5, SWB}                                                         */
/*                                                                         */
/*  takes bytes from stdin to init the PRNG.                               */
/*                                                                         */
/* Usage:  ranG                // uses subtract-with-borrow                */
/*         ranG md5            // uses MD5 as a PRNG                       */
/*                                                                         */
/* If any stdin remains after init, XOR those bytes with the PRNG output.  */
/* Continue after that with just the PRNG, forever.                        */
/*                                                                         */
/*    Copyright (c) 1993, 1994, 1995 by Carl Ellison                       */
/*    This code may be used for any purpose, provided this copyright       */
/*    and statement are left intact.                                       */
/***************************************************************************/

#include <stdio.h>
#include <string.h>
#include "global.h"
#include "md5.h"

extern void set_rnd_seed();	/* initialize the PRNG */
extern unsigned long rnd();	/* get the next word from the PRNG */

#define BLOCKSIZE (256)		/* block size for I/O */

char buf[BLOCKSIZE];		/* block of input bytes */

main(argc, argv)		/* read parameters and do the XOR */
long argc;
char **argv;
{
  register long i, len;
  long key[256] ;
  int tmp ;
  short use_md5 = (argc == 2) && (0 == strcmp( argv[1], "md5" ) ) ;

  if ( use_md5 ) {
    MD5_CTX ctx ;		/* context for the MD5 */
    unsigned char seed[32] ;	/* seed for future stuff */
    unsigned char val[16] ;	/* output from each round */

    MD5Init( &ctx ) ;		/* init the context */
    MD5Update( &ctx, "first", 5 ) ; /* something to start with */
    len = fread( buf, 1, BLOCKSIZE, stdin ) ; /* get input */
    MD5Update( &ctx, buf, len ) ; /* hash this first block */
    MD5Final( seed, &ctx ) ;	/* get the seed */

    MD5Init( &ctx ) ;		/* init the context */
    MD5Update( &ctx, "second", 6 ) ; /* start here, too */
    MD5Update( &ctx, seed, 16 ) ; /* fold in the first batch */
    len = fread( buf, 1, BLOCKSIZE, stdin ) ; /* get input */
    MD5Update( &ctx, buf, len ) ; /* hash this first block */
    MD5Final( &(seed[16]), &ctx ) ; /* get the second half of the seed */

    /* OK -- generate values, XORing with any left-over input */
    while (len = fread( buf, 1, 16, stdin ) ) {
      MD5Init( &ctx ) ;
      for ( i=31; 0 == ++(seed[i]); i-- ) ; /* count the seed by 1 */
      MD5Update( &ctx, seed, 32 ) ;
      MD5Final( val, &ctx ) ;
      for ( i=0; i<len; i++ ) val[i] ^= buf[i] ; /* XOR remaining input */
      fwrite( val, 1, 16, stdout ) ;
    } /* while still input */

    while (1) {			/* no input left */
      MD5Init( &ctx ) ;
      for ( i=31; 0 == ++(seed[i]); i-- ) ; /* count the seed by 1 */
      MD5Update( &ctx, seed, 32 ) ;
      MD5Final( val, &ctx ) ;
      fwrite( val, 1, 16, stdout ) ;
    }
  } else {			/* use subtract-with-borrow */

  /* initialize the PRNG key */
    
    for (i=0; i<256; i++) key[i] = i ; /* pre-fill, in case of EOF */

    for (i=0; i<256; i++) {	/* init the key array */
      tmp = getchar() ;
      if (tmp == EOF) break ;
      tmp = (0xff & tmp) ; /* get one byte */
      key[i] = (tmp << 8) | (0xff & getchar()) ; /* get two bytes per loc */
    } /* for */

    set_rnd_seed( key ) ;		/* init the ranno generator with key */

    while (len = fread( buf, 1, BLOCKSIZE, stdin)) /* for each input block */
      {
	for ( i = 0; i < len; i++) /* for each byte in the block */
	  buf[i] ^= (rnd() & 0xff) ; /* XOR it with one random byte */
	fwrite( buf, 1, len, stdout ) ; /* and write the block as output */
      } /* while */
    /* all the input is exhausted -- output just rnd() forever */

    while (1) {
      for ( i=0; i < BLOCKSIZE; i++ ) buf[i] = rnd() ;
      fwrite( buf, 1, BLOCKSIZE, stdout ) ;
    } /* while */
  }
} /* end of main */
