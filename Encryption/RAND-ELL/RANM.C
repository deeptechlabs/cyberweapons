/***************************************************************************/
/* ranM.c -- process stdin by algorithm M, from Knuth vol.2                */
/*  This is the PRNG suggested by MacLaren and Marsaglia [JACM 12 (1965),  */
/*  83-89; CACM 11 (1968), 759] (Knuth, vol.2, 2nd Ed., 1981, p.31).       */
/*                                                                         */
/*  There are two modes:                                                   */
/*                    ranM                                                 */
/*     seeds a subtract-with-borrow PRNG from stdin, then uses that PRNG's */
/*     output to select bytes from stdin to send to stdout.                */
/*                                                                         */
/*                    ranM <fname>                                         */
/*     reads selection bytes from <fname> (possibly a named pipe) to       */
/*     select bytes of stdin to send to stdout.                            */
/*                                                                         */
/*  ranM reads BULK_SIZ (32771) bytes of stdin to prime the array, so if   */
/*  stdin is from a limited file, stdout will be short by that many bytes. */
/*                                                                         */
/*   Copyright (c) 1993, 1994, 1995 Carl M. Ellison                        */
/*                                                                         */
/*   This software may be copied and distributed for any purposes          */
/*   provided that this copyright and statement are included in all such   */
/*   copies.                                                               */
/***************************************************************************/

#include <sys/param.h>
#include <sys/errno.h>
extern int errno;
#include <sys/file.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#define BULK_SIZ  (32771)	/* (prime) number of bytes in bulk[] */

static unsigned char bulk[BULK_SIZ] ; /* buffer of bytes */

static unsigned char
  next_byte() ;			/* get next ranno byte from bulk/stdin */

static unsigned char
  ind_byte() ;			/* get next ranno byte from bulk/stdin */

FILE *indf = NULL ;		/* file for index bytes */

/***************************************************************************/
/* main                                                                    */
/***************************************************************************/

main(argc, argv)
int argc;
char **argv;
{
  long i ;			/* index into arrays */
  long lim ;			/* limit */
  unsigned long ini[256] ;	/* to init the PRNG */

  for (i=0;i<BULK_SIZ;i++) bulk[i] = getchar() ; /* fill the bulk array */

  switch (argc) {
  case 1:			/* use stdin and rnd() */
    { long j, k ;		/* index vbls */
      for (j=k=0; j<256; j++, k += 2 )
	ini[j] = (bulk[k] << 8) | bulk[k+1] ;
    }
    set_rnd_seed( ini ) ;	/* init the PRNG */
    while (!(feof(stdin)||ferror(stdin)))
      putchar( next_byte() ) ;
    exit(0) ;

  case 2:			/* use the file given for indexes */
    indf = fopen( argv[1], "rb" ) ; /* read the file in binary */
    if (indf == NULL) {
      fprintf( stderr, "could not open %s\n", argv[1] ) ;
      exit(1) ;
    }
    while (!(feof(stdin)||ferror(stdin)||feof(indf)||ferror(indf)))
      putchar( ind_byte() ) ;
    exit(0) ;

  default:
    fprintf( stderr, "Usage:  %s [<ransource>]\n\
Where <ransource> is an optional file or stream of random bytes\n\
(2 per output byte) used to drive the algorithm.  If <ransource> is\n\
omitted, %s uses stdin and a relatively weak PRNG for generating\n\
index values.\n", argv[0], argv[0] ) ;
  } /* switch */

  exit(0);
} /* main */

/***************************************************************************/
/* next_byte -- get the next byte from bulk[].                             */
/***************************************************************************/

static unsigned char
next_byte()
{
  unsigned char r ;
  long i = rnd() ;		/* get ranno value for index */

  i %= BULK_SIZ ;		/* restrict it to a bulk[] index */
  r  = bulk[i] ;		/* get the saved char */
  bulk[i] = getchar() ;		/* and replace it */
  return ( r ) ;		/* return the saved char */
} /* next_byte */

/***************************************************************************/
/* ind_byte -- get the next byte from bulk[].                              */
/***************************************************************************/

static unsigned char
ind_byte()
{
  unsigned char r ;
  long i ;			/* ranno value for index */

  i = fgetc( indf ) ;		/* read 2 input bytes */
  i = i * 256 + fgetc( indf ) ;	/* to form the index into bulk[] */
  i %= BULK_SIZ ;		/* restrict it to a bulk[] index */
  r  = bulk[i] ;		/* get the saved char */
  bulk[i] = getchar() ;		/* and replace it */
  return ( r ) ;		/* return the saved char */
} /* ind_byte */
