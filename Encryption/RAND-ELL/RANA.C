/***************************************************************************/
/* ranA.c -- merge inputs by alternating them.  Merge stdin and all of the */
/*  file names listed on the command line, assumed to be nothing but file  */
/*  names.                                                                 */
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
  FILE **farr ;			/* array of files */
  char *factive ;		/* array of file open booleans */
  long nact = 0 ;		/* # of active files */
  long maxact ;			/* max index of active files */
  int ch ;			/* input character */
  FILE *f ;

#define FALSE (0)
#define TRUE (1)

  farr = (FILE **) malloc( argc * sizeof( f ) ) ;
  factive = (char *) malloc( argc ) ;

  farr[ 0 ] = stdin ;
  factive[ 0 ] = TRUE ;
  nact = 1 ;

  for (i = 1; i<argc; i++ ) {
    f = fopen( argv[i], "rb" ) ;
    if (f != NULL ) {
      farr[ nact ] = f ;
      factive[ nact++ ] = TRUE ;
    } /* if */
  } /* for */

  maxact = nact ;
  while (nact > 0) {
    for (i=0;i<maxact;i++)
      if ( factive[i] ) {
	int ch = fgetc( farr[i] ) ;
	if (ch == EOF) {
	  factive[i] = FALSE ;
	  nact-- ;
	} else
	  fputc( ch, stdout ) ;
      } /* for, if */
  } /* while */

  /* One could, instead of the loop above, XOR all the successful ch values */
  /* together and, if nact>0, write the result at the end of the while loop. */
  /* That would produce fewer outputs but would also combine multiple PRNG */
  /* streams.  If you're not following this function by ranM, the XOR */
  /* might be worth it.  If you *are* following this by ranM, ranA is */
  /* probably superior. */

  /* That function, call it ranX, would have the advantage of being usable */
  /* for doing N-way secret sharing (by generating N-1 ranno files of the */
  /* same length as a file to be split and XORing them all together to get */
  /* the last share.)  However, for PRNG purposes, ranA is probably better. */

  exit(0);
} /* main */
