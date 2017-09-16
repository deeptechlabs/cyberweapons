/***************************************************************************/
/* ranT.c -- split stdin equally to multiple output files/pipes.           */
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
  long nact = 0 ;		/* # of active files */
  int ch ;			/* input character */
  FILE *f ;

  farr = (FILE **) malloc( argc * sizeof( f ) ) ;

  farr[ 0 ] = stdout ;
  nact = 1 ;

  for (i = 1; i<argc; i++ ) {
    f = fopen( argv[i], "ab" ) ;
    if (f != NULL ) {
      farr[ nact++ ] = f ;
    } /* if */
  } /* for */
fprintf( stderr, "nact = %d\n", nact ) ;
  while (1)
    for (i=0;i<nact;i++) {
      int ch = fgetc( stdin ) ;
      if (ch == EOF)
	exit(0) ;
      else
	fputc( ch, farr[i] ) ;
    } /* for, if */

  exit(0);
} /* main */
