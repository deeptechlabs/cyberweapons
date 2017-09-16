/***************************************************************************/
/* ranX.c -- merge inputs by XORing them.  Merge stdin and all of the      */
/*  file names listed on the command line, assumed to be nothing but file  */
/*  names and switches.                                                    */
/*                                                                         */
/*   ranX [-s]                                                             */
/*     if -s, stop at first EOF (for XOR-splitting files)                  */
/*     by default, stop at the last EOF                                    */
/*                                                                         */
/*   Copyright (c) 1995 Carl M. Ellison                                    */
/*                                                                         */
/*   This software may be copied and distributed for any purposes          */
/*   provided that this copyright and statement are included in all such   */
/*   copies.                                                               */
/***************************************************************************/

#include <stdio.h>

/***************************************************************************/
/* main                                                                    */
/***************************************************************************/

main(argc, argv)
int argc;
char **argv;
{
  long i ;			/* index into arrays */
  FILE **farr ;			/* array of files */
  char *factive ;		/* array of file open booleans */
  long nact = 0 ;		/* # of active files */
  long maxact ;			/* max index of active files */
  int ch ;			/* input character */
  FILE *f ;
  short first_stop = 0 ;	/* by default, don't stop on first EOF */

#define FALSE (0)
#define TRUE (1)

  farr = (FILE **) malloc( argc * sizeof( f ) ) ;
  factive = (char *) malloc( argc ) ;

  farr[ 0 ] = stdin ;
  factive[ 0 ] = TRUE ;
  nact = 1 ;

  for (i = 1; i<argc; i++ )
    if (argv[i][0] == '-')
      switch (argv[i][1]) {	/* check switches */
      case 's':
	first_stop = 1 ;	/* stop on first EOF */
	break ;
      default:
	fprintf( stderr, "Usage: %s [-s]\n\
  -s: stop on first EOF\n\
  default: stop on last EOF\n", argv[0] ) ;
	exit(1) ;
      } /* switch */
    else {			/* not a switch -- a file name */
      f = fopen( argv[i], "rb" ) ;
      if (f != NULL ) {
	farr[ nact ] = f ;
	factive[ nact++ ] = TRUE ;
      } /* if */
    } /* else, for */

  maxact = nact ;
  while (nact > 0) {
    int xval = 0 ;		/* XOR accumulator */
    for (i=0;i<maxact;i++)
      if ( factive[i] ) {
	int ch = fgetc( farr[i] ) ;
	if (ch == EOF) {
	  if (first_stop) exit(0) ;
	  factive[i] = FALSE ;
	  nact-- ;
	} else
	  xval ^= ch ;		/* accumulate this piece */
      } /* for, if */
    if (nact > 0)
      fputc( xval, stdout ) ;	/* write the XOR result */
  } /* while */

  exit(0);
} /* main */
