/***************************************************************************/
/* ranH.c -- process stdin by sending it to MD5 and put the hash results   */
/*   to stdout.  Use (16+j) bytes of input for each output batch.  The j   */
/*   is chosen randomly between n and x.  n and x are provided on the      */
/*   command line (min and max values for j).  The "random" value is taken */
/*   from the output of the MD5.                                           */
/*                                                                         */
/* ranH -n <min extra> -x <max extra>                                      */
/*                                                                         */
/*   Copyright (c) 1993, 1994, 1995 Carl M. Ellison                        */
/*                                                                         */
/*   This software may be copied and distributed for any purposes          */
/*   provided that this copyright and statement are included in all such   */
/*   copies.                                                               */
/***************************************************************************/

#include <stdio.h>

#include "global.h"		/* RSAREF global defs */
#include "md5.h"		/* MD5 definitions */

extern	int	optind;
extern	char	*optarg;

static usage() ;
static void do_stream() ;

static long  minex, maxex ;	/* min and max extra amounts */
static long  ranval, maxran ;	/* random value and maximum value there */
static short augran = 0 ;	/* boolean: augment ranval */

/***************************************************************************/
/* main                                                                    */
/***************************************************************************/

main(argc, argv)
int argc;
char **argv;
{
  int	ch, sl ;
  int  c ;

  minex = 4 ;
  maxex = 17 ;

  ranval = 314 ;		/* dummy value, to start with, */
  maxran = 325 ;		/* just to seed the calculation */

  while ((ch = getopt(argc, argv, "n:x:")) != EOF)
    switch((char)ch) {
    case 'n':
      minex = atoi( optarg ) ;
      break ;

    case 'x':
      maxex = atoi( optarg ) ;
      break ;

    case '?':
    default:
      exit(usage(argv[0]));
    }

  if (minex > maxex) {
    fprintf( stderr, "%d minimum extra bytes > %d maximum extra bytes. Bye.\n",
	     minex, maxex ) ;
    exit( usage( argv[0] ) ) ;
  } /* if */

  if ((maxex-minex)>200) {
    fprintf( stderr, "max-min = %d > 200 (the max variation allowed)\n",
	     maxex-minex ) ;
    exit( usage( argv[0] ) ) ;
  } /* if */  

  maxex += 16 ;
  minex += 16 ;

  do_stream() ;

  exit(0);
} /* main */

/***************************************************************************/
/* usage -- print the usage message.                                       */
/***************************************************************************/

static usage(n)
char *n ;
{
  fprintf(stderr, "usage: %s -n <min # extra bytes per block> -x <max...>\n",
	  n);
  return(1);
} /* usage */

/***************************************************************************/
/* ran - return a value, 0 <= x < r, pulled from ranval.                   */
/***************************************************************************/

static long ran(r)
long r ;
{
  long x ;

  if ( r <= 1 ) return ( 0 ) ;
  x = ranval % r ;
  ranval /= r ;
  maxran /= r ;

  return ( x ) ;

} /* ran */

/***************************************************************************/
/* do_stream -- read stdin, gathering input for MD5, writing blocks to     */
/*    stdout.                                                              */
/***************************************************************************/

void do_stream()
{
  unsigned char ibuf[BUFSIZ] ;	/* input line buffer */
  MD5_CTX ctx ;			/* context for MD5 */
  long nb, nb2r, nbvar ;	/* # bytes read, # to read, # variation */
  unsigned int i ;

  nbvar = 1 + maxex - minex ;	/* variation in # of extra bytes */

  while (1) {
    MD5Init( &ctx ) ;		/* init the MD5 context */
    nb2r = minex + ran( nbvar ) ; /* compute # of bytes to read */
    /* read a full nb2r */
    while (nb2r > 0) {
      i = fread( ibuf, 1, (nb2r<BUFSIZ)?nb2r:BUFSIZ, stdin ) ;
      if (i == 0) return ;	/* too few bytes for another batch of output */
      nb2r -= i ;
      MD5Update( &ctx, ibuf, i ) ;
    } /* while (nb2r>0) */
    /* have the results */
    MD5Final( ibuf, &ctx ) ;
    if (maxran <= nbvar) {	/* grab a byte for ranval */
      maxran = (maxran+1) * 256 ; /* new 1+ maximum value */
      ranval = (ranval*256) + ibuf[15] ; /* new random value */
      fwrite( ibuf, 1, 15, stdout ) ; /* and ship the rest */
    } else
      fwrite( ibuf, 1, 16, stdout ) ; /* ship the whole output */
  } /* while TRUE */
} /* do_stream */


