/***************************************************************************/
/* ranD.c -- process stdin by sending it through triple-DES, using keys    */
/*   built from the input (via MD5).                                       */
/*                                                                         */
/*   Copyright (c) 1993, 1994, 1995 Carl M. Ellison                        */
/*                                                                         */
/*   This software may be copied and distributed for any purposes          */
/*   provided that this copyright and statement are included in all such   */
/*   copies.                                                               */
/***************************************************************************/

#include <stdio.h>

#include "global.h"		/* RSAREF global defs */
#include "rsaref.h"		/* RSAREF definitions */

#define BLOCK_SIZE  (256)	/* processing block */

static void do_stream() ;

/***************************************************************************/
/* main                                                                    */
/***************************************************************************/

main(argc, argv)
int argc;
char **argv;
{
  do_stream() ;
  exit(0);
} /* main */

/***************************************************************************/
/* make0 -- b has nb bytes, now.  Make nb == 0 mod 8 by taking bytes from  */
/*  the end and putting them in slop[] or if slop[] has more than 8 bytes, */
/*  and nb < BLOCK_SIZE, move some bytes from slop to b.                   */
/***************************************************************************/

static unsigned char slop[ 8 ] ; /* slop bytes, waiting for short lines */
static long nslop = 0 ;		/* number of bytes in slop[] */

void make0( b, pnb )
unsigned char b[] ;		/* the input line */
long *pnb ;			/* its length */
{
  register long nb = *pnb ;	/* # bytes in b[] */
  register long nsl = nslop ;	/* # bytes in slop[] */
  register long ns = nb & 0x7 ; /* how many slop bytes in b? */

  while ( ((ns + nsl) >= 8 ) && (nb < BLOCK_SIZE) ) {
    b[ nb++ ] = slop[ nsl-- ] ; /* add slop bytes */
    ns = nb & 0x7 ;		/* recompute ns */
  } /* while room and bytes to move from slop to b */
  while ( ns > 0 ) {
    slop[ nsl++ ] = b[ nb-- ] ;	/* save a byte in slop[] */
    ns-- ;			/* and count it */
  } /* while some slop in b[] but not enough combined to make == 0 mod 8 */
  *pnb = nb ;			/* tell caller the new length */
  nslop = nsl ;			/* record # of bytes in slop[] */
  return ;
} /* make0 */

/***************************************************************************/
/* do_stream -- read stdin, gathering input for MD5 for DES keys, then use */
/*   DES to encrypt stdin to stdout.                                       */
/***************************************************************************/

void do_stream()
{
  MD5_CTX ctx ;			/* context for MD5 */
  long nb ;			/* # bytes  */
  unsigned char key[32] ;	/* generated from MD5 of initial stdin */
  unsigned char *iv ;		/* last 8 bytes of key */
  unsigned char bin[BLOCK_SIZE],
                bout[BLOCK_SIZE] ; /* do blocks of BLOCK_SIZE bytes */
  DES3_CBC_CTX dctx ;		/* DES context */
  int ch ;			/* character from getchar() */

  iv = &(key[24]) ;		/* last 8 bytes */

  MD5Init( &ctx ) ;		/* init the first MD5 */
  nb = BLOCK_SIZE ;		/* gather the whole block, even if fread() */
  iv = bin ;			/* sometimes returns short blocks */
  while (((ch=getchar())!=EOF) && (nb-- > 0)) *(iv++) = ch ;
  MD5Update( &ctx, bin, BLOCK_SIZE ) ;
  MD5Final( key, &ctx ) ;

  MD5Init( &ctx ) ;		/* the second MD5 */
  nb = BLOCK_SIZE ;		/* gather the whole block */
  iv = bin ;			/* walk bin with iv */
  while (((ch=getchar())!=EOF) && (nb-- > 0)) *(iv++) = ch ;
  MD5Update( &ctx, bin, BLOCK_SIZE ) ;
  MD5Final( &(key[16]), &ctx ) ;

  DES3_CBCInit( &dctx, key, iv, 1 ) ; /* encrypting (not that it matters) */
				/* you can't decrypt this stream */
				/* which suggests that ranD should be */
				/* exportable.... */

  while (!feof( stdin )) {
    nb = fread( bin, 1, BLOCK_SIZE, stdin ) ; /* get a block of input */
    /* the man page warns that fread() can be short, for some devices */
    make0( bin, &nb ) ;		/* make nb = 0 mod 8 */
    if (nb > 0) {		/* any bytes left? */
      DES3_CBCUpdate( &dctx, bout, bin, nb ) ;
      fwrite( bout, 1, nb, stdout ) ;
    }
  } /* while */

} /* do_stream */


