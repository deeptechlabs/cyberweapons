/**********************************************************************

    Copyright (c) 1993, 1994 by Carl Ellison and William Setzer
    This code may be used for any purpose, provided this copyright
    and statement are left intact.

prngxor.c -- Written by Carl Ellison from tran.c (originally written by
setzer@math.ncsu.edu (William Setzer) and modified by Carl Ellison).

This software is not claimed to offer cryptographic security.  Rather, it
is offered as an illustration of a general cryptographic technique which
has been known and analyzed for years -- exclusive OR with a running key
stream, also known as a stream cipher.

To make this program secure, one would have to use a cryptographically
strong PRNG (pseudo-random number generator), rnd().  If instead of a PRNG
one used a truly random key stream which was used only once and was known
only to the parties involved in the communication, then this would be a
true one-time-tape program, as published by Vernam in about 1920.  That
algorithm is the only provably secure cipher known to this author.  It
suffers from a need to distribute massive keys, however, and is considered
impractical except for the highest security applications (such as the hot
line between Washington and Moscow).  Between friends who get together
physically often enough to exchange floppy disks of key material (*truly*
random numbers -- not PRNG output), this might also be practical, given the
invention of the personal computer and high density floppy disks.

Usage:  as written, prngxor takes 0 to 2 arguments:

      prngxor  <input file>  <output file>

If either of the files is not specified, stdin or stdout is used
respectively.  Because prngxor uses XOR, it is a self-inverse.  That is, in
UNIX terms,

      prngxor <f1 | prngxor >f2

is a no-op -- copying f1 to f2.

**********************************************************************/

#include <stdio.h>

extern void set_rnd_seed();	/* initialize the PRNG */
extern unsigned long rnd();	/* get the next word from the PRNG */

#define BLOCKSIZE (1024)	/* block size for I/O */

char buf[BLOCKSIZE];		/* block of input bytes */

FILE *my_fopen(file, type)	/* open a file for R or W */
char *file, *type;
{
  FILE *fp;

  if (fp = fopen(file, type))	/* do the open */
    return fp;			/* if no error, return */
  (void) fprintf(stderr, "Can't open '%s'\n", file); /* error: print msg */
  exit(1);			/* and exit */
} /* end of my_fopen */

main(argc, argv)		/* read parameters and do the XOR */
long argc;
char **argv;
{
  register long i, len;
  register FILE *infp, *outfp;
  long savlen, pos ;
  long key[256] ;
  char tmp;

  infp  = (argc > 1) ? my_fopen(argv[1], "r") : stdin ;	/* input file name */
  outfp = (argc > 2) ? my_fopen(argv[2], "w") : stdout ; /* output file name */

  /* initialize the PRNG key */

  for (i=0;i<256;i++) key[i] = i ; /* init the histogram array */

  set_rnd_seed(key);		/* init the ranno generator with key */

  while (len = fread(buf, 1, BLOCKSIZE, infp)) /* for each input block */
    {
      for ( i = 0; i < len; i++) /* for each byte in the block */
	buf[i] ^= (rnd() & 0xff) ; /* XOR it with one random byte */
      fwrite(buf, 1, len, outfp); /* and write the block as output */
    } /* while */
  exit(0) ;
} /* end of main */
