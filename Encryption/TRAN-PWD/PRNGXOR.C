/**********************************************************************

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

Usage:  as written, prngxor takes 0 to 3 arguments:

      prngxor <password-string>  <input file>  <output file>

If either of the files is not specified, stdin or stdout is used
respectively.  If the password string is not specified, a constant password
becomes the key.  Because prngxor uses XOR, it is a self-inverse.  That is,
in UNIX terms,

      prngxor <f1 | prngxor >f2

is a no-op -- copying f1 to f2.

There was posted to sci.crypt a version of prngxor which accepts no
password and is therefore not capable of hiding information.  That program
was written to illustrate cryptographic techniques but to remain free of
U.S. Government export limitations.  If no password is given to this
program, it should interoperate with the publicly posted version.

**********************************************************************/

#include <stdio.h>

extern void set_rnd_seed();	/* initialize the PRNG */
extern unsigned long rnd();	/* get the next word from the PRNG */

#define BLOCKSIZE (1024)	/* block size for I/O */

unsigned char buf[BLOCKSIZE];	/* block of input bytes */

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
  char *password, *pwp ;

  password   = (argc > 1) ? argv[1] : 0 ; /* typed password */
  infp  = (argc > 2) ? my_fopen(argv[2], "r") : stdin ;	/* input file name */
  outfp = (argc > 3) ? my_fopen(argv[3], "w") : stdout ; /* output file name */

  /* initialize the PRNG key */
  pwp = password ;		/* point to the typed password */
  if (password == 0)		/* if there was none, ignore it */
    for (i=0;i<256;i++) key[i] = i ; /* init the histogram array */
  else				/* there was a password typed */
    for (i=0;i<256;i++)		/* init the array with the password */
      { char nxt = *(pwp++) ;	/* get the next password char and advance */
	if (nxt == 0)		/* if off the end of the typed password, */
	  pwp = password ;	/*  ... cycle to the start */
	key[i] = nxt + i ;	/* use the current char to init this loc */
      } /* for -- using the command line password */

  set_rnd_seed(key);		/* init the ranno generator with key */

  while (len = fread(buf, 1, BLOCKSIZE, infp)) /* for each input block */
    {
      for ( i = 0; i < len; i++) /* for each byte in the block */
	buf[i] ^= (rnd() & 0xff) ; /* XOR it with one random byte */
      fwrite(buf, 1, len, outfp); /* and write the block as output */
    } /* while */
} /* end of main */
