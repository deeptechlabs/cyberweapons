/* secsplit.c */
/* Shamir secret sharing */
/* Based on "How to Share a Secret", by Adi Shamir,
   Communications of the ACM, November, 1979, Volume 22, Number 11, page
   612.

   Copyright (C) 1993 Hal Finney, 74076.1041@compuserve.com.
   Version 1.1, October, 1993.
   This software is being placed in the public domain.

   This program divides a file into n pieces, such that any k of them are
   sufficient to reconstruct the original file, but that k-1 pieces give
   NO information about the original file (except its length).

   It has been written for and tested on DOS and Unix systems.

   To split up a file, use the command;
      secsplit n k file
   where n is the number of pieces to split it up to, and k is the number
   of pieces needed to reconstruct it.  k should be <= n and > 1.  If you
   get n and k backwards the program will swap them for you so don't worry
   too much about remembering the order.

   The program will output to file.001, file.002, ....  If the file has an
   extension (e.g. "file.c") the extension will be stripped off before the
   ".001", etc., are added (so "file.c" will also output to "file.001", etc.).

   To reconstruct a file, use the command:
      secsplit k file.*
   or
      secsplit k file file1 file2...
   k should be >= the k used when the file was split; the minimum number of
   pieces needed to reconstruct the file.  If you have too few pieces then
   the program won't give an error, but you'll get the wrong answer.

   The first command form is for DOS or other systems which won't expand the
   ".*" for you; the program scans for file.000, file.001, etc., and uses the
   first k of them that it finds.  In the second form, the number of files
   given should be at least k, and again the first k of them will be used.

   The output in the first form will be file.out; in the second form it will
   be the first file on the command line, stripped of its extension, and
   with ".out" added, so generally it will be file.out too.

   Shamir's algorithm relies on cryptographically strong, unguessable,
   random numbers.  This version of the program uses the IDEA cryptographic
   algorithm used in the PGP encryption program to generate its random
   numbers.  This is thought to be a strong source of random numbers.
   The main potential weakness is in the initialization of the random
   number generator, which is based on the contents of the file being
   split, along with the current time of day.  This should be an unguessable
   seed as long as the contents of the file are not known by the attacker.
*/

/*
   Revision history:
   	Version 1.0	October 23, 1993

   	Version 1.1	October 24, 1993
   		Added IDEA-based random-number-generator, initialized by MD5
   		of input file, plus the time of day.
*/

/*
  The file formats used for output are as follows.  Each file starts with
  one byte which is the index, from 1 through n, of that file.  This is
  the x value used for the polynomial evaluation in Shamir's algorithm.
  The files then consist of a series of 16-bit values (high byte first),
  which are the result of applying Shamir's splitting algorithm to the
  input file taken in 16-bit chunks.  The prime used is slightly less than
  2^16, meaning that input data values close to 2^16 get turned into a
  pair of values (see below for more information on this expansion).

  If the input file is of even length, the output files will each by of
  that length+1 (because of the 1 byte at the beginning).  If the input
  file is of odd length, the input is padded with a random byte and 
  processed normally to get a pair of output bytes, then each output file
  is padded with an extra random byte to indicate this fact.  So output
  files which have an odd length correspond to input files with an even
  length, and vice versa.

  The output files could have encoded k and n information, but this could
  be helpful to an attacker (he would know when he was close to having enough
  pieces to reconstruct the file if he knew k).  So the user is required to
  remember this himself.

  The file formats are system-independent so files split on one kind of
  machine should be able to be reassembled on another kind of machine.

*/

/*
  One complication exists with this code.  The algorithm must work mod a
  prime which is bigger than all the data.  We want the data to be about
  16 bits therefore, so that we can multiply two numbers and have them fit
  in a 32-bit int.  This means that the prime has to be less than 2^16
  in order for them to fit.  The largest such prime is 65521.  This means
  that any data value > 65521 can't be processed directly; instead, I
  split it into two values, a 65520, followed by value-65520.  Also,
  65520 itself is split as 65520 followed by 0.  This complication is
  pretty well limited to the input routine on splitting and the output
  routine on assembly.
 */

/* The purpose of the "magic" is to xor the incoming value with a
 * different number each time.  This is purely intended to deal with
 * the problem that values of d >= limit-1 must be stored as four bytes
 * rather than two.  I was worried that some file might have a lot of
 * 0xff's which would balloon in size.  So I wanted to xor with a rather
 * random number.  Then, I change the random number each time in order
 * to make it less likely that some other file would happen to have a
 * lot of ballooning values.  This way it would be very rare that a file
 * managed to track my magic number in such a way that many d's were
 * over the size threshold.
 * (The "magic" is not intended to increase the security or the cryptographic
 * strength of the algorithm in any way; it is purely to keep the size of
 * the output files from being much bigger than the input.)
 */

#include <stdio.h>
#ifdef MSDOS
#include <stdlib.h>
#endif

#include "md5.h"

#define PRIME 65521
#define KMAX 48
#define NMAX 48

#ifdef NOMAGIC
/* For debugging */
#define IMAGIC 0
#define DMAGIC 0
#else
/* Two random values - see comment above to explain magic */
#define IMAGIC 0x8a31
#define DMAGIC 0x1347
#endif

#ifdef MSDOS
#define RB "rb"
#define WB "wb"
#define uint32 unsigned long
#else
#define RB "r"
#define WB "w"
#define uint32 unsigned int
#endif


/* Multiplicative inverses of 1-48 mod PRIME */
int invtab[] = {
    1, 32761, 43681, 49141, 52417, 54601, 56161, 57331,
    58241, 58969, 11913, 60061, 60481, 60841, 61153, 61426,
    42396, 61881, 6897, 62245, 62401, 38717, 11395, 62791,
    49796, 63001, 41254, 63181, 58743, 63337, 25363, 30713,
    3971, 21198, 63649, 63701, 54896, 36209, 63841, 63883,
    43148, 63961, 6095, 52119, 64065, 38458, 43216, 64156
};



/******************* Code related to splitting *********************/


/* Return a random number from 0 to n-1.  This version is optimized
 * for cases where n is slightly less than 0xffff.
 */
unsigned int
crandom (n)
unsigned int n;
{
    extern unsigned idearand();
    unsigned int c;

    do {
    	c = idearand() << 8;
    	c |= idearand();
    	c &= 0xffff;
    } while (c >= n);
    return c;
}

/* Init random number generator.  Use md5 of input file plus the
 * current time of day.
 */
void
initcrandom (f_in)
FILE *f_in;
{	int bytes;
	static unsigned char buffer[1024];
    MD5_CTX mdContext;
    unsigned char digest[16];
    long tbuf;

    /* Make sure at beginning of file */
    rewind(f_in);
    /* Calculate md5 of file into digest */
	MD5Init(&mdContext);
	while ((bytes = fread(buffer,1,1024,f_in)) != 0)
		MD5Update(&mdContext,buffer,bytes);
    MD5Final (digest, &mdContext);
    /* Get current time of day */
    time (&tbuf);
    /* Initialize key.  Notice that this routine can take up to 28 bytes of
     * random data but we only are giving it 20.  This should still be quite
     * random.
     */
    init_idearand(digest, digest, tbuf);
    /* Reset to beginning of file */
    rewind(f_in);
}


/* Evaluate the given polynomial, n coefficients, at point x=i.
 * Do it mod the specified modulus.
 */
unsigned int
eval(poly, n, i, mod)
unsigned int *poly;	/* Polynomial coefficients */
int n;			/* # coefficients (order of polynomial + 1) */
int i;			/* Point to evaluate it at */
unsigned int mod;	/* Modulus for evaluation */
{
    uint32 prod;		/* Accumulated product */
    int j;			/* index */

    prod = poly[n-1];
    for (j=n-1; --j>=0; ) {
	prod *= i;
	prod += poly[j];
	prod %= mod;
    }
    return prod;
}


/* Return a 16-bit value from file f_in, but limit it to be less than limit.
 * Anything >= limit-1 gets returned as two consecutive values (on 2 calls).
 * Return -1 on EOF, or -2 if the previous return value had been padded
 * because the file had an odd # bytes.
 */
unsigned int
get_limited_16 (f_in, limit)
FILE *f_in;
unsigned int limit;
{
    static int have_extra;
    static unsigned int extra;
    static int oddflag;
    static unsigned int magic = IMAGIC;
    unsigned int c1, c2;
    unsigned int d;

    /* First check for leftover from last time */
    if (have_extra) {
	have_extra = 0;
	return extra;
    }

    /* Check if last return included a pad */
    if (oddflag)
	return -2;

    /* Read data (bigendian), do the magic */
    c1 = fgetc(f_in);
    if (c1==EOF)
	return -1;
    c2 = fgetc(f_in);
    if (c2==EOF) {
	c2 = crandom(0x100);
	oddflag = 1;
    }
    d = ((c1&0xff) << 8) + (c2&0xff);
    d ^= magic;
    magic = (magic + DMAGIC) & 0xffff;

    /* If over the limit, return limit-1 as a code for that, and remember
     * to return the rest next time.
     */
    if (d >= limit-1) {
	have_extra = 1;
	extra = d - (limit-1);
	d = limit-1;
    }
    return d;
}


/* Given a 16-bit value d, less than mod, split it into nout files such
 * that any k of them can reconstruct it.
 */
void
split_out (d, f_out, nout, k, mod)
unsigned int d;
FILE *f_out[];
int nout;
int k;
unsigned int mod;
{
    unsigned int poly[KMAX];
    int i, j;
    unsigned int di;

    poly[0] = d;
    for (j=1; j<k; ++j) {
	poly[j] = crandom(mod);
    }
    for (i=0; i<nout; ++i) {
	di = eval(poly, k, i+1, mod);
	fputc ((di>>8)&0xff, f_out[i]);
	fputc (di&0xff, f_out[i]);
    }
}


/* Split the specified input file into nout output files, such that
 * any k of them are sufficient to reconstruct the input.  mod is the
 * largest prime < 2^16.  This is the main routine for the splitting case.
 */
void
split (f_in, f_out, nout, k, mod)
FILE *f_in;			/* Input file handle */
FILE *f_out[];			/* Output file handles */
int nout;			/* Number of output files */
int k;				/* Threshhold for re-assembly */
unsigned int mod;		/* Modulus for calculations */
{
    int i;
    unsigned int d;

    /* Prefix each file with "x" coordinate, 1 byte */
    for (i=0; i<nout; ++i) {
        fputc (i+1, f_out[i]);
    }
    for ( ; ; ) {
	d = get_limited_16 (f_in, PRIME);
	if (d==-1)
	    break;
	if (d==-2) {
	    /* Odd flag - pad output files with a random byte to remember */
	    for (i=0; i<nout; ++i)
		fputc(crandom(0x100), f_out[i]);
	    break;
	}
	split_out (d, f_out, nout, k, mod);
    }
}




/******************* Code related to assembly *********************/


/* Return the multiplicative inverse of small positive or negative value
   x modulo the current prime.  Do a table lookup for speed. */
unsigned int
inverse (x, mod)
int x;				/* Small value to find inverse of */
unsigned int mod;		/* Argument is ignored */
{
    int neg = 0;

    if (x < 0) {
	x = -x;
	neg = 1;
    }
    if (x < 1 || x > (sizeof(invtab)/sizeof(invtab[0]))) {
	fprintf (stderr, "inverse out of range: %d\n", x);
	exit (1);
    }
    if (neg)
	return PRIME - invtab[x-1];
    else
	return invtab[x-1];
}


/* Interpolate the polynomial specified at x and y coordinates
 * in the array of size n, at x=i.  Do it mod the specified modulus.
 * This algorithm is from Knuth, The Art of Computer Programming, Vol. 2,
 * Seminumerical Algorithms, section 4.6.4, Evaluation of Polynomials,
 * equation 43 and 44, page 485 (bottom) in 1981 hardcover edition.
 * Knuth has his indices go from 0 to n; mine go from 0 to n-1, a slight
 * notational change.
 */
unsigned int
interp (i, x, y, n, mod)
int i;				/* x coord of interpolated point */
int x[];			/* x coordinates of known points */
unsigned int y[];		/* y coordinates of known points */
int n;				/* size of x, y, and alpha arrays */
unsigned int mod;		/* modulus for reducing results */
{
    uint32 alpha[KMAX];
    int j, k;
    uint32 prod;

    for (j=0; j<n; ++j) {
	alpha[j] = y[j];
#ifdef DEBUG
printf ("Interp: alpha[%d] = %x\n", j, alpha[j]);
#endif
    }
    for (k=1; k<n; ++k) {
	for (j=n-1; j>=k; --j) {
	    if (alpha[j] > alpha[j-1])
		alpha[j] = alpha[j] - alpha[j-1];
	    else
		alpha[j] = alpha[j] - alpha[j-1] + mod;
	    alpha[j] *= inverse (x[j] - x[j-k], mod);
	    alpha[j] = alpha[j] % mod;
	}
    }
#ifdef DEBUG
for (j=0; j<n; ++j) printf ("Interp: alpha[%d] = %x\n", j, alpha[j]);
#endif
    prod = alpha[n-1];
    for (j=n-2; j>=0; --j) {
	if (i < x[j]) {
	    prod *= i-x[j]+mod;
	} else {
	    prod *= i-x[j];
	}
	prod += alpha[j];
	prod %= mod;
    }
#ifdef DEBUG
printf ("Interp: prod = %x\n", prod);
#endif
    return prod;
}


/* Return a 16-bit-value from the file, with a flag set if only the
 * high 8 bits of the reconstructed value will be valid.  This is known
 * because odd-size files are padded with an extra byte.  We have to stay
 * two bytes ahead to know this.
 */
unsigned int
get_assemble_16 (f_in, i, podd)
FILE *f_in[];
int i;
int *podd;
{
    static int notfirst[KMAX];
    static unsigned int next_d1[KMAX];
    unsigned int d1;
    unsigned int c1, c2;

    if (!notfirst[i]) {
	/* Get ahead the first time */
	c1 = fgetc(f_in[i]);
	c2 = fgetc(f_in[i]);
	next_d1[i] = ((c1&0xff) << 8) + (c2&0xff);
	notfirst[i] = 1;
    }
	
    d1 = next_d1[i];
    c1 = fgetc(f_in[i]);
    if (c1 == EOF) {
	next_d1[i] = -1;
    } else {
	c2 = fgetc(f_in[i]);
	if (c2 == EOF) {
	    *podd = 1;
	    next_d1[i] = -1;
	} else {
	    next_d1[i] = ((c1&0xff) << 8) + (c2&0xff);
	}
    }
    return d1;
}
    
    
/* Get 16-bit values from each file, and interpolate them to get the value
 * at x=0.  That is how we do the assembly.  Set the podd flag if
 * only the high 8 bits of this interpolated value are valid.
 */
unsigned int
get_assemble (f_in, nin, x, f_out, mod, podd)
FILE *f_in[];
int nin;
int x[];
FILE *f_out;
unsigned int mod;
int *podd;
{
    unsigned int y[KMAX];
    int i;

    for (i=0; i<nin; ++i) {
	y[i] = get_assemble_16 (f_in, i, podd);
	if (y[i] == -1)		/* EOF */
	    return -1;
    }
    return interp (0, x, y, nin, mod);
}

/* Given a set of nin file descriptors, assemble them to generate the
 * original file.  This is the main routine for the assembly case.
 */
void
assemble (f_in, names, nin, f_out, mod)
FILE *f_in[];
char *names[];
int nin;
FILE *f_out;
unsigned int mod;
{
    unsigned int magic = IMAGIC;
    int i;
    int x[KMAX];
    int oddflag = 0;
    unsigned int c1, c2;
    unsigned int d;

    /* Read x index number from each file, one byte per */
    for (i=0; i<nin; ++i) {
        x[i] = fgetc(f_in[i]);
        if (x[i] > NMAX) {
            fprintf (stderr, "File %s does not appear to be valid\n", names[i]);
            exit (1);
        }
    }

    for ( ; ; ) {
    	d = get_assemble (f_in, nin, x, f_out, mod, &oddflag);
    	if (d == -1)
    	    break;
    	if (d == mod-1) {
    	    d = get_assemble (f_in, nin, x, f_out, mod, &oddflag);
    	    d += mod-1;
    	}
    	d ^= magic;
    	magic = (magic + DMAGIC) & 0xffff;
    	c1 = (d>>8) & 0xff;
    	c2 = d & 0xff;
    	fputc (c1, f_out);
	if (oddflag)
	    break;
	fputc (c2, f_out);
    }
}


/********************************* MAIN *********************************/

char *pname;

main (argc, argv)
int argc;
char **argv;
{
    int splitmode;
    int n, k;
    static FILE *f_in[NMAX];
    static FILE *f_out[NMAX];
    static char *names[NMAX];
    static char fname[1024];
    char *fnp;
    int fnamelen;
    int i, j;
    void usage();

    pname = argv[0];
    if (argc < 3)
    	usage();
    if ((n = atoi(argv[1])) <= 1 || n > NMAX)
        usage();
    if ((k = atoi(argv[2])) == 0)  {
        k = n;
        splitmode = 0;
    } else if (k <= 1  ||  k > KMAX) {
        usage;
    } else {
        if (argc != 4)
            usage;
        splitmode = 1;
        if (k > n) {
            int t = k; k = n; n = t;
        }
    }
    if (splitmode) {
        if (!(f_in[0] = fopen (argv[3], RB))) {
            fprintf (stderr, "Unable to open file %s\n", argv[3]);
            exit (1);
        }
        /* Strip off extension */
        strcpy (fname, argv[3]);
        fnamelen = strlen(fname);
        for (fnp = fname + fnamelen; *--fnp!='.' && fnp>fname; )
            ;
        if (fnp != fname) {
            *fnp = '\0';
            fnamelen = fnp - fname;
        }
        /* Open output files */
        for (i=0; i<n; ++i) {
            names[i] = (char *)malloc (fnamelen+5);
            sprintf (names[i], "%s.%03d", fname, i+1);
            if (!(f_out[i] = fopen(names[i], WB))) {
            	fprintf (stderr, "Unable to create file %s\n", names[i]);
            	exit (1);
            }
        }
        printf ("Splitting file %s to:\n", argv[3]);
        for (i=0; i<n; ++i) {
	    printf ("%s%s", names[i], i==n-1?"\n":" ");
        }
    	/* Initialize RNG based on contents of input file */
	initcrandom(f_in[0]);
	/* Do the work */
	split (f_in[0], f_out, n, k, PRIME);
	/* Clean up and exit */
	for (i=0; i<n; ++i)
	    fclose (f_out[i]);
	fclose (f_in[0]);
	exit (0);
    } else {
        if (argc == 3) {
            /* Manual globbing.  Strip off '.*' */
            strcpy (fname, argv[2]);
            fnp = fname + strlen(fname);
            if (*--fnp != '*' || *--fnp != '.')
                usage();
            *fnp = '\0';
            fnamelen = fnp - fname;
            /* Search for and open input files */
            names[0] = (char *) malloc(fnamelen+5);
            for (i=0,n=0; i<=NMAX && n<k; ++i) {
                sprintf (names[n], "%s.%03d", fname, i);
            	if (f_in[n] = fopen(names[n], RB)) {
            	    names[++n] = (char *) malloc(fnamelen+5);
            	}
            }
            if (n < 2) {
                fprintf (stderr, "Unable to open files matching %s\n",argv[2]);
                exit (1);
            }
	    if (n < k) {
		fprintf (stderr, "Unable to find sufficient files\n");
		exit (1);
	    }
        } else {
            /* filename list */
	    if (argc-2 < k) {
		fprintf (stderr, "Insufficient files specified\n");
		exit (1);
	    }
            /* Open input files */
            for (i=0; i<k; ++i) {
                names[i] = argv[i+2];
                if (!(f_in[i] = fopen(names[i], RB))) {
                    fprintf (stderr, "Unable to open file %s\n", names[i]);
                    exit (1);
                }
            }
	    /* Strip extension off 1st input file */
	    strcpy (fname, argv[2]);
	    fnamelen = strlen(fname);
	    for (fnp = fname + fnamelen; *--fnp!='.' && fnp>fname; )
		;
	    if (fnp != fname) {
		*fnp = '\0';
		fnamelen = fnp - fname;
	    }
	}
	/* Two assembly cases (fname-list and glob) come together here */
	/* Add .out and open output files */
	strcat (fname, ".out");
	if (!(f_out[0] = fopen (fname, WB))) {
	    fprintf (stderr, "Unable to create output file %s\n", fname);
	    exit (1);
	}
	printf ("Creating file %s from files:\n", fname);
	for (i=0; i<k; ++i) {
	    printf ("%s%s", names[i], i==k-1?"\n":" ");
	}
	/* Do the work */
	assemble (f_in, names, k, f_out[0], PRIME);
	/* Clean up and exit */
	fclose (f_out[0]);
	for (i=0; i<n; ++i)
	    fclose (f_in[i]);
	exit(0);
    }
}
            
void
usage()
{
    fprintf (stderr, "Usage: %s <n-pieces> <n-needed> file\n", pname);
    fprintf (stderr, "   (splits to file.001, file.002, ...)\n");
    fprintf (stderr, "or %s <n-files> file.*\n", pname);
    fprintf (stderr, "or %s <n-files> file file2 [...]\n", pname);
    fprintf (stderr, "   (These last two re-assemble the pieces to file.out)\n");
    exit (1);
}
