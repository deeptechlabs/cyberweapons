/* File: unsplay.c
   Author: Jeffrey Chilton, PO Box 807, West Branch, IA 52358.
   Author: Douglas Jones, Dept. of Comp. Sci., U. of Iowa, Iowa City, IA 52242.
   Date: Feb. 14, 1990.
	 (minor revision of Feb. 20, 1989 to add exit(0) at end of program).
	 (minor revision of Nov. 14, 1988 to detect corrupt input better).
	 (minor revision of Aug. 8, 1988 to eliminate unused vars, fix -c).
   Copyright 1988 by Jeffrey Chilton and Douglas Jones.
	      Copies of this program and associated files may not be sold,
			nor may it (or parts of it) be incorporated into
			products which will be sold, without the express
			prior permission of the authors.
	      Copies of this program, associated files, or parts thereof may
			not be made for use by any national government or
			agency thereof without the express prior permission
			of the authors.
	      Permission is hereby granted to make copies of this program for
			research use (including research in commercial or
			governmental settings) so long as this copyright
			notice is included in the copy and in any derived work.
   Language: C (UNIX)
   Purpose: Data uncompression and decryption program
   Algorithm: Uses a splay-tree based prefix code, with one splay tree per
			state in a Markov model.  The nature of the Markov
			model is determined by the splay procedure in the
			include file splay.i.
*/

#include<stdio.h>
#include<strings.h>
#include"splay.i"

/* begin RECEIVE macro */
#define TOPBITINBUFFER 128
#define MAXBITCOUNTER 8
short int bitbuffer = 0;
short int bitcounter = 0;
#define RECEIVE(bit) {				\
	short int  ch;				\
	if(bitcounter == 0) {			\
		ch = getc(in);			\
		if ((ch == EOF) && feof(in)) {	\
			bad_data();		\
		}				\
		bitbuffer = ch;			\
		bitcounter = MAXBITCOUNTER;	\
	}					\
	--bitcounter;				\
	if ((bitbuffer & TOPBITINBUFFER) != 0) {\
		bit = 1;			\
	} else {				\
		bit = 0;			\
	}					\
	bitbuffer = bitbuffer << 1;		\
}
/* end RECEIVE macro */

short int plain;	/* most recent character uncompressed */

/* begin UNCOMPRESS macro */
/* if your compiler cannot handle macros or you are out of memory, */
/* use the function only and delete the macro */
#define UNCOMPRESS()				\
{						\
	short int *R, *L, bit;			\
	short int a = ROOT;			\
	L = &left[state * SUCCMAX];		\
	R = &right[state * SUCCMAX];		\
						\
	do {  /* once for each bit on path */	\
		RECEIVE(bit);			\
		if (bit == 0) {			\
			a = L[a];		\
		} else {			\
			a = R[a];		\
		}				\
	} while (a <= MAXCHAR);			\
	plain = a - SUCCMAX;			\
	SPLAY(plain);			\
}
/* end uncompress macro */

/* begin uncompress function */
uncompress()
{
	UNCOMPRESS();
}
/* end uncompress function */

/* begin openfiles function */
openfiles()
{
	int s;

	if(filename == NULL) {
		in = stdin;
		out = stdout;
		cflag = 1;
		compflag = 1;
		rmfileflag = 0;
	} else {
		if ((in = fopen(filename, "r")) == NULL) {
			cannot_open(filename);
		}
		if (cflag == 0) {
			char *c;
			strncpy(filenmod, filename, 120);
			c = rindex(filenmod, '.');
			if ((c == NULL) || (c[1] != 'S') || (c[2] != '\000')) {
				no_S();
			}
			c[0] = c[1] = '\000';
			if ((out = fopen(filenmod, "a")) == NULL) {
				cannot_open(filenmod);
			}
			if ((forceflag == 0) && (ftell(out) != 0)) {
				overwrite();
			}
		} else {
			out = stdout;
		}
	}
	if ((getc(in) != MAGIC1) || (getc(in) != MAGIC2)) {
		not_splayed();
	}
	s = getc(in);
	if (s == NULL) {
		s = 256;
	}
	if ((states != s) && (states != 0)) {
		toomanyargs();
	}
	states = s;
	initsplay();
}
/* end openfiles function */

/* THE MAIN PROGRAM */
main(argc, argv)
int argc;
char *argv[];
{
	linearg(argc, argv);

	/* begin remove garbage prefix on encrypted data */
	if (cryptflag == 1) {
		int x;
		for (x = 1; x <= 4; ++x) {
			uncompress();
		}
	}
	/* end remove garbage prefix on encrypted data */

	/* begin uncompress input */
	for (;;) {
		UNCOMPRESS();
		if (plain != MAXCHAR) {
			putc(plain, out);
		} else {
			break;
		}
	}
	/* end uncompress input */

	/* see if file really ended */
	if ((getc(in) != EOF) || !feof(in)) {
		bad_data();
	}

	/* finish the job */
	if (in == stdin) {
		exit(0);
	}
	if (rmfileflag == 1) {
		unlink(filename);
	}
	exit(0);
}
