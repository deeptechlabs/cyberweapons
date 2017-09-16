/* File: splay.c
   Author: Jeffrey Chilton, PO Box 807, West Branch, IA 52358.
   Author: Douglas Jones, Dept. of Comp. Sci., U. of Iowa, Iowa City, IA 52242.
   Date: Feb. 14, 1990
	 (minor revision of Feb. 20, 1989 to add exit(0) at end of program).
	 (minor revision of Nov. 14, 1988 to fix portability problems).
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
   Purpose: Data compression and encryption program
   Algorithm: Uses a splay-tree based prefix code, with one splay tree per
			state in a Markov model.  The nature of the Markov
			model is determined by the splay procedure in the
			include file splay.i.
*/

#include <stdio.h>
#include <strings.h>
#include <time.h>
#include "splay.i"

/* begin TRANSMIT macro */
#define MAXBITCOUNTER 8
short int bitbuffer = 0;
short int bitcounter = 0;
#define TRANSMIT(b) {						\
	bitbuffer = (bitbuffer << 1) + (b);			\
	if ((++bitcounter) == MAXBITCOUNTER) {			\
		putc(bitbuffer, out);				\
		bitcounter = bitbuffer = 0;			\
	}							\
}
/* end TRANSMIT macro */

short int stack[SUCCMAX]; /* used by compress, statically allocated for speed */

/* begin COMPRESS macro */
/* COMPRESS macro is used where speed is essential, and if your compiler */
/* can't handle the macro, or if you are out of memory, use the function */
/* compress and delete the macro */
#define COMPRESS(plain) {					\
	short int *U, *R;					\
	short int sp = 0;					\
	short int a = (plain) + SUCCMAX;			\
	R = &right[state * SUCCMAX];				\
	U = &up[state * SUCCTWICE];				\
	do { 		/* walk up the tree pushing bits */	\
		stack[sp] = R[U[a]] == a;			\
		++sp;						\
		a = U[a];					\
 	} while (a != ROOT);					\
	do {							\
		TRANSMIT(stack[(--sp)]);			\
	} while (sp != 0);					\
	SPLAY((short int)(plain));				\
}
/* end COMPRESS macro */

/* begin compress function */
compress(plain)
short int plain;
{
	COMPRESS(plain);
}
/* end compress function */

/* begin openfiles function */
openfiles()
{
	if (filename == NULL) {
		in = stdin;
		out = stdout;
		cflag = 1;
		compflag = 1;
		rmfileflag = 0;
	} else {
		if ((in = fopen(filename, "r")) == NULL) cannot_open(filename);
		if (cflag == 0) {
			strncpy(filenmod, filename, 117);
			strncat(filenmod, ".S", 3);
			if ((out = fopen(filenmod, "a")) == NULL) {
				cannot_open(filenmod);
			}
			if ((forceflag == 0) && (ftell(out) != 0)) overwrite();
		} else out = stdout;
	}
}
/* end openfiles function */

/* THE MAIN PROGRAM */
main(argc, argv)
int argc;
char *argv[];
{
	int plain;
	long int oldlen, newlen;

	linearg(argc, argv);

	if (states == 0) {
		states = nokeydefault;
		initsplay();
	}

	putc(MAGIC1, out);
	putc(MAGIC2, out);
	if (states == 256) {
		putc(NULL, out);
	} else {
		putc((char)states, out);
	}

	/* begin transmit garbage prefix */
	if (cryptflag == 1) {
		long int pid, t, k;
		pid = getpid();
		t = time(NULL);
		k = (pid & 0x00007fffL) * (t & 0x00007fffL);
		compress((short)k & 0xff);
		compress((short)(k >> 8) & 0xff);
		compress((short)(k >> 16) & 0xff);
		compress((short)(k >> 24) & 0xff);
	}
	/* end transmit garbage prefix */

	/* begin compress input */
	for (;;) {
		if (((plain = getc(in)) == EOF) && feof(in)) break;
		COMPRESS ((short int)(plain & 0xff));
	}
	compress(MAXCHAR);
	/* end compress input */

	/* begin flushtransmit routine */
	while (bitcounter != 0) {
		TRANSMIT(0);
	}
	/* end flushtransmit routine */

	/* begin calculate compression */
	oldlen = ftell(in);
	newlen = ftell(out);
	if (vflag == 1) {
		int bytes = 2 * (states * SUCCMAX * sizeof(short)) + (states *
			SUCCTWICE * sizeof(short));
		float comp = 100.0 * (1.0 - ((float)newlen / (float)oldlen));
		fprintf(stderr, "%s: Compression: %2.1f%% ", filename, comp);
		if (rmfileflag == 1) {
			fprintf(stderr, "-- replaced with %s\n", filenmod);
		} else fprintf(stderr, "\n");
		fprintf(stderr, "Data structure used %d bytes\n", bytes);
	}
	/* end calculate compression */

	if ((newlen > oldlen) && (compflag == 0)) {
		unlink(filenmod);
		already_compressed();
	}
	if ((filename != NULL) && (rmfileflag == 1)) unlink(filename);
	exit(0);
}
