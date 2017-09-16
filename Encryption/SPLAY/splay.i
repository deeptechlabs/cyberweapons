/* File: splay.i
   Author: Jeffrey Chilton, PO Box 807, West Branch, IA 52358.
   Author: Douglas Jones, Dept. of Comp. Sci., U. of Iowa, Iowa City, IA 52242.
   Date: Dec. 11, 1989.
         (very minor revision of Feb. 20, 1989 to eliminate %i in sscanf).
	 (minor revision of Nov. 14, 1988 to remove dead code).
	 (minor revision of Aug. 8, 1988 to correct declaration of filenmod).
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
   Purpose: Include file for splay-tree based compression and encryption.
   Algorithm: Procedures for command-line parsing and splay-tree maintenance.
*/

#define MAGIC1 0x93	/* ^S with the high bit set */
#define MAGIC2 0x10	/* ^P */
#define MAXCHAR	256	/* maximum source character code */
#define SUCCMAX	257	/* MAXCHAR + 1 */
#define TWICEMAX 513	/* 2 * MAXCHAR + 1 */
#define SUCCTWICE 514	/* TWICEMAX + 1 */
#define ROOT	1
#define nokeydefault 32	/* default number of states for no keys */
#define keydefault 1	/* default number of states for key */
short int *left;
short int *right;
short int *up;

/* begin SPLAY macro called from loops */
#define SPLAY(plain) {							\
	register short int *L, *R, *U, a, b, c, d;			\
	L = &left[state * SUCCMAX];					\
	R = &right[state * SUCCMAX];					\
	U = &up[state * SUCCTWICE];					\
	a = (plain) + SUCCMAX;						\
									\
	do { 	/* walk up the tree semi-rotating pairs of nodes */	\
		if ((c = U[a]) != ROOT) { 	/* a pair remains */	\
			d = U[c];					\
			b = L[d];					\
			if (c == b) {					\
				b = R[d];				\
				R[d] = a;				\
			} else {					\
				L[d] = a;				\
			}						\
			if (L[c] == a) {				\
				L[c] = b;				\
			} else { 					\
				R[c] = b;				\
			}						\
			U[a] = d;					\
			U[b] = c;					\
			a = d;						\
		} else { 						\
			a = c;						\
		}							\
	} while (a != ROOT);						\
	state = (plain) % states;					\
}
/* end SPLAY macro */

/* the following flags do not correspond directly to the command line args */
/* the documented meanings correspond to the default initial values */
int cryptflag = 0;	/* don't encrypt; set by -p, -k */
int compflag = 0;	/* if output bigger delete it; set by -c, -f, -p, -k */
int rmfileflag = 1;	/* remove input when done; unset by -n, -c */
int vflag = 0;		/* don't show statistics; set by -v */
int forceflag = 0;	/* don't ignore overwrite; set by -f */
int cflag = 0;		/* output to stdout; set by -c */

/* the following variables determine the operation of the Markov model */
int states = 0;		/* number of states = 0; default indicates unknown */
int state = 0;		/* current splay tree; initial state is always 0 */

/* files */
char *filename = NULL;	/* textual name of the input file; NULL = unknown */
char filenmod[120];	/* textual name of the output file */
char *pgmname;		/* name of program for error messages */
FILE *in, *out;		/* files used for compression or uncompression */

/* begin line argument check function */
linearg(argc, argv)
int argc;
char *argv[];
{
	int i;
	pgmname = argv[0];

	for (i =1; i < argc; i++) {
		if (argv[i][0] == '-') { /* a flag */
			if (argv[i][1] == 'p') {
				char *p;
				if (argv[i][2] != NULL) {
					p = &argv[i][2];
				} else if ((i + 1) < argc) {
					p = &argv[i + 1][0];
					i++;
				} else {
					syntax("-p");
				}
				if (in == NULL) {
					openfiles();
				}
				if (states == 0) {
					states = keydefault;
					initsplay();
				}
				while (*p != NULL) {
					splay((short int)(*(p++)));
				}
				compflag = 1;
				cryptflag = 1;
			} else if (argv[i][1] == 'k') {
				char *p;
				FILE *f;
				char c;
				if (argv[i][2] != 0) {
					p = &argv[i][2];
				} else if ((i + 1) < argc) {
					p = &argv[i + 1][0];
					i++;
				} else {
					syntax("-k");
				}
				f = fopen(p, "r");
				if (f == NULL) {
					cannot_open(p);
				}
				if (in == NULL) {
					openfiles();
				}
				if (states == 0) {
					states = keydefault;
					initsplay();
				}
				for (;;) {
					if (((c = getc(f)) == EOF)
							&& feof(f)) break;
					SPLAY((short int)(c & 0xff));
				}
				compflag = 1;
				cryptflag = 1;
			} else if (argv[i][1] == 'n') {
				rmfileflag = 0;
			} else if (argv[i][1] == 'v') {
				vflag = 1;
			} else if (argv[i][1] == 'f') {
				forceflag = 1;
				compflag = 1;
			} else if (argv[i][1] == 'c') {
				if (in != NULL) {
					syntax("-c");
				}
				cflag = 1;
				compflag = 1;
				rmfileflag = 0;
			} else if (argv[i][1] == 's') {
				char *p;
				int s;
				if (argv[i][2] != NULL) {
					p = &argv[i][2];
				} else if ((i + 1) < argc) {
					p = &argv[++i][0];
				} else syntax(argv[i]);
				if (sscanf(p, "%d\0", &s)
						== EOF) {
					syntax(argv[i]);
				}
				if (s < 1 || s > 256) {
					out_of_bounds(s);
				}
				if ((states != s) && (states != 0)) {
					toomanyargs();
				}
				if (states == 0) {
					states = s;
					initsplay();
				}
			} else {
				syntax(argv[i]);
			}
		} else { /* no - at front of argument */
			filename = &argv[i][0];
			if (in != NULL) {
				toomanyargs();
			}
			openfiles();
		} /* end if */
	} /* end for loop */
	if (in == NULL) {
		openfiles();
	} /* end if */
} /* end linearg */

/* begin build initial splay tree */
initsplay ()
{
	short int *L;
	short int *R;
	short int *U;

	left = (short *) malloc(states * SUCCMAX * sizeof(short));
	right = (short *) malloc(states * SUCCMAX * sizeof(short));
	up = (short *) malloc(states * SUCCTWICE * sizeof(short));
	for (state = 0; state < states; ++state) {
		short int i, j;
		L = &left[state * SUCCMAX];
		R = &right[state * SUCCMAX];
		U = &up[state * SUCCTWICE];
		for (i = 2; i <= TWICEMAX; ++i)	{
			U[i] = i/2;
		}
		for (j = 1; j <= MAXCHAR; ++j)	{
			L[j] = 2 * j;
			R[j] = 2 * j + 1;
		}
	}
	state = 0;
}
/* end build initial splay tree */

/* begin splay function */
splay(plain)
short int plain;
{
	SPLAY(plain);
}
/* end splay function */

/* begin overwrite permission */
overwrite()
{
	fprintf(stderr, "%s already exists;", filenmod);
	fprintf(stderr, " do you wish to overwrite (y or n)? ");
	for (;;) {
		char c[20];
		int i;
		if (fgets(c, 20, stdin) == NULL) {
			exit(-1);
		}
		i = strspn(c, " ");
		if ((c[i] == 'n') && (c[i + 1] == '\n')) {
			exit(0);
		} else if ((c[i] == 'y') && (c[i + 1] == '\n')) {
			freopen(filenmod, "w", out);
			break;
		} else {
			fprintf(stderr, "Please enter y or n! ");
		}
	}
}
/* end overwrite permission */

/* begin error messages */
cannot_open(name)
char *name;
{
	fprintf(stderr, "Error: %s can't open %s\n", pgmname, name);
	exit(-1);
}

not_splayed()
{
	fprintf(stderr, "Error: %s is not in splayed format\n", filename);
	exit(-1);
}

syntax(c)
char *c;
{
	fprintf(stderr, "Error: bad %s argument\nUsage: %s [input file] ",
		c, pgmname);
	fprintf(stderr, "[-s states] [-c] [-f] [-n] [-v] [-k keyfile] [-p ");
	fprintf(stderr, "password]\n");
	exit(-1);
}

bad_data()
{
	fprintf(stderr, "Error: corrupt input in %s\n", filename);
	exit(-1);
}

no_S()
{
	fprintf(stderr, "Error: cannot %s %s: .S suffix expected\n", pgmname,
		filename);
	exit(-1);
}

already_compressed()
{
	fprintf(stderr, "Error: %s could not be compressed\n",filename);
	exit(-1);
}

toomanyargs()
{
	fprintf(stderr, "Error: too many arguments\n");
	exit(-1);
}

out_of_bounds(s)
int s;
{
	fprintf(stderr, "Error: -s %d not in bounds of 1 to 256\n", s);
	exit(-1);
}
/* end error messages */
