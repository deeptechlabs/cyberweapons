/*
 * Test driver for BIGRAM character guessing stuff.
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"


#define NDOBLOCKS	2		/* Number of blocks to do. */
#define	DEBUG		FALSE

ecinfo	myecinfo;

char	plainbuf[BLOCKSIZE+1];
float	accept_level;
float	prob_cutoff;

extern	ec_best(), ec_dplain(), ec_dscipher();
extern	ec_dnext(), ec_dsizetab(), ec_dperm(), ec_dpmap();
extern	ec_init(), ec_best(), ec_cscore();
extern	lp_init(), lp_best_char(), lp_cscore(), lp_accept(), lp_best_pos();
extern	lp_dclasses();

extern	char	mcbuf[];
extern	char	*fname;			/* Used by fillcbuf. */
/* Test routine for equiv class info. */
main(argc, argv)
int		argc;
char	*argv[];
{
	ecinfo	*eci;
	FILE	*inp;
	FILE	*sout, *sin;
	int		i, blknum;
	int		maxblock;
	long	filelength;
	char	infile[100];
	char	inplain[100];
	char	*plain = ".txt";
	char	*code = ".cipher";
	char	*p, *q;

	sout = stdout;		/* For use within debugger, dbx. */
	sin = stdin;

	if (argc != 4)  {
		printf("Usage: %s input_file_root acceptance_level prob_cutoff\n",
				argv[0]);
		exit(0);
		}

	p = inplain;
	q = argv[1];
	while (*p++ = *q++);
	--p;
	q = plain;
	while (*p++ = *q++);

	p = infile;
	q = argv[1];
	while (*p++ = *q++);
	--p;
	q = code;
	while (*p++ = *q++);

	if (sscanf(argv[2], "%f", &accept_level) != 1)  {
		printf("Could not parse the acceptance level from %s.\n", argv[2]);
		exit(0);
		}

	if (sscanf(argv[3], "%f", &prob_cutoff) != 1)  {
		printf("Could not parse the probability cutoff from %s.\n", argv[2]);
		exit(0);
		}

	printf("\t\tEquivalence Class Guessing\n\n");
	printf("Filename = %s.  Acceptance level = %4.2f\n",infile,accept_level);

	printf("Loading statistics ...");
	printf(" 1");
	load_1stats_from("mss.stats");
	printf(" 2");
	load_2stats_from("mss-bigram.stats");
	printf(" done.\n");

	eci = &myecinfo;

	if ((inp = fopen(infile, "r")) == NULL) {
		printf("\nCannot open %s for reading.\n", infile);
		exit(0);
		}
	fseek(inp, 0L, 2);
	filelength = ftell(inp);
	fclose(inp);

	maxblock = filelength / BLOCKSIZE;
	if (maxblock > (NDOBLOCKS-1))  maxblock = (NDOBLOCKS-1);

	for (blknum = 0 ; blknum <= maxblock ; blknum++) {
		do_lp_block(eci, blknum, infile, inplain);
		}
}


/* Do a block using the letter pair statistics.
 */
do_lp_block(eci, blknum, cfile, plainfile)
reg		ecinfo	*eci;
int		blknum;
char	*cfile, *plainfile;
{
	int		i;
reg	int		c;
	int		ntried;
	int		naccepted, nwrong;
reg	int		classpos;
	int		charcount;
	int		*permp, repeat;

	cipherfile = cfile;
	fillcbuf(blknum, mcbuf);
	cipherfile = plainfile;
	fillcbuf(blknum, plainbuf);

	lp_init(mcbuf, refperm(blknum), eci);

for(repeat = 0 ; repeat < 3 ; repeat++)  {
	naccepted = 0;
	nwrong = 0;
	ntried = 0;

	for (ntried = 0 ; ntried < BLOCKSIZE ; ntried++)  {
		classpos = lp_best_pos(eci, 2);
		if (classpos == NONE)
			break;
		c = lp_best_char(eci, classpos,
						accept_level - ((repeat == 0) ? 0.0 : 0.0),
						prob_cutoff);
		if (c != NONE) {
			lp_accept(eci, classpos, c);
			naccepted++;
#if DEBUG
			printf("ACCEPTED");
#endif
			if (plainbuf[classpos] != c)  {
				nwrong++;
#if DEBUG
				printf(" -- INCORRECT");
#endif
				}
#if DEBUG
			printf("\n");
#endif
			}
		}

/*	decode(eci->ciphertext, eci->plaintext, eci->perm);
*/

	for (i = 0 ; i < eci->nclasses ; i++)  {
		eci->classlist[i].changed = TRUE;
		}


	charcount = 0;
 	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (eci->plaintext[i] != NONE)  charcount++;
		}

	printf("\n\nPlaintext for block %d using %d wires", blknum, naccepted);
	printf(" (%d wrong)", nwrong);
	printf(" yields %d characters.", charcount);
	printf("\nThere were %d classes and %d guess tries.",eci->nclasses,ntried);
	printf("\n\n");
	ec_dplain(stdout, eci);
	}

	permp = refperm(blknum);
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		permp[i] = eci->perm[i];
		}
}


key	u_getkey()
{
}

keyer	topktab[] ={{0, NULL}};


char	*quitcmd()
{
}
