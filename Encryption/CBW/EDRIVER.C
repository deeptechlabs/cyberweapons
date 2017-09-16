/*
 * Test driver for equivalence class stuff.
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"


ecinfo	myecinfo;

char	plainbuf[BLOCKSIZE+1];
float	accept_level;

extern	ec_best(), ec_dplain(), ec_dscipher();
extern	ec_dnext(), ec_dsizetab(), ec_dperm(), ec_dpmap();
extern	ec_init(), ec_best(), ec_cscore();

extern	char	mcbuf[];
extern	char	*fname;			/* Used by fillcbuf. */
/* Test routine for equiv class info. */
main(argc, argv)
int		argc;
char	*argv[];
{
	ecinfo	*eci;
	FILE	*inp;
	int		i, blknum;
	int		maxblock;
	long	filelength;
	char	infile[100];
	char	inplain[100];
	char	*plain = ".txt";
	char	*code = ".cipher";
	char	*p, *q;

	if (argc != 3)  {
		printf("Usage: %s input_file_root acceptance_level\n", argv[0]);
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

	load_1stats_from("mss.stats");
	eci = &myecinfo;

	if ((inp = fopen(infile, "r")) == NULL) {
		printf("\nCannot open %s for reading.\n", infile);
		exit(0);
		}
	fseek(inp, 0L, 2);
	filelength = ftell(inp);
	fclose(inp);

	maxblock = filelength / BLOCKSIZE;
	if (maxblock > 19)  maxblock = 19;

	printf("\t\tEquivalence Class Guessing\n\n");
	printf("Filename = %s.  Acceptance level = %4.2f\n",infile,accept_level);
	for (blknum = 0 ; blknum <= maxblock ; blknum++) {
		do_block(eci, blknum, infile, inplain);
		}
}


do_block(eci, blknum, cipherfile, plainfile)
ecinfo	*eci;
int		blknum;
char	*cipherfile, *plainfile;
{
	int		i,c,x,y;
	int		naccepted, nwrong;
	int		classpos;
	int		charcount;

	fname = cipherfile;
	fillcbuf(blknum, mcbuf);
	fname = plainfile;
	fillcbuf(blknum, plainbuf);

	ec_init(mcbuf, refperm(blknum), eci);

	naccepted = 0;
	nwrong = 0;

	for (i = 0 ; i < eci->sizelast ; i++)  {
		classpos = eci->sizelist[i].firstpos;
		c = ec_best(eci, classpos, accept_level);
		if (c != NONE) {
			x = eci->scipher[classpos];
			y = MODMASK & (c + classpos);
			if (eci->perm[x] == NONE  &&  eci->perm[y] == NONE) {
				naccepted++;
				eci->perm[x] = y;
				eci->perm[y] = x;
/*				printf("ACCEPTING best guess of %d wired to %d.\n",
						x, y);
*/				if ((MODMASK & plainbuf[classpos]) != c) {
					nwrong++;
/*					printf("*** WRONG ***  First char should be %c.\n",
							plainbuf[classpos]);
*/					}
				}
			else if (eci->perm[x] == y) {
/*				printf("CONFIRMING guess of %d wired to %d.\n",
						x, y);
*/				}
			else {
/*				printf("CONFLICTING guess of %d wired to %d.\n",
						x, y);
*/				}
			}
		}

	decode(eci->ciphertext, eci->plaintext, eci->perm);

	charcount = 0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (eci->plaintext[i] != NONE)  charcount++;
		}

	printf("\n\nPlaintext for block %d using %d wires", blknum, naccepted);
	printf(" (%d wrong)", nwrong);
	printf(" yields %d characters.\n\n", charcount);
	ec_dplain(stdout, eci);
}

key	u_getkey()
{
}

keyer	topktab[] ={{0, NULL}};
