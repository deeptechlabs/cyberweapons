/*
 * Test driver for automated trigram guessing.
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"
#include	"cipher.h"
#include	"autotri.h"


extern	char	*atr_best();
extern			atr_autoguess();
extern	float	atr_score();
extern	int		accept_permvec();

atrinfo	myatrinfo;
char	plainbuf[BLOCKSIZE+1];
int		naccepted, nwrong, nright;		/* Number of wires accepted / wrong. */

extern	char	mcbuf[];

/* Test routine for automated trigram guessing. */
main(argc, argv)
int		argc;
char	*argv[];
{
	FILE	*inp;
	int		i, blknum;
	int		nblocks;
	int		*saveperm;
	long	filelength;
	atrinfo	*atri;
	char	permfbuf[100];
	char	cipherfbuf[100];
	char	plainfbuf[100];
	char	*perm = ".perm";
	char	*plain = ".txt";
	char	*code = ".cipher";
	char	*p, *q;

	if (argc != 5)  {
		printf("Usage: %s input_file_root", argv[0]);
		printf(" min_score min_total_chars min_per_wire_chars\n");
		exit(0);
		}

	p = cipherfile = cipherfbuf;
	q = argv[1];
	while (*p++ = *q++);
	--p;
	q = code;
	while (*p++ = *q++);

	p = plainfbuf;
	q = argv[1];
	while (*p++ = *q++);
	--p;
	q = plain;
	while (*p++ = *q++);

	p = permfile = permfbuf;
	q = argv[1];
	while (*p++ = *q++);
	--p;
	q = perm;
	while (*p++ = *q++);

	atri = &myatrinfo;

	if (sscanf(argv[2], "%f", &atri->max_score) != 1)  {
		printf("Could not parse the max score from %s.\n", argv[2]);
		exit(0);
		}

	if (sscanf(argv[3], "%d", &atri->min_total_chars) != 1)  {
		printf("Could not parse the min chars from %s.\n", argv[2]);
		exit(0);
		}

	if (sscanf(argv[4], "%d", &atri->min_wire_chars) != 1)  {
		printf("Could not parse the min chars from %s.\n", argv[2]);
		exit(0);
		}

	permchgflg = FALSE;

	letterstats = "mss.stats";
	trigramstats = "trigrams.stats";
	load_1stats_from(letterstats);
	load_tri_from(trigramstats);

	if ((inp = fopen(cipherfile, "r")) == NULL) {
		printf("\nCannot open %s for reading.\n", cipherfile);
		exit(0);
		}
	fseek(inp, 0L, 2);
	filelength = ftell(inp);
	fclose(inp);

	nblocks = filelength / BLOCKSIZE;
	if (nblocks > NPERMS)  nblocks = NPERMS;

	printf("\t\tAutomated Trigram Guessing");
	printf(" for %s\n\n",cipherfile);
	printf("Max score = %4.2f", atri->max_score);
	printf(".  Min total chars = %d", atri->min_total_chars);
	printf(".  Min per wire chars = %d", atri->min_wire_chars);
	printf("\n\n");
	for (blknum = 0 ; blknum < nblocks ; blknum++) {
		do_block(blknum, cipherfile, plainfbuf, atri);
		saveperm = refperm(blknum);
		for (i = 0 ; i < BLOCKSIZE ; i++)
			saveperm[i] = atri->eci->perm[i];
		}

	permsave();
}


do_block(blknum, cfile, pfile, atri)
int		blknum;
char	*cfile, *pfile;
atrinfo	*atri;
{
	int		i,c,x,y;
	int		j;
	int		pos;
	char	*trigram;
	int		charcount;				/* Number of characters deduced. */
	float	score;
	int		*dbsperm;
	perment	permvector[PERMSZ];
	int		pvec[BLOCKSIZE+1];
	char	str[BLOCKSIZE+1];

	cipherfile = pfile;
	fillcbuf(blknum, plainbuf);
	cipherfile = cfile;
	fillcbuf(blknum, mcbuf);

	dbsperm = refperm(blknum);
	atr_init(mcbuf, dbsperm, atri);

	ec_autoguess(atri->eci, 1.7);
/*	decode(atri->eci->ciphertext, atri->eci->plaintext, atri->eci->perm);

	naccepted = 0;
	nwrong = 0;
	nright = 0;
	charcount = 0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (atri->eci->plaintext[i] != NONE)  charcount++;
		if (((y=atri->eci->perm[i]) != NONE) && (i < y))  naccepted++;
		}

	printf("\n\nEquiv Guessing for block %d yields %d wires",blknum,naccepted);
	printf(" and %d characters.\n\n", charcount);
	ec_dplain(stdout, atri->eci);
*/

	naccepted = 0;
	nwrong = 0;
	nright = 0;

	printf("\n\nStarting block %d.\n", blknum);
#if TRUE
	for (pos = 0 ; pos < BLOCKSIZE ; pos++) {
		trigram = atr_best(atri, pos);
		if (trigram != NULL) {
			accept_permvec(atri, atri->best_permvec);
/*			printf("\n");
			printf("Best trigram at %d is '%s'", pos, atri->best_trigram);
			pvec2str(str, atri->best_pvec);
			printf(" which deduced '%s'", str);
			printf(" with a score of %f", atri->best_score);
			printf(".\n");
			printf("There were %d guesses", atri->gcount);
			printf(" yeilding a total score of %f", atri->total_score);
			printf(".\n");
*/
			if (wrong_guess(plainbuf, pos, atri->best_trigram))  {
				nwrong++;
/*				printf("WRONG\n");*/
				}
			else {
				nright++;
/*				printf("CORRECT\n");*/
				}
			}
		}
#else
	atr_autoguess(atri);
#endif

	decode(atri->eci->ciphertext, atri->eci->plaintext, atri->eci->perm);

	charcount = 0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (atri->eci->plaintext[i] != NONE)  charcount++;
		if (((y=atri->eci->perm[i]) != NONE) && (i < y))  naccepted++;
		}

	printf("\n\nPlaintext for block %d using %d wires", blknum, naccepted);
	printf(" yields %d characters.", charcount);
#if TRUE
	printf("\nThere were %d right guesses and %d wrong ones.",nright, nwrong);
#endif
	printf("\n\n");
	ec_dplain(stdout, atri->eci);
}


/* Look for best trigram at given position.
 */
trytri(atri, pos, tindex)
atrinfo	*atri;
int		pos;
int		tindex;
{
	int		i;
	int		j, x, y;
	char	*trigram;
	char	str[BLOCKSIZE+1];

/*
	trigram = atr_best(atri, pos, min_score);

	if (trigram != NULL) {
		printf("Best trigram is %s", atri->best_trigram);
		pvec2str(str, atri->best_pvec);
		printf(" which deduced '%s'", str);
		printf("' with a score of %f", atri->best_score);
		printf(".\n");
		printf("There were %d guesses", atri->gcount);
		printf(" yeilding a total score of %d", atri->total_score);
		printf(".\n");
		}
*/
}


/* Return TRUE if the guess is wrong.
 */
int	wrong_guess(plaintext, position, trigram)
char	*plaintext;
int		position;
char	*trigram;
{
	char	*guess, *reality;

	guess = trigram;
	reality = &plaintext[position];

	while (*guess) {
		if (*guess++ != *reality++)  return(TRUE);
		}

	return(FALSE);
}



key	u_getkey()
{
}

keyer	topktab[] ={{0, NULL}};


char *quitcmd(arg)
char	*arg;
{
	printf("\n");
	exit(1);
}
