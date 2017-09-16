/*
 * Equivalence class information about a cipher block.
 *
 * Bob Baldwin, January 1985.
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"
#include	"cipher.h"


#define	DEBUG	FALSE

#define	MIN_SHOW_SCORE	(0.7)
#define	ECBLABEL1	"Equiv class guessing at level %6.3f  -- Please Wait"
#define	ECBLABEL2	"Equiv class guessing at level %6.3f  -- Done"
#define	ECBHELP "F3 enters guess, ^G undoes it."


extern	char	mcbuf[];
extern	ecinfo	gecinfo;
extern	ecbdraw(), ecbfirst(), ecbenter(), ecbundo();

/* Gloabal State. */
float	ec_accept_level = 0.0;
keyer	ecbktab[] = {
		{CACCEPT, ecbenter},
		{CUNDO, ecbundo},
		{CGO_UP, jogup},
		{CGO_DOWN, jogdown},
		{CGO_LEFT, jogleft},
		{CGO_RIGHT, jogright},
		{0, NULL},
};


/* Routine invoked by user to put up the equivalence class
 * guessing window.
 * The window is drawn empty, and then filled in with the guess.
 * Return NULL if command completes ok.
 */
char	*ecbguess(str)
char	*str;			/* Command line */
{
	ecinfo	*ecbi;
	int		i;
	gwindow	*ecb;

	ecb = &gbstore;
	ecbi = &gecinfo;
	ec_init(mcbuf, refperm(dbsgetblk(&dbstore)), ecbi);

	if ((i = sscanf(str, "%*[^:]: %f", &ec_accept_level)) != 1)  {
		return("Could not parse acceptance level.");
		}

	gbsswitch(ecb, ((char *) ecbi), ecbktab, ecbfirst, wl_noop, ecbdraw);

	sprintf(statmsg, ECBLABEL1, ec_accept_level);
	gblset(&gblabel, statmsg);

	ecbdraw(ecb);
	fflush(stdout);

	ec_autoguess(ecbi, ec_accept_level);
	decode(ecbi->ciphertext, ecbi->plaintext, ecbi->perm);

	sprintf(statmsg, ECBLABEL2, ec_accept_level);
	gblset(&gblabel, statmsg);
	ecbdraw(ecb);

	return(NULL);
}


/*  (re) Draw the window.
 */
ecbdraw(ecb)
gwindow	*ecb;
{
	int			i;
	int			row, col;
	ecinfo		*ecbi;

	ecbi = ((ecinfo *) ecb->wprivate);
	row = 1;
	col = 1;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (i%LINELEN == 0) {
			wl_setcur(ecb, gbspos2row(i), gbspos2col(i));
			}
		plnchars(1, char2sym(ecbi->plaintext[i]));
		}

	for (i = gbspos2row(BLOCKSIZE) ; i <= GBHEIGHT ; i++) {
		wl_setcur(ecb, i, 1);
		plnchars(LINELEN, ' ');
		}

	for (i = 1 ; i <= GBHEIGHT ; i++) {
		wl_setcur(ecb, i, LINELEN+1);
		plnchars(ecb->wwidth - LINELEN, ' ');
		}

	wl_setcur(ecb, row, col);
}


/* First time cursor enters window.
 */
ecbfirst(ecb, row, col)
gwindow	*ecb;
int			row, col;
{
	usrhelp(&user, ECBHELP);
	wl_setcur(ecb, row, col);
}


/* Enter the guess into the decryption block.
 */
ecbenter(ecb)
gwindow	*ecb;
{
	ecinfo		*ecbi;

	ecbi = ((ecinfo *) ecb->wprivate);
	dbsmerge(&dbstore, ecbi->perm);
	wl_rcursor(ecb);
}


/* Undo the last guess.
 */
ecbundo(ecb)
gwindow	*ecb;
{
	ecinfo		*ecbi;

	ecbi = ((ecinfo *) ecb->wprivate);
	dbsundo(&dbstore);
	wl_rcursor(ecb);
}




/* Dump plaintext chars onto stream.
 */
ec_dplain(out, eci)
FILE	*out;
ecinfo	*eci;
{
	int		i,c;
	int		*pbuf;

	pbuf = &eci->plaintext[0];
	for (i = 0 ; i < BLOCKSIZE ; i++) {
		c = *pbuf++;
		if (i % 20 == 0)  fprintf(out,"\n");
		if (c != NONE)
			write_char(out, c);
		else
			write_char(out, '.');
		}
	fprintf(out,"\n");
}


/* Dump shifted cipher chars onto stream.
 */
ec_dscipher(out, eci)
FILE	*out;
ecinfo	*eci;
{
	int		i,c;
	int		*pbuf;

	pbuf = &eci->scipher[0];
	for (i = 0 ; i < BLOCKSIZE ; i++) {
		c = *pbuf++;
		if (i++ % 20 == 0)  fprintf(out,"\n");
		if (c != NONE)
			write_char(out, c);
		else
			write_char(out, '.');
		}
	fprintf(out,"\n");
}


/* Dump table of next pointers onto a stream.
 */
ec_dnext(out, eci)
FILE	*out;
ecinfo	*eci;
{
	writeperm(out, &(eci->next[0]));
}


/* Dump size table onto a stream.
 */
ec_dsizetab(out, eci)
FILE	*out;
ecinfo	*eci;
{
	int		i;

	fprintf(out, "\nThere are %d classes longer than 1 character.\n",
			eci->sizelast);
	for (i = 0 ; i < eci->sizelast ; i++)  {
		fprintf(out, "Size: %d,  First member: %d.\n",
				eci->sizelist[i].size, eci->sizelist[i].firstpos);
		}
}


/* Dump our permutation onto a stream.
 */
ec_dperm(out, eci)
FILE	*out;
ecinfo	*eci;
{
	writeperm(out, &(eci->perm[0]));
}


/* Dump the permutation map onto a stream.
 */
ec_dpmap(out, eci)
FILE	*out;
ecinfo	*eci;
{
	writeperm(out, &(eci->permmap[0]));
}



/* Update ecbi to reflect the automatic guesses.
 */
ec_autoguess(ecbi, alevel)
ecinfo	*ecbi;
float	alevel;
{	int		i, c;
	int		classpos;
	int		x, y;

	for (i = 0 ; i < ecbi->sizelast ; i++)  {
		classpos = ecbi->sizelist[i].firstpos;
		c = ec_best(ecbi, classpos, alevel);
		if (c != NONE) {
			x = ecbi->scipher[classpos];
			y = MODMASK & (c + classpos);
			if (!perm_conflict(ecbi->perm, x, y)) {
				ecbi->perm[x] = y;
				ecbi->perm[y] = x;
				}
#if DEBUG
			else {
				printf("ec_autoguess: Best guess conflicts");
				printf(" with an accepted.\n");
				}
#endif
			}
		}
}


/* Score a single equivalence class.
 * Bigger scores are better scores.  They range from 0 to 1.
 * A score of zero means the choice is not possible.
 */
float	ec_cscore(eci, firstpos, plainchar)
ecinfo	*eci;
int		firstpos;
int		plainchar;
{
	extern	float	logvar;
	float	score;
	int		pvec[BLOCKSIZE+1];
	int		ccount;
	char	str[BLOCKSIZE+1];


	if (decode_class(eci, firstpos, plainchar, pvec) == ERROR)  {
		return(0.0);
		}

	score = pvec_1score(pvec);
	if (score < 0.0)  return(0.0);
	score = exp(-(score * score) / 2.0);
	for (ccount = 0 ; pvec[ccount] != NONE ; ccount++);
	score = score / sqrt(2*PI*logvar/ccount);

#if DEBUG
	if (score > MIN_SHOW_SCORE) {
		pvec2str(str, pvec);
		printf("Derived characters are '%s", str);
		printf("', their score is %7.4f\n", score);
		}
#endif
	return(score);
}


/* Select best plaintext value for a ciphertext equiv class.
 * The class is identified by the position in the block of one
 * of the characters in the class.  The plaintext value for
 * an entire class can be specified by the plaintext value of
 * one of its members.  This routine returns the best plaintext
 * value for the ciphertext character at position firstpos.
 * If there is not a clear best value, NONE is returned.
 */
int	ec_best(eci, firstpos, alevel)
ecinfo	*eci;
int		firstpos;
float	alevel;
{
	float	total_score, score;
	float	best_score;
	int		best_char;
	int		c;
	int		x,y;
	float	count;

#if DEBUG
	int		pvec[BLOCKSIZE+1];
	char	str[BLOCKSIZE+1];

	printf("\n");
	printf("The first position of this class is %d.\n", firstpos);
#endif
	total_score = 0.0;
	best_score = 0.0;
	count = 0.0;
	best_char = NONE;

	for (c = 0 ; c <= MAXCHAR  ; c++)  {
		score = ec_cscore(eci, firstpos, c);
		if (score > 0.0)  {
			count += 1.0;
			total_score += score;
			}
		if (score > best_score) {
			best_score = score;
			best_char = c;
			}
		}

#if DEBUG
	printf("Total score is %7.4f", total_score);
	printf(".  Count is %4.0f.\n", count);
#endif
	if (total_score == 0.0  ||  count == 0.0  ||  best_char == NONE) {
#if DEBUG
		printf("NO GUESSES\n");
#endif
		return(NONE);
		}
#if DEBUG
	printf("Best score is %7.4f", best_score);
	printf(", which is %7.4f fraction of total", best_score/total_score);
	printf(".\n");

	decode_class(eci, firstpos, best_char, pvec);
	pvec2str(str, pvec);
	printf("The best chars are '%s.\n", str);
#endif

	if (best_score  >  alevel * (total_score - best_score)) {
		return(best_char);
		}
	else {
		return(NONE);
		}
}


/* Fill in equiv class info from given ciphertext block
 * and permutation.
 */
ec_init(cipher, perm, eci)
char	cipher[];
int		perm[];
ecinfo	*eci;
{
	int		i,j;
	int		lastmember;
	int		firstpos, size;

	eci->sizelast = 0;
	eci->sizemin = 2;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		eci->ciphertext[i] = cipher[i];
		eci->scipher[i] = (cipher[i] + i)&MODMASK;
		eci->perm[i] = perm[i];
		eci->permmap[i] = NONE;
		}
	decode(eci->ciphertext, eci->plaintext, eci->perm);


	/* The permmap points to the most recent member we have seen */
	/* of each known class, or a NONE.  Ptrs are array indexes. */
	for (i = BLOCKSIZE-1 ; i >= 0 ; i--) {
		eci->next[i] = i;
		if ((lastmember = eci->permmap[eci->scipher[i]]) != NONE) {
			eci->next[i] = eci->next[lastmember];
			eci->next[lastmember] = i;
			}
		eci->permmap[eci->scipher[i]] = i;
		}

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		firstpos = eci->permmap[i];
		if (firstpos != NONE)  {
			size = ec_compsize(eci, firstpos);
			ec_addsize(eci, size, firstpos);
			}
		}
}


/* Add an entry to the size list.
 * Implementation:  Find the first slot before sizelast+1 that
 * has a size less than the size arg.  Shuffle down the list
 * to create a hole and insert the new entry.
 */
ec_addsize(eci, size, firstmember)
register	ecinfo	*eci;
int		size;
int		firstmember;
{
	int		k;		/* Slot where new entry will go. */
	int		i;
	ecsize	sizeinfo;

	if (size < eci->sizemin) return;

	sizeinfo.size = size;
	sizeinfo.firstpos = firstmember;
	for (k = 0 ; k < eci->sizelast ; k++)  {
		if (eci->sizelist[k].size < size)  break;
		}
	if (k >= SZMAX) return;

	for (i = eci->sizelast ; i > k ; i--)  {
		eci->sizelist[i] = eci->sizelist[i-1];
		}
	eci->sizelast++;

	eci->sizelist[k] = sizeinfo;
}


/* Compute the size of a clas given a pointer to one of its members.
 */
int	ec_compsize(eci, member)
ecinfo	*eci;
int		member;
{
	int		size;
	int		position;
	int		firstflag;

	size = 0;
	for_pos_in_class(position, member) {
		size++;
		}
	return(size);
}
