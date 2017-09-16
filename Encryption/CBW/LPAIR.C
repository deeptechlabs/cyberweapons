/*
 * Letter pair and equivalence class guessing.
 *
 * Bob Baldwin, May 1985.
 */

#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"
#include	"cipher.h"


#define	DEBUG		FALSE
#define	AUTOREPEAT	1	/* Number of times to repeat guess loop. */

#define	LPBLABEL1	"Bigram guess, level %6.3f, prob %6.3f  -- Wait"
#define	LPBLABEL2	"Bigram guess, level %6.3f, prob %6.3f  -- Done"
#define	LPBHELP "F3 enters guess, ^G undoes it."


extern	char	mcbuf[];
extern	ecinfo	gecinfo;
extern	ec_init();
extern	lpbdraw(), lpbfirst(), lpbenter(), lpbundo();

/* Gloabal State. */
keyer	lpbktab[] = {
		{CACCEPT, lpbenter},
		{CUNDO, lpbundo},
		{CGO_UP, jogup},
		{CGO_DOWN, jogdown},
		{CGO_LEFT, jogleft},
		{CGO_RIGHT, jogright},
		{0, NULL},
};

/* Routine invoked by user to put up the letter pair equivalence class
 * guessing window.
 * The window is drawn empty, and then filled in with the guess.
 * Return NULL if command completes ok.
 */
char	*lpbguess(str)
char	*str;			/* Command line */
{
	ecinfo	*ecbi;
	int		i;
	gwindow	*ecb;
	float	lp_accept_level, lp_prob_cutoff;

	ecb = &gbstore;
	ecbi = &gecinfo;
	lp_init(mcbuf, refperm(dbsgetblk(&dbstore)), ecbi);

	if ((i = sscanf(str, "%*[^:]: %f %*[^:]: %f",
			&lp_accept_level, &lp_prob_cutoff)) != 2)  {
		return("Could not parameters.");
		}

	gbsswitch(ecb, ((char *) ecbi), lpbktab, lpbfirst, wl_noop, lpbdraw);

	sprintf(statmsg, LPBLABEL1, lp_accept_level, lp_prob_cutoff);
	gblset(&gblabel, statmsg);
	gbsclear(ecb);
	fflush(stdout);

	lp_autoguess(ecbi, lp_accept_level);
	decode(ecbi->ciphertext, ecbi->plaintext, ecbi->perm);

	sprintf(statmsg, LPBLABEL2, lp_accept_level, lp_prob_cutoff);
	gblset(&gblabel, statmsg);
	lpbdraw(ecb);

	return(NULL);
}


/*  (re) Draw the window.
 */
lpbdraw(ecb)
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
lpbfirst(ecb, row, col)
gwindow	*ecb;
int			row, col;
{
	usrhelp(&user, LPBHELP);
	wl_setcur(ecb, row, col);
}


/* Enter the guess into the decryption block.
 */
lpbenter(ecb)
gwindow	*ecb;
{
	ecinfo		*ecbi;

	ecbi = ((ecinfo *) ecb->wprivate);
	dbsmerge(&dbstore, ecbi->perm);
	wl_rcursor(ecb);
}


/* Undo the last guess.
 */
lpbundo(ecb)
gwindow	*ecb;
{
	ecinfo		*ecbi;

	ecbi = ((ecinfo *) ecb->wprivate);
	dbsundo(&dbstore);
	wl_rcursor(ecb);
}



/* Guess at a block using letter pair statistics.
 * The parameter accept_level is the minimum ratio (of estmated prob
 * that the guess is right over estimate prob that some other guess
 * is right) needed to accept a guess.
 * The parameter prob_cutoff is the minimum probability (density) that
 * the guess is right.  This parameter comes into play when there is one
 * guess which looks much better than the rest (i.e., has a high ratio),
 * but in fact all the guesses look pretty bad, so the program should
 * avoid picking one.
 * Modfies eci.
 */
lp_autoguess(eci, accept_level, prob_cutoff)
reg	ecinfo	*eci;
	float	accept_level;
	float	prob_cutoff;
{
	int		i;
reg	int		c;
	int		ntried;
reg	int		classpos;
	int		*permp;
	int		repeat;

for(repeat = 0 ; repeat < AUTOREPEAT ; repeat++)  {
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
			}
		}
#if (AUTOREPEAT > 1)
	for (i = 0 ; i < eci->nclasses ; i++)  {
		eci->classlist[i].changed = TRUE;
		}
#endif
	}
}


/* Score a guess using letter pair statistics.
 * Bigger scores are better scores.  They range from 0 to 1.
 * A score of zero means the choice is not possible.
 * The result is the probability density that the guess is correct.
 * Actually, the resulting score is the product of the prob densities
 * of the first and second order statistics.
 */
float	lp_cscore(gsi)
reg	gsinfo	*gsi;
{
	extern	float	score2_scale, score1_scale;
	float	score1, score2;
reg	float	sdev1, sdev2;		/* Standard Deviation for 1st and 2nd stats. */
	int		ccount;

	for (ccount = 0 ; gsi->cpos[ccount] != NONE ; ccount++);

	sdev1 = gsi_1score(gsi);
	if (sdev1 < 0.0)  return(0.0);
	score1 = fexp(sdev1);
	score1 = (score1 * isqrt[ccount]) / score1_scale;

	sdev2 = gsi_2score(gsi);
	if (sdev2 < 0.0)  return(0.0);
	score2 = fexp(sdev2);
	score2 = (score2 * isqrt[ccount]) / score2_scale;

	return(score1 * score2);
}


/* Select best plaintext value for a ciphertext equiv class.
 * The class is identified by the position in the block of one
 * of the characters in the class.  The plaintext value for
 * an entire class can be specified by the plaintext value of
 * one of its members.  This routine returns the best plaintext
 * value for the ciphertext character at position firstpos.
 * If there is not a clear best value, NONE is returned.
 */
int	lp_best_char(eci, firstpos, alevel, min_prob)
reg		ecinfo	*eci;
int		firstpos;
float	alevel;		/* Level to accept a guess ~= prob(right)/prob(wrong) */
float	min_prob;
{
#if DEBUG
	int		pvec[BLOCKSIZE+1];
	char	str[BLOCKSIZE+1];
#endif
	float	total_score, score;
	float	best_score;
	int		best_char;
reg	int		c;
	int		x,y;
	int		class;
	float	count;
reg	gsinfo	*gsi;
	gsinfo	tmpgsi;
	int		gssbuf[BLOCKSIZE+1];

	gsi = &tmpgsi;
	gsi_init(gsi, eci->plaintext, gssbuf);

	total_score = 0.0;
	best_score = 0.0;
	count = 0.0;
	best_char = NONE;

	for (c = 0 ; c <= MAXCHAR  ; c++)  {
		gsi_clear(gsi);
		if (gsi_class_guess(gsi, eci, firstpos, c) == 0)
			continue;
		score = lp_cscore(gsi);
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

	class = eci->posclass[firstpos];
	printf("Class reliability is %d.",
		(2 * eci->classlist[class].npairs) + eci->classlist[class].nchars);
	printf("  ");

	decode_class(eci, firstpos, best_char, pvec);
	pvec2str(str, pvec);
	printf("The best chars are '%s'\n", str);
#endif

	if ((best_score  >  alevel * (total_score - best_score))
	 && (best_score > min_prob)) {
		return(best_char);
		}
	else {
		return(NONE);
		}
}


/* Accept a guess.
 * Updates the eci plaintext to reflect the characters deduced from
 * assuming that the plaintext character at position pos is pchar.
 * It updates the npairs count and used flag in the class info list.
 * The changed flag is set for positions pos-1 and pos+1 (if they exist).
 * The used flag is set for the class(es) that now have an accepted value.
 */
lp_accept(eci, firstpos, firstpchar)
reg		ecinfo	*eci;
int		firstpos;
int		firstpchar;
{
	int		firstflag;	/* For macro for_pos_in_class. */
	int		otherpos;
reg	int		pos;
	int		x,y;
	int		pchar;
	int		delta;
	clinfo	*firstclassp, *otherclassp;
reg	clinfo	*classp;

	firstpos = firstpos & MODMASK;
	firstpchar = firstpchar & CHARMASK;
	x = eci->scipher[firstpos];
	y = MODMASK & (firstpchar + firstpos);

	eci->perm[x] = y;
	eci->perm[y] = x;

	firstclassp = &(eci->classlist[eci->posclass[firstpos]]);
	firstclassp->used = TRUE;

	otherpos = eci->permmap[y];
	if (otherpos == NONE)  {
		otherclassp = NULL;
		}
  	else  {
		otherclassp = &(eci->classlist[eci->posclass[otherpos]]);
		otherclassp->used = TRUE;
		}


	delta = y - x;
	for_pos_in_class(pos, firstpos)  {
		pchar = MODMASK & (eci->scipher[pos] + delta - pos);
		eci->plaintext[pos] = pchar;
		if ((pos - 1) >= 0)  {
			classp = &(eci->classlist[eci->posclass[pos - 1]]);
			if (classp != firstclassp)  {
				classp->changed = TRUE;
				classp->npairs++;
				}
			}
		if ((pos + 1) < BLOCKSIZE)  {
			classp = &(eci->classlist[eci->posclass[pos + 1]]);
			if (classp != firstclassp)  {
				classp->changed = TRUE;
				classp->npairs++;
				}
			}
		}

	if (otherpos != NONE)  {
		delta = x - y;
		for_pos_in_class(pos, otherpos)  {
			pchar = MODMASK & (eci->scipher[pos] + delta - pos);
			eci->plaintext[pos] = pchar;
			if ((pos - 1) >= 0)  {
				classp = &(eci->classlist[eci->posclass[pos - 1]]);
				if (classp != otherclassp)  {
					classp->changed = TRUE;
					classp->npairs++;
					}
				}
			if ((pos + 1) < BLOCKSIZE)  {
				classp = &(eci->classlist[eci->posclass[pos + 1]]);
				if (classp != otherclassp)  {
					classp->changed = TRUE;
					classp->npairs++;
					}
				}
			}
		}
}



/* Pick the best position to do guessing.
 * Use the class info list to select the unused class that will yield
 * the most reliable guesses.
 * The changed flag is cleared to make sure that a class is not considered
 * again unless the reliability of its guesses has changed.
 * At first, all the changed flags should be set.
 * The changed flag for the selected class is cleared.
 * Returns a position or NONE.
 */
int	lp_best_pos(eci, min_reliability)
reg		ecinfo	*eci;
int		min_reliability;
{
	int		score;
	int		best_score, best_pos;
reg	clinfo	*classp;
reg	clinfo	*endclassp;

	best_score = 0;
	best_pos = NONE;
	endclassp = &(eci->classlist[eci->nclasses]);
	for (classp = &(eci->classlist[0]) ; classp < endclassp ; classp++)  {
		if ((classp->used) || (!(classp->changed)))
			continue;
		score = (2 * (classp->npairs)) + classp->nchars;
		if (score > best_score)  {
			best_score = score;
			best_pos = classp->firstpos;
			}
		}
	if (best_score < min_reliability)
		return(NONE);

	if (best_pos != NONE)  {
		eci->classlist[eci->posclass[best_pos]].changed = FALSE;
		}
	return(best_pos);
}


/* Fill in equiv class info from given ciphertext block
 * and permutation.
 */
lp_init(cipher, perm, eci)
char	cipher[];
int		perm[];
reg		ecinfo	*eci;
{
	int		firstflag;	/* Used by for_pos_in_class */
	int		i,j;
	int		firstpos, char_count, pair_count;
reg	int		pos;
reg	clinfo	*class;

	ec_init(cipher, perm, eci);

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		eci->posclass[i] = NONE;
		}

	eci->nclasses = 0;
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if ((firstpos = eci->permmap[i]) == NONE)
			continue;
		char_count = 0;
		pair_count = 0;
		for_pos_in_class(pos, firstpos) {
			eci->posclass[pos] = eci->nclasses;
			char_count++;
			}
		for_pos_in_class(pos, firstpos) {
			if ((pos + 1) < BLOCKSIZE)  {
			 	if (eci->posclass[pos + 1] == eci->nclasses)  {
					pair_count++;
					}
				else if (eci->perm[eci->scipher[pos + 1]] != NONE)  {
					pair_count++;
					}
				}
			if ((pos - 1) >= 0)  {
			 	if (eci->posclass[pos - 1] == eci->nclasses)  {
					/* Don't double count it. */
					}
				else if (eci->perm[eci->scipher[pos - 1]] != NONE)  {
					pair_count++;
					}
				}
			}
		class = &(eci->classlist[eci->nclasses]);
		class->nchars = char_count;
		class->npairs = pair_count;
		class->firstpos = firstpos;
		class->changed = TRUE;
		if (eci->perm[i] != NONE)
			class->used = TRUE;
		else
			class->used = FALSE;

		eci->nclasses++;
		}
}


/* Initialize a guess info structure.
 * Also clears the guess buffer.
 */
gsi_init(gsi, pbuf, gssbuf)
reg		gsinfo	*gsi;
		int		*pbuf;		/* Accepted characters. */
reg		int		*gssbuf;	/* Buffer for new guesses. */
{
reg	int		i;

	gsi->cknown = pbuf;
	gsi->cpos[0] = NONE;
	gsi->cguessed = gssbuf;
	for (i = 0 ; i < BLOCKSIZE ; i++)
		*gssbuf++ = NONE;
}


/* Clear out a guess from a gsi.
 */
gsi_clear(gsi)
reg	gsinfo	*gsi;
{
reg	int		*ip;

	for (ip = &(gsi->cpos[0]) ; *ip != NONE ; ip++)  {
		gsi->cguessed[*ip] = NONE;
		}
	gsi->cpos[0] = NONE;
}


/* Add to a gsi with the characters deduced from assuming that
 * the character at firstpos is c.
 * If that asumption conflicts with eci->perm, then nothing is added.
 * Returns the number of characters added.
 */
int	gsi_class_guess(gsi, eci, firstpos, c)
reg		gsinfo	*gsi;
reg		ecinfo	*eci;
		int		firstpos;
		int		c;
{
	int		firstflag;	/* For macro for_pos_in_class. */
	int		otherpos;
reg	int		pos;
	int		x,y;
	int		pchar;
	int		delta;
	int		*cposp;
	int		nchars;

	for (cposp = &(gsi->cpos[0]) ; *cposp != NONE ; cposp++);
	nchars = 0;

	firstpos = firstpos & MODMASK;
	c = c & CHARMASK;
	x = eci->scipher[firstpos];
	y = MODMASK & (c + firstpos);

	if (perm_conflict(eci->perm, x, y))
		return(nchars);

	delta = y - x;
	for_pos_in_class(pos, firstpos)  {
		pchar = MODMASK & (eci->scipher[pos] + delta - pos);
		if ((pchar & CHARMASK) != pchar)  {
			*cposp = NONE;
			return(0);
			}
		gsi->cguessed[pos] = pchar;
		*cposp++ = pos;
		nchars++;
		}

	otherpos = eci->permmap[y];
	if (otherpos != NONE)  {
		delta = x - y;
		for_pos_in_class(pos, otherpos)  {
			pchar = MODMASK & (eci->scipher[pos] + delta - pos);
			if ((pchar & CHARMASK) != pchar)  {
				*cposp = NONE;
				return(0);
				}
			gsi->cguessed[pos] = pchar;
			*cposp++ = pos;
			nchars++;
			}
		}
	*cposp = NONE;
	return(nchars);
}


/* Dump class table onto a stream.
 */
lp_dclasses(out, eci)
FILE	*out;
ecinfo	*eci;
{
	int		i;

	fprintf(out, "\nThere are %d classes.\n", eci->nclasses);
	for (i = 0 ; i < eci->nclasses ; i++)  {
		fprintf(out, "Singles: %d, pairs: %d,  First member: %d",
				eci->classlist[i].nchars, eci->classlist[i].npairs,
				eci->classlist[i].firstpos);
		fprintf(out, ", flags:");
		if (!(eci->classlist[i].used))
			fprintf(out, " not");
		fprintf(out, " used");
		fprintf(out, " and");
		if (!(eci->classlist[i].changed))
			fprintf(out, " not");
		fprintf(out, " changed");
		fprintf(out, "\n");
		}
}


