/*
 * Automatic guessing based on trigrams.
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
#include	"autotri.h"


#define	DEBUGP	FALSE		/* Perm building */
#define	DEBUGB	FALSE		/* Best guess */

#define	ATRLABEL1  \
"Auto Trigram, max SD: %4.2f total: %d wire: %d -- Please Wait"
#define	ATRLABEL2  \
"Auto Trigram, max SD: %4.2f total: %d wire: %d -- Done"
#define	ATRHELP		 "F3 enters guess, ^G undoes it."


extern	char	mcbuf[];
extern	ecinfo	gecinfo;
extern	atrdraw(), atrfirst(), atrenter(), atrundo();

/* Gloabal State. */
char	*trigramstats;		/* Filename for statistics. */
atrinfo	gatrinfo;
keyer	atrktab[] = {
		{CACCEPT, atrenter},
		{CUNDO, atrundo},
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
char	*atrguess(str)
char	*str;			/* Command line */
{
	gwindow	*atr;
	atrinfo	*atri;
	ecinfo	*ecbi;
	int		*dbsperm;
	int		i, c;
	int		classpos;
	int		x, y;

	atr = &gbstore;
	atri = &gatrinfo;
	dbsperm = refperm(dbsgetblk(&dbstore));
	atr_init(mcbuf, dbsperm, atri);
	ecbi = atri->eci;
	atri->min_total_chars = 123;
	atri->min_wire_chars = 456;

	if ((i = sscanf(str, "%*[^:]: %f %*[^:]: %d %*[^:]: %d",
		&atri->max_score, &atri->min_total_chars,
		&atri->min_wire_chars)) != 3)  {
			return("Could not parse all three arguments.");
		}

	gbsswitch(atr, ((char *) atri), atrktab, atrfirst, wl_noop, atrdraw);

	sprintf(statmsg, ATRLABEL1,
	        atri->max_score, atri->min_total_chars, atri->min_wire_chars);
	gblset(&gblabel, statmsg);
	atrdraw(atr);
	fflush(stdout);

	atr_autoguess(atri);
	decode(ecbi->ciphertext, ecbi->plaintext, ecbi->perm);

	sprintf(statmsg, ATRLABEL2,
	        atri->max_score, atri->min_total_chars, atri->min_wire_chars);
	gblset(&gblabel, statmsg);
	atrdraw(atr);

	return(NULL);
}


/*  (re) Draw the window.
 */
atrdraw(atr)
gwindow	*atr;
{
	int			i;
	int			row, col;
	atrinfo		*atri;
	ecinfo		*ecbi;

	atri = ((atrinfo *) atr->wprivate);
	ecbi = atri->eci;
	row = 1;
	col = 1;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (i%LINELEN == 0) {
			wl_setcur(atr, gbspos2row(i), gbspos2col(i));
			}
		plnchars(1, char2sym(ecbi->plaintext[i]));
		}

	for (i = gbspos2row(BLOCKSIZE) ; i <= GBHEIGHT ; i++) {
		wl_setcur(atr, i, 1);
		plnchars(LINELEN, ' ');
		}

	for (i = 1 ; i <= GBHEIGHT ; i++) {
		wl_setcur(atr, i, LINELEN+1);
		plnchars(atr->wwidth - LINELEN, ' ');
		}

	wl_setcur(atr, row, col);
}


/* First time cursor enters window.
 */
atrfirst(atr, row, col)
gwindow	*atr;
int			row, col;
{
	usrhelp(&user, ATRHELP);
	wl_setcur(atr, row, col);
}


/* Enter the guess into the decryption block.
 */
atrenter(atr)
gwindow	*atr;
{
	atrinfo		*atri;

	atri = ((atrinfo *) atr->wprivate);
	dbsmerge(&dbstore, atri->eci->perm);
	wl_rcursor(atr);
}


/* Undo the last guess.
 */
atrundo(atr)
gwindow	*atr;
{
	dbsundo(&dbstore);
	wl_rcursor(atr);
}


/* Fill in auto-trigram info from given ciphertext block.
 * The filter parameters are not set by this routine.
 */
atr_init(cipher, perm, atri)
char	cipher[];
int		perm[];
atrinfo	*atri;
{
extern	int	*trig_loaded;
	int		i;

	atri->eci = &gecinfo;
	if (!trig_loaded)
		load_tri_from(trigramstats);
	ec_init(cipher, perm, atri->eci);
	atr_guess_init(atri);
}


/* Per guess initialization.
 */
atr_guess_init(atri)
atrinfo	*atri;
{
	atri->best_trigram = NULL;
	atri->best_score = 10.0;
	atri->gcount = 0;
	atri->total_score = 0;
	atri->best_pvec[0] = NONE;
	atri->best_permvec[0].x = NONE;
}



/* Score a trigram at a given position.
 * It also looks in atri for filtering parameters (total number
 * of chars must not be less than min_total_chars, and the minimum number
 * of chars deduced per wire must not be less than min_wire_chars).
 * This routine fills in permvec and pvec.
 * Returns -1.0 if guess is unacceptable.
 */
float	atr_score(atri, trigent, pos, permvec, pvec)
atrinfo		*atri;
trig_ent	*trigent;
int			pos;
perment		permvec[];
int			pvec[];
{
	int		length;
	int		i, x, y;
	int		ccount;
	int		added;
	extern	float	logvar;
	float	score;
	ecinfo	*eci;
	int		butfirst;
	int		butlast;

	for (length = 0 ; trigent->trigram[length] != 0 ; length++);
	eci = atri->eci;
	added = permvec_from_string(atri->eci, trigent->trigram, pos, permvec);
	if (added < 0)  return(-1.0);

	butfirst = pos;
	butlast = pos + length -1;
	ccount = 0;

	for (i = 0 ; i < PERMSZ  &&  permvec[i].x != NONE ; i++)  {
		if (ccount >= BLOCKSIZE-1)  break;
		x = permvec[i].x;
		y = permvec[i].y;
/*		added = decode_wire_but(eci, x, y, &pvec[ccount], -1, -1);*/
		added = decode_wire_but(eci, x, y, &pvec[ccount], butfirst, butlast);
		if (added < 0)  {
			ccount = 0;
			break;
			}
		if (added < atri->min_wire_chars)  {
			ccount = 0;
			break;
			}
		ccount += added;
		}
	pvec[ccount] = -1;

	if (ccount <= 0)  return(-1.0);
	if (ccount < atri->min_total_chars)  return(-1.0);

	score = pvec_1score(pvec);
	if (score < 0.0)  return(-1.0);
/*
	score = exp(-(score * score) / 2.0);
	score = score / sqrt(2*PI*logvar/ccount);
	score = score * trigent->prob;
*/
	return(score);
}


/* Select the best trigram for a given position.
 * Returns pointer to trigram string, or NULL.
 * Fills in atri with additional information.
 * Filtering parameters are in atri.
 */
char	*atr_best(atri, pos)
atrinfo	*atri;
int		pos;
{
	int		tgram;
	float	score;
	perment	permvec[PERMSZ];
	int		pvec[BLOCKSIZE+1];
#if DEBUGB
	char	str[BLOCKSIZE+1];
#endif

	atr_guess_init(atri);

	for (tgram = 0 ; trig_tab[tgram].trigram != NULL ; tgram++)  {
		score = atr_score(atri, &trig_tab[tgram], pos, permvec, pvec);
		if (score < 0.0)  continue;
		atri->total_score += score;
		atri->gcount++;
		if (score < atri->best_score) {
			atri->best_score = score;
			atri->best_trigram = trig_tab[tgram].trigram;
			pvec_copy(pvec, atri->best_pvec);
			permvec_copy(permvec, atri->best_permvec, PERMSZ);
			}
		}

#if DEBUGB
	if (atri->best_score < atri->max_score) {
		printf("\nTrigram '%s' at %d", atri->best_trigram, pos);
		pvec2str(str, atri->best_pvec);
		printf(" deduces '%s'", str);
		printf(" which scores as %g", atri->best_score);
		printf(".\n");
		}
#endif

	if (atri->best_score < atri->max_score)
		{return(atri->best_trigram);}
	else
		{return(NULL);}
}


/* Merge the given permvector into the permutation table.
 * Return ERROR if there is a conflict, otherwise TRUE.
 */
int	accept_permvec(atri, permvec)
atrinfo	*atri;
perment	permvec[];
{
	int		i, x, y;
	ecinfo	*ecbi;

	ecbi = atri->eci;
	for (i = 0 ; i < PERMSZ  &&  permvec[i].x != NONE ; i++)  {
		x = MODMASK & permvec[i].x;
		y = MODMASK & permvec[i].y;
		if (perm_conflict(ecbi->perm, x, y)) {
#if DEBUGP
			printf("CONFLICT trying to wire %d to %d.\n", x, y);
#endif
			return(ERROR);
			}
		}


	/* Now know that there are no conflicts. */
	for (i = 0 ; i < PERMSZ  &&  permvec[i].x != NONE ; i++)  {
#if DEBUGP
		printf("ACCEPTING wiring of %d to %d.\n", x, y);
#endif
		x = MODMASK & permvec[i].x;
		y = MODMASK & permvec[i].y;
		ecbi->perm[x] = y;
		ecbi->perm[y] = x;
		}

	return(TRUE);
}



/* Perform automatic guessing given a set of
 * filter parameters in an atrinfo structure.
 */
atr_autoguess(atri)
atrinfo	*atri;
{
	int		pos;
	char	*trigram;

	for (pos = 0 ; pos < BLOCKSIZE ; pos++) {
		trigram = atr_best(atri, pos);
		if (trigram != NULL) {
			accept_permvec(atri, atri->best_permvec);
			}
		}
}
