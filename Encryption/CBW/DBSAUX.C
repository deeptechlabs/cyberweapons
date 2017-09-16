/*
 * dblock.c takes too long to compile, so this is separate.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"layout.h"
#include	"specs.h"
#include	"pqueue.h"
#include	"cipher.h"

#include	"dblock.h"


ecinfo	t_ecinfo;


/* Try all the possible characters at the current position.
 * Display those that do not generate any conflicts.
 */
dbstryall(dbs, k)
gwindow	*dbs;
key		k;
{
	int		col, pos;
	int		oldrow, oldcol;
	int		i;
	int		tchar;
	ecinfo	*ecbi;
	dbsinfo	*dbsi;
	int		pque_index;
	pqueue_hdr	pque_hdr;
	pqueue_ent	the_pque[MAXCHAR+1];

	dbsi = ((dbsinfo *) dbs->wprivate);
	ecbi = &t_ecinfo;

	pque_init(&pque_hdr, 1000.0, &the_pque[0], MAXCHAR+1);
	ec_init(dbsi->cbuf, dbsi->perm, ecbi);
	
	oldrow = dbs->wcur_row;
	oldcol = dbs->wcur_col;
	pos = dbsrc2pos(oldrow, oldcol);
	dbstrypq(ecbi, &pque_hdr, pos);

	wl_setcur(dbs, dbsp2row(BLOCKSIZE), dbsp2col(BLOCKSIZE));

	tchar = 0;
	for (col = 1 ; col < dbs->wwidth ; col++)  {
		pque_index = col - 1;
		if (pque_index >= pque_hdr.next_index)  break;
		tchar = the_pque[pque_index].value1;
		plnchars(1, char2sym(tchar));
		}
  alldone:
	plnchars((dbs->wwidth) - col, ' ');
	wl_setcur(dbs, oldrow, oldcol);
}


/* Try all chars in position pos.  Added them to a priority queue.
 * The most likely character appears first.
 */
dbstrypq(ecbi, pque_hdr, pos)
ecinfo		*ecbi;
pqueue_hdr	*pque_hdr;
int			pos;
{
	int		plainchar;
	int		added;
	float	score;
	extern	float	score2_scale, score1_scale;
	float	score1, score2;
	float	sdev1, sdev2;		/* Standard Deviation for 1st and 2nd stats. */
	gsinfo	tmpgsi;
	gsinfo	*gsi;
	int		gssbuf[BLOCKSIZE+1];

	gsi	= &tmpgsi;
	gsi_init(gsi, ecbi->plaintext, gssbuf);

	for (plainchar = 0 ; plainchar <= MAXCHAR ; plainchar++)  {
		gsi_clear(gsi);
		added = gsi_class_guess(gsi, ecbi, pos, plainchar);
		if (added > 0) {
			sdev1 = gsi_1score(gsi);
			if (sdev1 < 0.0)
				continue;
			sdev2 = gsi_2score(gsi);
			if (sdev2 < 0.0)
				continue;
			score = sdev1 + sdev2;
			pque_add(pque_hdr, score, plainchar, 0);
			}
		}
}


/* Word search from dictionary.  Try to find the word at the cursor position.
 * The cursor must be at either the beginning or end of a word as indicated
 * by the cursor being adjacent to a whitespace character.
 * 
 * For now, a pattern is extracted an a word lookup command gets executed.
 * The keystroke argument, k, is not used.
 */
dbswrdsrch(dbs, k)
gwindow	*dbs;
key		k;
{
	int	oldrow, oldcol;		/* To reset cursor pos if needed. */
	int	pos;			/* Char offset in block. */
	int	prev_char;
	ecinfo	*ecbi;
	dbsinfo	*dbsi;
	
	dbsi = ((dbsinfo *) dbs->wprivate);
	ecbi = &t_ecinfo;
	ec_init(dbsi->cbuf, dbsi->perm, ecbi);
	
	oldrow = dbs->wcur_row;
	oldcol = dbs->wcur_col;
	pos = dbsrc2pos(oldrow, oldcol);
	prev_char = pos > 0 ? dbsi->pbuf[pos-1] : NONE;
	if (isletter(prev_char)) {
		usrstatus(&user,
		   "Word Search: Cursor must be start of a word.");
		return;
		}

/*	websearch(&webster, ecbi, pos, TRUE); */
	return;
}
