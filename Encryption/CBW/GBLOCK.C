/*
 * Guess block and its label.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"
#include	"cipher.h"		/* RWB */
#include	"autotri.h"



/* Private buffers for plaintext guessing. */

char	gcbuf[BLOCKSIZE+1];
int		gpbuf[BLOCKSIZE+1];
int		gperm[BLOCKSIZE+1];
ecinfo	gecinfo;			/* RWB */

extern	atrinfo	gatrinfo;
extern	char	mcbuf[];

/* Window for the guess block label. */

displine	gblline1 = {
		GBLROW,1,		/* Origin. */
		1,GBWIDTH,		/* Height and width. */
		1,1,			/* Initial (relative) cursor pos. */
		NULL,			/* No private data. */
		wl_setcur,		/* Firstime = restore cursor pos. */
		wl_noop,		/* Lasttime = do nothing. */
		wl_dldraw,		/* Default dispaly line draw routine */
		dokey,			/* Default keystroke handler. */
		arwktab,		/* Basic arrow keystroke handler. */
		1,GBWIDTH,		/* Min and Max col for cursor line */
};

displine	*gbllines[] = {		/* List of display lines for the label. */
			&gblline1,
			NULL,
			};

twindow		gblabel = {
			GBLROW,1,		/* Origin. */
			1,GBWIDTH,		/* Height and width. */
			1,1,			/* Initial (relative) cursor position */
			NULL,			/* No private data. */
			wl_setcur,		/* Firstime = restore cursor position. */
			wl_noop,		/* Lasttime = do nothing. */
			wl_twdraw,		/* Simple draw routine. */
			dokey,			/* Default keystroke handler. */
			arwktab,		/* Basic arrow keystroke handler. */
			gbllines,
			};


/* Window for the guess block. */

gwindow	gbstore = {
		GBSROW,1,		/* Origin. */
		GBHEIGHT,GBWIDTH,	/* Height and width. */
		1,1,			/* Initial cursor position */
		NULL,			/* Private data. */
		wl_setcur,		/* Firstime = accept cursor pos. */
		wl_noop,		/* Lasttime = do nothing. */
		wl_outline,		/* Simple draw routine. */
		dokey,			/* Default keystroke handler. */
		arwktab,		/* Keystroke table. */
};



/* Initialize the guess block label, and return a ptr to it.
 */
gwindow	*(igblabel())
{
	displine	*line;

	line = gblabel.dlines[0];
	setadline(line, GBLTEXT);
	return ((gwindow *) &gblabel);
}


/* Set the label to indicate the given string.
 * Redisplay the label.
 */
gblset(label, str)
twindow	*label;
char	*str;
{
	int		row,col;
	displine	*line;

	row = rowcursor();
	col = colcursor();

	line = label->dlines[0];
	setadline(line, str);
	(*(line->wredraw))(line);

	setcursor(row, col);
}



/* Initialize the guess block storage, and return a ptr to it.
 * Start with the Trigram guessing window.
 */
gwindow	*(igbstore())
{
	extern	atrdraw();
	extern	atr_init();
	atrinfo	*atri;

	atri = &gatrinfo;
	atr_init(mcbuf, refperm(dbsgetblk(&dbstore)), atri);
	gbsswitch(&gbstore, ((char *) atri), arwktab, wl_setcur, wl_noop, atrdraw);
	return (&gbstore);
}


/* Switch the guessing window to the desired functionality
 * by changing the keytable, private data pointer, firsttime,
 * and lasttime function routines.
 */
gbsswitch(gbs, private, keytable, firsttime, lasttime, draw)
gwindow	*gbs;
char	*private;
keyer	keytable[];
int		(*firsttime)(), (*lasttime)();
int		(*draw)();
{
	gbs->wprivate = private;
	gbs->wkeyprocs = keytable;
	gbs->wfirst = firsttime;
	gbs->wlast = lasttime;
	gbs->wredraw = draw;
}


/* Convert block position to relative row/column coordinate.
 */
int	gbspos2row(pos)
int	pos;
{
	return(1 + (pos/LINELEN));
}


/* Convert block position to relative row/column coordinate.
 */
int	gbspos2col(pos)
int	pos;
{
	return(1 + (pos%LINELEN));
}


/* Clear out the guess block marking all character positions as unknown.
 */
gbsclear(gbs)
gwindow	*gbs;
{
	int			i;
	int			row, col;

	row = 1;
	col = 1;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (i%LINELEN == 0) {
			wl_setcur(gbs, gbspos2row(i), gbspos2col(i));
			}
		plnchars(1, char2sym(NONE));
		}

	for (i = gbspos2row(BLOCKSIZE) ; i <= GBHEIGHT ; i++) {
		wl_setcur(gbs, i, 1);
		plnchars(LINELEN, ' ');
		}

	for (i = 1 ; i <= GBHEIGHT ; i++) {
		wl_setcur(gbs, i, LINELEN+1);
		plnchars(gbs->wwidth - LINELEN, ' ');
		}

	wl_setcur(gbs, row, col);
}
