/*
 * Library of window routines.
 *
 * Robert W. Baldwin, December 1984.
 */

#include	<stdio.h>
#include	"window.h"
#include	"specs.h"


/* The external topktab must be filled in by the application.
 * It specifies the keystroke behavior that is the same in
 * all windows.  For example, the refresh function can be handled here.
 * It should be terminated by a keychar == 0, not -1, so the
 * active window will get a chance to handle the key.
 */
extern	keyer	topktab[];


/* This external must be a routine that gets and returns
 * a keystroke (integer) without taking any arguments.
 */
extern	key		u_getkey();



/* This is the main loop that runs the window system.
 * It returns if the cursor is not in any of the windows in wtab.
 */
wl_driver(wtab)
gwindow		*wtab[];		/* Ptr to null terminated list of windows. */
{
gwindow		**pw, *w;
int			lrow, lcol;		/* Cursor location relative to window. */
key			k;

while (TRUE)  {
	for (pw = wtab ; TRUE ; pw++)  {
		w = *pw;
		if (w == NULL)  return;
		if (wl_hascur(w))  break;
		}

	lrow = rowcursor() - w->worg_row + 1;
	lcol = colcursor() - w->worg_col + 1;
	(*(w->wfirst))(w, lrow, lcol);

	while (wl_hascur(w))  {
		k = u_getkey();
		if (!ddokey(w, k, topktab)) {
			(*(w->wkey))(w, k);
			}
		}

	(*(w->wlast))(w);
	}
}



/* Refresh all windows.
 * Do not move the cursor.
 */
wl_refresh(wtab)
gwindow		*wtab[];		/* Ptr to null terminated list of windows. */
{
	gwindow		**pw, *w;
	int			row, col;		/* Initial global cursor location. */

	row = rowcursor();
	col = colcursor();

	for (pw = wtab ; TRUE ; pw++)  {
		w = *pw;
		if (w == NULL)  break;
		wl_draw(w);
		}
	setcursor(row, col);
}



/* Restore the cursor the the position saved in the window structure.
 * Can also be used to set the cursor by first setting the cursor coords
 * in the window data structure.
 */
wl_rcursor(w)
gwindow	*w;			/* Pointer to basic window data. */
{
	int	grow,gcol;	/* Global cursor locations. */

	grow = w->wcur_row + w->worg_row - 1;
	gcol = w->wcur_col + w->worg_col - 1;
	setcursor(grow,gcol);
	if (!wl_hascur(w))  disperr("wl_rcursor arguments out-of-bounds.");
}



/* Set the cursor to the given coordinates within a window.
 * That is, set it relative to the window's origin.
 * It displays an error if the cursor leaves the window.
 */
wl_setcur(w, row, col)
gwindow	*w;			/* Pointer to basic window data. */
int		row, col;	/* Local coordinates. */
{
	int	grow,gcol;	/* Global cursor locations. */

	w->wcur_row = row;
	w->wcur_col = col;
	grow = w->worg_row + row - 1;
	gcol = w->worg_col + col - 1;
	setcursor(grow,gcol);
	if (!wl_hascur(w))  disperr("wl_setcur arguments out-of-bounds.");
}


/* No-op window routine.
 */
wl_noop()
{
}



/* Return TRUE if the cursor is in the given window.
 */
wl_hascur(w)
gwindow		*w;
{
	int		grow, gcol;		/* Global cursor location. */
	int		lrow, lcol;		/* Cursor location relative to window. */

	grow = rowcursor();
	gcol = colcursor();
	lrow = grow - w->worg_row + 1;
	lcol = gcol - w->worg_col + 1;

	if (lrow < 1  ||  w->wheight < lrow)  return(FALSE);
	if (lcol < 1  ||  w->wwidth  < lcol)  return(FALSE);
	return(TRUE);
}



/* Generic draw routine.
 */
wl_draw(w)
gwindow	*w;
{
	(*(w->wredraw))(w);
}


/* Redraw routine that can be used with any twindow.
 * Leaves cursor on the last display line.
 */
wl_twdraw(w)
twindow	*w;
{
	displine	**lines, *line;

	for (lines = w->dlines ; (line = *lines) != NULL ; lines++)  {
		(*(line->wredraw))(line);
		}
}


/* Erase the window by putting spaces of all of it.
 * Leave the cursor at the window's origin.
 */
wl_erase(w)
gwindow	*w;
{
	int	grow, gcol;		/* Global row and column locations. */
	int i;

	grow = w->worg_row;
	gcol = w->worg_col;

	for (i = 0 ; i < w->wheight ; i++)  {
		setcursor(grow+i, gcol);
		plnspaces(w->wwidth);
		}
	wl_setcur(w, 1, 1);
}


/* Outline a window without changing its inside.
 * Leave cursor at the origin.
 */
wl_outline(w)
gwindow	*w;
{
	int	grow, gcol;		/* Global row and column locations. */

	grow = w->worg_row;
	gcol = w->worg_col;

	setcursor(grow, gcol);
	plnchars(w->wwidth, '-');
	setcursor(grow+w->wheight-1, gcol);
	plnchars(w->wwidth, '-');

	setcursor(grow, gcol);
	vertnchars(w->wheight, '|');
	setcursor(grow, gcol+w->wwidth-1);
	vertnchars(w->wheight, '|');

	grow = w->worg_row + w->wcur_row - 1;
	gcol = w->worg_col + w->wcur_col - 1;
	setcursor(grow, gcol);
}
