/*
 * Library of keystroke handling routines.
 *
 * Robert W. Baldwin,  December 1984.
 */

#include	<stdio.h>
#include	"window.h"
#include	"terminal.h"
#include	"specs.h"


/* Keystroke table for default arrow key functionality.
 * Used by the windows that don't accept keystroke commands.
 */
keyer	arwktab[]	=	{
		{CGO_UP, jogup},
		{CGO_DOWN, jogdown},
		{CGO_LEFT, jogleft},
		{CGO_RIGHT, jogright},
		{0, NULL},
};



/* The following routines move the cursor.
 * If the cursor is still in the window, they update the
 * cursor location in the window's data structure.
 */
jogup(w,k)
gwindow	*w;
key		k;
{
	if (w->wcur_row > 1) {
		w->wcur_row--;
		}
	jogcursor(1);
}

jogdown(w,k)
gwindow	*w;
key		k;
{
	if (w->wcur_row < w->wheight) {
		w->wcur_row++;
		}
	jogcursor(2);
}

jogleft(w,k)
gwindow	*w;
key		k;
{
	if (w->wcur_col > 1) {
		w->wcur_col--;
		}
	jogcursor(3);
}

jogright(w,k)
gwindow	*w;
key		k;
{
	if (w->wcur_col < w->wwidth) {
		w->wcur_col++;
		}
	jogcursor(4);
}



/* ddokey is the lookup routine for interpreting keys.
 * It searches a table of keyer entries for one that matches the
 * given key.  If a match is found, it calls the corresponding
 * routine and returns TRUE.  Otherwise returns FALSE.
 * The end of the table is marked by an entry with a keychar = 0 or -1.
 * If it is -1, the proc in that entry will be called with the key,
 * and TRUE is returned.  If it is 0, the no-match status is returned.
 */
int ddokey(w, k, ktab)
gwindow	*w;		/* Window */
key	k;		/* Key to handle */
keyer	*ktab;		/* Table of handling procedures */
{
	int	cmd;

	cmd = (k >> CMDSHIFT) & CMDMASK;
	for ( ; ktab->keychar != 0 ; ktab++ )  {
		if (ktab->keychar == cmd  ||  ktab->keychar == -1)  {
			(*(ktab->keyproc))(w, (k & CHARM));
			return(TRUE);
			}
		}

	return(FALSE);
}



/* Lookup and call a keyproc in the window's key handling table.
 */
dokey(w, k)
gwindow		*w;
key			k;
{
	return(ddokey(w, k, w->wkeyprocs));
}
