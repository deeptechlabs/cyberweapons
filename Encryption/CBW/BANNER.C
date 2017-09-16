/*
 * Banner window abstraction.  Just a title text with default behavior.
 *
 * Robert W. Baldwin,  December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"layout.h"


/* Window for the title banner. */

displine	banline1 = {
			1,1,			/* Origin. */
			1,MAXWIDTH,		/* Height and width. */
			1,1,			/* Initial cursor position */
			NULL,			/* No private data. */
			wl_setcur,		/* Firstime = Set cursor to current value. */
			wl_noop,		/* Lasttime = do nothing. */
			wl_dldraw,		/* Default dispaly line draw routine. */
			dokey,			/* Default keystroke handler. */
			arwktab,		/* Basic arrow keystroke handler. */
			1,MAXWIDTH,		/* Min and Max column for cursor in line. */
			};

displine	*banlines[] = {
			&banline1,		/* List of display lines for the banner. */
			NULL,
			};

twindow		banner = {
			1,1,			/* Origin. */
			1,MAXWIDTH,		/* Height and width. */
			1,1,			/* Initial cursor position */
			NULL,			/* No private data. */
			wl_setcur,		/* Firstime = accept current cursor position. */
			wl_noop,		/* Lasttime = do nothing. */
			wl_twdraw,		/* Simple draw routine. */
			dokey,			/* Default keystroke handler. */
			arwktab,		/* Basic arrow keystroke handler. */
			banlines,
			};



/* Initialize the banner window and return a pointer to it.
 * Fill in the banner text.
 */
gwindow *(ibanner())
{
	displine	*line;
	int			i;

	line = banner.dlines[0];
	clrdline(line);
	setndline(line, BANTEXT, BANLM);
	return ((gwindow *) &banner);
}
