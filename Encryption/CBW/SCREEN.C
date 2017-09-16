/* Screen interface package
 *
 * Author: Bob Baldwin  June 1983
 * $Date: 86/01/15 16:04:16 $
 * $Log:	screen.c,v $
 * Revision 1.1  86/01/15  16:04:16  baldwin
 * Initial revision
 * 
 * Much code moved to terminal.c  baldwin 10/86
 *
 * Revision 1.2  85/01/10  02:35:10  simsong
 * Changed to termcap support
 * 
 * Revision 1.1  85/01/09  23:45:10  simsong
 * Initial revision
 * 
 */


/* The screen consists of 24 lines and 80 columns.  The basic screen
 * operation is replacing the character that is already at a given
 * position with a new character.  That is, characters are placed,
 * they are not inserted.
 *
 * Various commands are provided for positioning the cursor, placing
 * strings on the screen, and removing characters.
 *
 * If a routine finds something wrong or inconsistent, it will print
 * an error message on the screen.
 */


#include <stdio.h>
#include <strings.h>
#include "window.h"
#include "terminal.h"
#include "specs.h"



/* These variables contain the current location of the cursor.
 * The origin, or home, of the  cursor is in the upper lefthand
 * corner of the screen.  That location is line 1, column 1.
 * The lower righthand corner of the screen is the location
 * identified by line 24, column 80.
 */

int	cline;
int	ccolumn;

/* These must be 24 and 80 since only that region of the screen
 * is covered by the windows.  The wl_driver() routine will
 * exit if the cursor moves out of that area.
 */
int	MXLINE = MAXHEIGHT;	    /* Max line number */
int	MXCOL = MAXWIDTH;	    /* Max column number */



/* Clear Screen.  This should be the first screen operation called in order
 * to initialize the line and column locations.
 */
clrscreen()
{
	enter_mode(SMNORMAL);
	Puts(erase_scr);			    /* clear the screen */
	cline = 1;
	ccolumn = 1;
}


/* Set Cursor Position.  The next character places on the screen
 * will appear in the given line and column.
 *
 * Note: Bob's code is broken in that it assumes the screen goes
 * from 1..24 and 1..80, rather than 0..23 and 0..79. So this
 * routine subtracs one before it calls the curses routine.
 */
setcursor(line, column)
int	line, column;		/* ranges: 1..24 and 1..80 inclusive */
{
	if (line < 1 || line > MXLINE  ||  column < 1 || column > MXCOL)  {
		disperr("setcursor tried to move cursor off screen");
		return;
		}

	cline = line;
	ccolumn = column;
	
	enter_mode(SMNORMAL);
	Puts(tgoto(cm,column-1,line-1));
}


/* Return the row location of the cursor (1 is in upper-left corner).
 */
rowcursor()
{
	return(cline);
}


/* Return the row location of the cursor (1 is in upper-left corner).
 */
colcursor()
{
	return(ccolumn);
}



/* Get Cursor Position
 * The value returned equals 256*LineNumber + ColumnNumber
 */
int	getcursor()
{
	return((cline<<8)+ccolumn);
}


/* Jog the Cursor one position
 * The value of dir determines the direction of travel:
 * 1 = up, 2 = down, 3 = left, 4 = right.  A value other than one of those
 * four will cause an error message to be printed.
 */
/* of course, there is a more ellegant way to implement this */

jogcursor(dir)
int	dir;
{
	switch(dir) {
		case 1:	cline = (cline<=1) ? 1 : cline-1;
			break;
		case 2:	cline = (cline >= MXLINE) ? MXLINE : cline+1;
			break;
		case 3:	ccolumn = (ccolumn <= 1) ? 1 : ccolumn-1;
			break;
		case 4:	ccolumn = (ccolumn >= MXCOL) ? MXCOL : ccolumn+1;
			break;
		default:
			disperr("jogcursor arg out of range");
			return;
		}

	setcursor(cline, ccolumn);
}


/* Place String on the current line.  The cursor is advanced to the
 * position after the last character in the string, unless we hit the
 * edge of the screen in which case the cursor stays pinned to the
 * edge and doesn't move beyond it.
 */
plstring(s)
char	*s;
{
	for ( ; *s != NULL ; s++)  {
		putsym((*s) & 0377);
	}
	ccolumn += strlen(s);
	if (ccolumn >= MXCOL)
	  	ccolumn = MXCOL;	/* Assumes no wrap-around. */
}


/* Place a number of Spaces
 * This routine can also be used to erase characters on the screen by
 * overwriting them with spaces.
 */
plnspaces(n)
int	n;
{	int	i;
	if (n < 0)  {
		disperr("plnspaces: negative arg");
		return;
		}

	for (i = 0 ; i < n ; i++)  {
		putsym(' ');
		}
	ccolumn += n;
	if (ccolumn >= MXCOL)
	  	ccolumn = MXCOL;
}


/* Place a Number of a given Character
 */
plnchars(n, c)
int	n;
int	c;
{	
	int	i;
	if (n < 0)  {
		disperr("plnchars: negative arg");
		return;
		}

	for (i = 0 ; i < n ; i++)  {
		putsym(c);
		}
	ccolumn += n;
	if (ccolumn >= MXCOL)
	  	ccolumn = MXCOL;
}


/* Vertical place a Character a Number of times.
 * This routine can be used to draw vertical lines using
 * a given character.  It correctly handles displaying
 * in column 80.
 * The cursor is moved to the position below the last character
 * placed on the screen.  However the cursor will not move below
 * the last line on the screen.
 */
vertnchars(n,c)
int	n;
int	c;
{
	int	i;
	if (n < 0)  {
		disperr("vertnchars: negative arg");
		return;
		}

	for (i = 0 ; i < n ; i++)  {
		putsym(c);
		/* Assume cursor motion ok even in graphic mode. */
		setcursor(++cline, ccolumn);
		if (cline >= MXLINE)  {
			cline = MXLINE;
			break;
			}
		}
}


/* Delete characters after the cursor up until the End Of the Line
 */
deleol()
{
	Puts(erase_eol);
}


/* Delete characters after the cursor up until the End Of the Screen
 */
deleos()
{
	Puts(erase_eos);
}


/* Display Error message.  The message is a string that does not end
 * with a \n.
 */
disperr(s)
char	*s;
{	int	sline, scolumn;		/* Saved line and column numbers. */

	sline = cline;
	scolumn  = ccolumn;

/*	setcursor(1, 1);	 avoid bug when screen size unknown. */
	printf("\n%s\n", s);
/*	setcursor(sline, scolumn);  or position not set. */
}


/* Put a string to stdout without trailing newline.
 */
Puts(s)
char *s;
{
	while(*s)
		putchar(*s++);
}
