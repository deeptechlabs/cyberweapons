/*
 * Library of display line routines.
 *
 * Robert W. Baldwin, December 1984.
 */

#include	<stdio.h>
#include	"window.h"
#include	"specs.h"


/* After clrdline is called the routines assume that there is
 * a null character terminating the string at index w->wwidth.
 * That is, the length of the display string is always equal
 * the the (fixed) width of the line.
 * The dl_length field behaves like the apparent string length.
 * It is the column location of the last non-blank character.
 * That is, an all blank line has a length of zero.
 */

/* INTERNAL PROCEDURES */

/* Set the range of positions between firstcol and lastcol (inclusive) to
 * the given string.  The string is padded on the right with spaces
 * or truncated to make it fill the interval.
 */
setarange(line, str, firstcol, lastcol)
displine	*line;
char		*str;
int			firstcol, lastcol;
{
	int		i;

	line->dl_length = 0;
	for (i = firstcol-1 ; i < lastcol ; i++)  {
		if (*str == 0)  break;
		if (*str != ' ')  line->dl_length = i+1;
		line->dl_chars[i] = *str++;
		}

	for ( ; i < lastcol ; i++)  {
		line->dl_chars[i] = ' ';
		}

	line->dl_chars[i] = '\000';
}



/* PUBLIC PROCEDURES */



/* Set the line from column, col, onward to the given string,
 * padding with blanks if needed.  Note col = 1, set the whole line.
 * This cannot be used to initialize a display line.  It does not
 * set the character preceeding col.
 */
setnadline(line, str, col)
displine	*line;
char		*str;
int			col;
{
	setarange(line, str, col, line->wwidth);
}


/* Blank out all the characters in a displine.
 */
clrdline(line)
displine	*line;
{
	line->dl_length = 0;
	setarange(line, "", 1, line->wwidth);
}


/* Set the entire displine to the given string, padding with blanks.
 * This fills in the null termination, so it can be used to initialize
 * a display line.
 */
setadline(line, str)
displine	*line;
char		*str;
{
	line->dl_length = 0;
	setarange(line, str, 1, line->wwidth);
}


/* Set characters in the given range to the string, truncating 
 * if necessary.  Do not pad with blanks, just avoid overflowing
 * the range.
 */
setrange(line, str, firstcol, lastcol)
displine	*line;
char		*str;
int			firstcol, lastcol;		/* Inclusive interval. */
{
	int		i;
	int		newlength;

	newlength = 0;
	for (i = firstcol-1 ; i < lastcol ; i++)  {
		if (*str == 0)  return;
		if (*str != ' ')  newlength = i+1;
		line->dl_chars[i] = *str++;
		}

	if (newlength > line->dl_length)  line->dl_length = newlength; 
}



/* Starting at column, col, set the characters in the display line, line,
 * to the given string, str.
 * This differs from setnadline because it does not pad the line with blanks.
 * Overflows are avoided by truncation.
 * Note that col is a one-based position, not zero-based as strings are.
 * This cannot be used to initialize a line, since it does not set the
 * characters before column col.
 */
setndline(line, str, col)
displine	*line;
char		*str;
int			col;
{
	setrange(line, str, col, line->wwidth);
}


/* Set the variable part of the line (between min and max_col) to
 * the given string.  Pad with blanks.
 */
dlsetvar(line, str)
displine	*line;
char		*str;
{
	setarange(line, str, line->dl_min_col, line->dl_max_col);
}



/* Fill the given buffer from the given range of column positions.
 * Trailing blanks are not removed.
 */
getrange(line, buf, firstcol, lastcol)
displine	*line;
char		*buf;
int			firstcol, lastcol;
{
	int		i;

	for (i = firstcol-1 ; i < lastcol ; i++)  {
		*buf++ = line->dl_chars[i];
		}
	*buf = '\000';
}


/* Fill the given character buffer with a null terminated string
 * corresponding to the part of the dline between the min and max
 * column positions.  Trailing blanks are not removed.
 */
dlgetvar(line, buf)
displine	*line;
char		*buf;
{
	getrange(line, buf, line->dl_min_col, line->dl_max_col);
}



/* EDITING PROCEDURES */


/* Insert the given character at the current cursor position.
 * Do nothing if the line would become too long.
 * Do nothing if the character is not printable.
 * The cursor moves to the right one column, provided it doesn't
 * move past dl_max_col.
 */
dlinsert(line, k)
displine	*line;
key			k;
{
	char	restbuf[MAXWIDTH+1];		/* Char from cursor to end. */
	char	insbuf[2];					/* Char to insert. */

	if (line->dl_length >= line->wwidth)  return;
	if (!printable(k))  return;

	getrange(line, restbuf, line->wcur_col, line->wwidth);

	insbuf[0] = k;
	insbuf[1] = '\000';
	setrange(line, insbuf, line->wcur_col, line->wcur_col);

	setrange(line, restbuf, line->wcur_col+1, line->wwidth);

	dlright(line);
}


/* Delete the character at the current cursor position and
 * shuffle down the rest of the line.
 * The cursor doesn't move.
 * The non-blank length is correctly maintained.
 */
dldelete(line)
displine	*line;
{
	char	*p;
	char	linebuf[MAXWIDTH+1];		/* Rebuild whole line here. */

	getrange(line, linebuf, 1, line->wcur_col-1);

	for (p = linebuf ; *p != '\000' ; p++);	/* p pts to end of line. */
	getrange(line, p, line->wcur_col+1, line->wwidth);
	
	setadline(line, linebuf);
}


/* Move the cursor right within min and max column.
 */
dlright(line)
displine	*line;
{
	if (line->wcur_col+1 <= line->dl_max_col)
		line->wcur_col++;
}


/* Move the cursor left within min and max column.
 */
dlleft(line)
displine	*line;
{
	if (line->wcur_col-1 >= line->dl_min_col)
		line->wcur_col--;
}



/* DISPLAY UPDATING PROCEDURES */


/* Redraw routine for a display line.
 */
wl_dldraw(dline)
displine	*dline;
{
	int		oldcolumn;

	oldcolumn = dline->wcur_col;

	wl_setcur(dline, 1, 1);
	plstring(dline->dl_chars);
	wl_setcur(dline, 1, oldcolumn);
}


/* Insert a character an redisplay the line.
 */
wl_dlinsert(line, k)
displine	*line;
key			k;
{
	dlinsert(line, k);
	wl_dldraw(line);
}


/* Delete the current character an redisplay the line.
 */
wl_dlfdel(line, k)
displine	*line;
key			k;
{
	dldelete(line, k);
	wl_dldraw(line);
}


/* Delete the previous character an redisplay the line.
 * The cursor moves backwards one position.
 */
wl_dlbdel(line, k)
displine	*line;
key			k;
{
	if (line->wcur_col == line->dl_min_col)  return;

	dlleft(line);
	dldelete(line, k);
	wl_dldraw(line);
}


/* Move cursor right and update display.
 */
wl_dlright(line)
displine	*line;
{
	dlright(line);
	wl_rcursor(line);
}


/* Move cursor left and update display.
 */
wl_dlleft(line)
displine	*line;
{
	dlleft(line);
	wl_rcursor(line);
}


/* Clear the variable part of the display line and update the display.
 */
wl_dlclr(line)
displine	*line;
{
	dlsetvar(line, "");
	line->wcur_col = line->dl_min_col;
	wl_dldraw(line);
}


/* Scan for the first argument place holder, '%',
 * position the cursor there, and delete it.
 * Do nothing if the line doesn't contain a '%'.
 */
wl_nxtarg(line)
displine	*line;
{
	int		i;

	for (i = line->dl_min_col-1 ; i < line->dl_max_col ; i++) {
		if (line->dl_chars[i] != '%') continue;
		wl_setcur(line, 1, i+1);
		wl_dlfdel(line);
		break;
		}
}
