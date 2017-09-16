/*
 * Pattern matching on words in a dictionary.
 * Patterns are entered as command arguments and results are
 * displayed in this window.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"


#define	DICTNAME	"/usr/dict/words"
#define	DICTVAR		"DICTIONARY"	/* Name of shell var. */
#define	WEBHELP		"Word match is invoked using the 'lookup' command"
#define	TOPINDEX	2
#define	BOTINDEX	(WEBHEIGHT-2)

extern	int	wordsim();	/* Defined below. */
extern		web_first();	/* Defined below. */

/* Strings for outlining the window.
 */
char	*webhead = "| Word Match";
char	*webpane = "|";
char	*webbot  = "`-------------------------";

/* Window for the list of matches. */

displine webaline[WEBHEIGHT];		/* Display lines for the history. */
displine *weblines[WEBHEIGHT+1];	/* Pointers to them plus NULL. */

twindow  webster = {
		WEBROW,WEBCOL,		/* Origin. */
		WEBHEIGHT,WEBWIDTH,	/* Height and width. */
		1,1,			/* Initial (relative) cursor pos. */
		NULL,			/* No private data. */
		web_first,		/* Firstime = accept cursor pos. */
		wl_noop,		/* Lasttime = do nothing. */
		wl_twdraw,		/* Default draw routine. */
		dokey,			/* Default keystroke handler. */
		arwktab,		/* Basic arrow keystroke handler. */
		weblines,
};



/* Make a window with a title and partial outline.
 */
gwindow *(iwebster())
{
	int		i;
	displine	*line;

	webgraphics(webhead);
	webgraphics(webpane);
	webgraphics(webbot);

	for (i = 0 ; i < WEBHEIGHT ; i++)  {
		line = &webaline[i];
		line->worg_row = webster.worg_row + i;
		line->worg_col = webster.worg_col;
		line->wheight = 1;
		line->wwidth = webster.wwidth;
		line->wcur_row = 1;
		line->wcur_col = 1;
		line->wfirst = wl_noop;
		line->wlast = wl_noop;
		line->wredraw = wl_dldraw;
		line->wkey = dokey;
		line->wkeyprocs = arwktab;
		line->dl_min_col = 2;
		line->dl_max_col = webster.wwidth;
		setadline(line, webpane);
		webster.dlines[i] = line;
		}
	webster.dlines[i] = NULL;

	line = &webaline[0];
	setadline(line, webhead);
	line = &webaline[i - 1];
	setadline(line, webbot);	/* Truncates to fit. */
	return((gwindow *) &webster);
}


/* Convert a default graphic chars to fancy graphics chars
 * in the given string.
 */
webgraphics(str)
char	*str;
{
	for ( ; *str != NULL ; str++)  {
		switch (*str)  {
		  default:
			break;

		  case '|':
			*str = SVERTBAR;
			break;

		  case '-':
			*str = SHORZBAR;
			break;

		  case '`':
			*str = SLLCORNER;
			break;
		}
	}
}


/* Command to lookup word pattern in dictionary.
 * The pattern contains letters and dots.  The dots match any character.
 */
char *webmatch(args)
char	*args;
{
	char	*p, *w;		/* Pattern and word pointers. */
	char	patbuf[MAXWIDTH+1];
	char	wordbuf[MAXWIDTH+1];
	int	i;
	char	*bufptr;
	int	row,col;
	FILE	*fd;
	displine *line;
	int	nextline;	/* Index of next line to put result. */
	char	*dictfile;
	extern	char	*getenv();

	row = rowcursor();
	col = colcursor();

	if ((i = sscanf(args,"%*[^:]: %s", patbuf)) != 1) {
		sprintf(statmsg, "Error, got %d args not 1. From: %s", i,args);
		return(statmsg);	/* Beware: this returns a pointer to the stack. */
		}
	line = webster.dlines[TOPINDEX-1];
	dlsetvar(line, patbuf);

	for (nextline = TOPINDEX ; nextline <= BOTINDEX ; nextline++) {
		line = webster.dlines[nextline];
		dlsetvar(line, "");
		}
	wl_draw(&webster);
	setcursor(row, col);
	fflush(stdout);

	dictfile = getenv(DICTVAR);
	if (dictfile == NULL)
	  	dictfile = DICTNAME;

	if ((fd = fopen(dictfile, "r")) == NULL)  {
		sprintf(statmsg, "Could not open %s to read dictionary.",
			dictfile);
		return(statmsg);
		}

	for (nextline = TOPINDEX ; nextline <= BOTINDEX ; nextline++) {
		line = webster.dlines[nextline];
		while (TRUE) {
			bufptr = fgets(wordbuf, MAXWIDTH+1, fd);
			if (bufptr != wordbuf) {
				wordbuf[0] = '\000';
				goto alldone;
				}
			if (wordsim(patbuf, wordbuf)) break;
			}
		for (w=wordbuf ; *w != '\n' ; w++) {}
		*w = '\000';
		dlsetvar(line, wordbuf);
		wl_draw(line);
		setcursor(row, col);
		fflush(stdout);
		}

alldone:
	fclose(fd);

	return(NULL);
}


/* Return TRUE if the pattern matches the word
 */
int	wordsim(pattern, word)
char	*pattern;
char	*word;
{
	for ( ; *pattern != 0 && *word != 0 ; ((int)pattern++)|((int)word++)) {
		if (*word == '\n')
		  	return(FALSE);
		if (*pattern == '.')
		  	continue;
		if (*pattern != *word)
		  	return(FALSE);
		}
	if (*pattern == 0 && *word == '\n')
	  	return(TRUE); /* Same length */
	return(FALSE);
}


/* Called when cursor enters the window.
 * Clears the help message and accepts the cursor position.
 */
web_first(w, row, col)
gwindow	*w;
int		row, col;
{
	wl_setcur(w, row, col);
	usrhelp(&user, WEBHELP);
}
