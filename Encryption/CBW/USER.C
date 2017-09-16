/*
 * User status and command window.
 *
 * Robert W. Baldwin, December 1984.
 *
 * Bob Baldwin 10/86.
 *  Formatting changes.
 *  Change usrdown to fix screen fall off bug.
 *  Change usrfirst to fix cursor pos so jumpcmd() works.
 */


#include	<stdio.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"
#include	"parser.h"


#define	DONEMSG	 "Command completed."
#define	USRHLP	1		/* Offset for help line. */
#define	USRSTAT	2		/* Offset for status line. */
#define	USRCMD	3		/* Offset for command line. */


/* Global space to build status messages. */
char	statmsg[MAXWIDTH+1];


extern	int	usrfirst();	/* Defined below. */
extern	int	usrdokey();	/* Defined below. */
extern	int	usrdraw();	/* Defined below. */
extern	int	usrup();	/* Defined below. */
extern	int	usrdown();	/* Defined below. */


/* Command table. */
#define USRHTEXT \
"bigram, knit, prop, load, save, lookup, clear, equiv, auto-tri, pword"

cmdent	usrcmdtab[] = {
		{"quit-program permanently", quitcmd},
{"auto-trigram max_dev: % min_total_chars: % min_wire_chars: %", atrguess},
		{"knitting using blocks from: % to: %  Min show count: %", kntguess},
		{"lookup-pattern: % in dictionary", webmatch},
		{"equivalence-class guess, use accept level: % (try 2.0)", ecbguess},
		{"pwords-from file: %  Max dev: % (try 1.0)", pwdguess},
		{"load-permutations", permload},
		{"save-permutations", permsave},
		{"clear-zee permutation", clearzee},
		{"propagate-info from: % to: % using Zee", pgate},
		{"bigram-guess level: % (2.0), min_prob: % (0.15)", lpbguess},
		{0, NULL},
		};


/* Keystroke table for the user area. */
extern	usrdocmd();

/* Keystroke table for the whole user window.
 * The editing on the command line is handled by a sub-window.
 */
keyer	usrktab[] = {
		{CGO_UP, usrup},	/* Keep off help and status lines. */
		{CGO_DOWN, usrdown},	/* Normal behavior ok. */
		{CEXECUTE, usrdocmd},	/* Interprete a command. */
		{0, NULL},		/* Handle other chars elsewhere. */
		};

/* Keystroke table for the command line sub-window.
 */
keyer	cmdktab[] = {
                {CNEXTARG, wl_nxtarg},
		{CGO_LEFT, wl_dlleft},	/* Stay withing variable area. */
		{CGO_RIGHT, wl_dlright},/* Stay withing variable area. */
		{CDELF, wl_dlfdel},	/* Delete forward within var area. */
		{CDELB, wl_dlbdel},	/* Delete backward within var area. */
		{CCLRLINE, wl_dlclr},	/* Clear variable area. */
		{CINSERT, wl_dlinsert},	/* All other chars self-insert. */
		};


/* Window for the user commands and program status. */

displine usraline[USRHEIGHT];		/* Display lines for the user. */
displine *usrlines[USRHEIGHT+1];	/* Pointers to them plus NULL. */

twindow	user = {
		USRROW,1,		/* Origin. */
		USRHEIGHT, USRWIDTH,	/* Height and width. */
		USRCMD+1, USRSCOL,	/* Initial (relative) cursor pos. */
		NULL,			/* No private data. */
		usrfirst,		/* Firstime = restore cursor pos. */
		wl_noop,		/* Lasttime = do nothing. */
		usrdraw,		/* Default draw routine. */
		usrdokey,		/* Custom keystroke handler. */
		usrktab,		/* Keystroke table. */
		usrlines,
};



/* Display a string in the status area.
 * If the string is empty, this will clear the status area.
 * Put the cursor back where it was.
 *
 * The empty string is special case.  If the status line is
 * empty, then wcur_col = 1.  A second request to clear
 * the line is ignored.
 * If the line is not empty, wcur_col = dl_min_col.
 */
usrstatus(w, str)
twindow	*w;
char	*str;
{
	displine *line;
	int	 row, col;
	
	row = rowcursor();
	col = colcursor();

	line = w->dlines[USRSTAT];
	if (*str == 0  &&  line->wcur_col == 1)
	  	return;

	dlsetvar(line, str);
	(*(line->wredraw))(line);
	setcursor(row, col);

	line->wcur_col = (*str == 0) ? 1 : 2;
}



/* Display a string in the help area.
 * If the string is empty, this will clear the help area.
 * Put the cursor back where it was.
 */
usrhelp(w, str)
twindow	*w;
char	*str;
{
	displine *line;
	int	 row, col;
	
	row = rowcursor();
	col = colcursor();

	line = w->dlines[USRHLP];
	dlsetvar(line, str);
	(*(line->wredraw))(line);

	setcursor(row, col);
}



/* Draw the user area.
 * Leaves the cursor on the command line.
 */
usrdraw(w)
twindow	*w;
{
	wl_twdraw(w);
}



/* Make a window with a title and partial outline.
 */
gwindow *(iuser())
{
	int	 i;
	displine *line, *lines;
	twindow	 *w;

	w = &user;
	lines = usraline;
	for (i = 0 ; i < w->wheight ; i++)  {
		line = &lines[i];
		line->worg_row = w->worg_row + i;
		line->worg_col = w->worg_col;
		line->wheight = 1;
/* Fix bug on terminals that autowrap. */
		line->wwidth = (i == USRCMD) ? w->wwidth - 1 : w->wwidth;
		line->wcur_row = 1;
		line->wcur_col = USRSCOL;
		line->wfirst = wl_rcursor;
		line->wlast = wl_noop;
		line->wredraw = wl_dldraw;
		line->wkey = dokey;
		line->wkeyprocs = arwktab;
		line->dl_min_col = USRSCOL;
		line->dl_max_col = line->wwidth;
		clrdline(line);
		w->dlines[i] = line;
		}
	w->dlines[i] = NULL;

	line = &lines[USRHLP];
	setadline(line, "Help   : This feature not implemented");
	line = &lines[USRSTAT];
	setadline(line, "Status : ");
	dlsetvar(line, "Just barely working");
	line = &lines[USRCMD];
	setadline(line, "Command: ");
	line->wkeyprocs = cmdktab;

	return((gwindow *) w);
}


/* Behavior of the up arrow key.
 * Move up to the window above us staying in the same column.
 */
usrup(w, k)
twindow	*w;		/* The user window. */
key	k;
{
	wl_setcur(w, 1, w->dlines[USRCMD]->wcur_col);
	jogup(w, k);
}


/* Behavior of the down arrow key.
 * Move to command line.
 */
usrdown(w, k)
twindow	*w;		/* The user window. */
key	k;
{
	wl_setcur(w, USRHEIGHT, w->dlines[USRCMD]->wcur_col);
}


/* Behavior when cursor first enters the user window.
 * Move to the command line.
 */
usrfirst(w, row, col)
twindow	*w;
int	row, col;	/* Place in window when cursor currently is. */
{
	displine *cmdline;

	wl_setcur(w, USRHEIGHT, w->dlines[USRCMD]->wcur_col);
	usrhelp(w, USRHTEXT);
	cmdline = w->dlines[USRCMD];
	(*(cmdline->wfirst))(cmdline, 1, col);
}


/* Keystroke handler for user window.
 * If it is not an up-arrow or down-arrow, pass it to the command line.
 */
usrdokey(w, k)
twindow	*w;		/* The user window. */
key	k;
{
	char	 *expanded;	/* Expanded command line. */
	char	 cmdbuf[MAXWIDTH+1];
	displine *cmdline;

	cmdline = w->dlines[USRCMD];
	usrstatus(&user, "");
	if (ddokey(w, k, w->wkeyprocs))  {  /* If handled by top window. */
		return;			    /* Includes doit key. */
	}

	if (k == ((CINSERT << CMDSHIFT) | SPACE))  {
		dlgetvar(cmdline, cmdbuf);
		expanded = cmdcomplete(usrcmdtab, cmdbuf);
		if (expanded != NULL)  {
			dlsetvar(cmdline, expanded);
			wl_dldraw(cmdline);
			return;
			}
		}
	(*(cmdline->wkey))(cmdline, k);	/* Else pass to sub-window. */
}


/* Interprete a command.
 */
usrdocmd(usr)
twindow	*usr;
{
	char	 cmdbuf[MAXWIDTH+1];
	char	 *errmsg;
	displine *cmdline;

	cmdline = usr->dlines[USRCMD];
	wl_setcur(usr, usr->wcur_row, cmdline->wcur_col);
	dlgetvar(cmdline, cmdbuf);
	if ((errmsg = cmddo(usrcmdtab, cmdbuf)) == NULL)
		errmsg = DONEMSG;
	usrstatus(&user, errmsg);
}
