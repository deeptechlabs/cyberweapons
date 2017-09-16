/* 
 * Structure definitions for the window and keyboard routines.
 * The first half of this file contains structure declarations.
 * The second half contains functions, static variables, and
 * key value declarations.
 *
 * Robert W. Baldwin,  December 1984
 */


/* Parameters */

#define	MAXWIDTH	80		/* Max width of a display line. */
#define	MAXHEIGHT	24		/* Max height of a window. */


/* Key stroke handler structure.
 * The table is searched to find a key that matches the command typed
 * by the user.  The corresponding keyproc is then invoked.
 * The last entry in the table can have keychar == 0  or  -1.
 * If it is -1, that entry's corresponding
 * procedure is invoked with any characacter not previously matched.
 * If it is 0, then the table driver knows it should look at 
 * another table (if any).
 * See terminal.h and .c for more info on command keys.
 */

#define	key	int		/* Command code in high byte, arg in low. */
#define	keyer	struct xkeyer	/* Typically have a table of these. */

struct	xkeyer	{
	key	keychar;	/* Must be -1 or 0 for last entry in table. */
	int	(*keyproc)();	/* Called with: window and key arg. */
	};


/* Common window definition. */

#define zwindow \
	int	worg_row;	/* Row and column of the upper lefthand corner */\
	int	worg_col;	/* of this window in global screen coordinates */\
	int	wheight;	/* Number of rows in window. */\
	int	wwidth;		/* Number of columns. */\
	int	wcur_row;	/* Location of cursor relative to the origin. */\
	int	wcur_col;	/* Equals (1,1) if at window's origin. */\
	char	*wprivate;	/* Ptr to window's private data. */\
	int	(*wfirst)();	/* Called when cursor enters window. */\
	int	(*wlast)();	/* Called after cursor leaves window. */\
	int	(*wredraw)();	/* Called to redraw window over junk. */\
	int	(*wkey)();	/* Called when key pressed and window is active*/\
	keyer	*wkeyprocs	/* Procs that perform key stroke actions. */


/* Specification of window procedures. */

/* The follow declarations are assumed: gwindow *w;  key k;  keyer *ktab;
 * int	currow, curcol;  (cursor location in local coordinates).
 *
 * wfirst(w, currow, curcol)
 *    Called when cursor first enters window,
 *	  Responsible for setting w->wcur_row, w->wcur_col to desired value.
 *	  The display's cursor is already at the given coordinates.
 *
 * wlast(w)
 *    Called when the driving loop notices that the cursor is no longer
 *    in the currently active window.  Responsible for any cleanup needed
 *    before another window can become active.
 *
 * wredraw(w)
 *    Called to cleanup junk on the screen, usually at the user's request.
 *    The routine should set every character within its window.
 *	  It should leave the cursor at some reasonable place, such as the
 *    place it last was within this window.
 *
 * wkey(w, k)
 *    Called when a key is pressed, and this window is active.
 *    Responsible for performing the desired action.  Sub-windows
 *    can assume that common keystrokes (like arrow movement) have
 *    already been handled.
 */

/* General purpose window. */

#define	gwindow		struct	xgwindow

struct 	xgwindow	{
	zwindow;
	};


/* Display line for fixed and editable strings. */

#define	displine	struct	xdispline

struct	xdispline	{
	zwindow;
	int	dl_min_col;	/* Min location of cursor relative to origin */
	int	dl_max_col;	/* Max location of cursor relative to origin */
	int	dl_length;	/* Last non-blank column in line. */
	char	dl_chars[MAXWIDTH+1];	/* Null terminated string whose len */
					/*  always == the width of the line. */
	};


/* Window containing changeable lines of text. */

#define	twindow		struct	xtwindow

struct	xtwindow	{
	zwindow;
	displine	**dlines;	/* Null terminated array of lines. */
	};


/* Procedures from windowlib.c */

extern	int	wl_driver(/* wtab */);	/* Run window system. */
extern	int	wl_refresh(/* wtab */);	/* Redraw all windows. */
extern	int	wl_rcursor(/* w */);	/* Restore old cursor position. */
extern	int	wl_setcur(/* w, row, col */);	/* Set cursor relative. */
extern	int	wl_noop(/* w */);	/* Do nothing. */
extern	int	wl_hascur(/* w */);	/* Return TRUE if cursor in window. */
extern	int	wl_draw(/* w */);	/* Invoke window's redraw routine. */
extern	int	wl_twdraw(/* w */);	/* Redraw for twindow. */
extern	int	wl_dldraw(/* w */);	/* Redraw for displine. */
extern	wl_dlleft(/* w */), wl_dlright(/* w */);
extern	wl_dlfdel(/* w */), wl_dlbdel(/* w */), wl_dlclr(/* w */);
extern	wl_dlinsert(/* w, k */);
extern	wl_dlgetvar(/* w, buf */);	/* Fill buf with variable part. */
extern	wl_dlsetvar(/* w, str */);	/* Set variable part from string. */
extern	wl_nxtarg(/* line */);		/* Adv to next %. */
extern	int	clrdline(/* dl */);	/* Blankout all chars in displine. */
extern	int	setdline(/* dl */);	/* Set first chars of displine. */
extern	int	wl_erase(/* w */);	/* Blank out a window. */
extern	int	wl_outline(/* w */);	/* Outline w/o changing insides. */
extern	int	key2graphic(/* c */);	/* Returns key to represent char c. */


/* Procedures from keylib.c */
extern	int	getkey();		/* Get a key stroke from the user. */
extern	int	dokey(/* w, k */);	/* Invokes window's keyproc for k. */
extern	int	ddokey(/* w,k,ktab */);	/* Invokes keyproc for k found in ktab. */
extern	int	noopkey(/* w, k */);	/* A do-nothing keyproc. */


/* These four routines move the cursor and if it is still within
 * the window, w, they update the window's cursor position field.
 * They can be used as keyprocs.
 */
extern	int	jogleft(/* w, k */);
extern	int	jogright(/* w, k */);
extern	int	jogup(/* w, k */);
extern	int	jogdown(/* w, k */);


/* Static variables from keylib.c */

extern	keyer	arwktab[];		/* Default key table for arrow keys. */
					/* They call the correct jog routine */



/* ASCII character definitions
 */
#define	CNTRL		037
#define CTRL_P		(CNTRL & 'P')
#define CTRL_N		(CNTRL & 'N')
#define CTRL_B		(CNTRL & 'B')
#define CTRL_F		(CNTRL & 'F')
#define CTRL_C		(CNTRL & 'C')   /* added by slg */
#define	RETURN		(CNTRL & 'M')
#define	LINEFEED	(CNTRL & 'J')
#define	TAB		(CNTRL & 'I')
#define	SPACE		(' ')

