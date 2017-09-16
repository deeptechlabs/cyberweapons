/*
 * Decrytion block and its label.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"


/* Relative layout constants. */

#define	TOPROW		2		/* First non-blank row. */
#define	BOTROW		(TOPROW+2*(NLINES-1))	/* First non-blank row. */
#define DBSHELP	\
	"^G: undo, ^T: tryall, ^W: wrdsrch, F2 F1: next prev block"
#define WIREWIDTH	23	/* Number of chars from WIREFORMAT */
#define WIREFORMAT	"Know %3d of 128 wires  "
#define	WIRECOL		(LINELEN - WIREWIDTH + 1)  /* Starting column. */
#define	BLOCKFORMAT	"Block - %d"

/* Keystroke handler for decryption block storage. */

extern	dbsup(), dbsdown(), dbsleft(), dbsright();
extern	dbskey();
extern	dbsundo();
extern	dbsdelf();
extern	dbsdelb();
extern	dbsnxtblk();
extern	dbsprvblk();
extern	dbstryall();
extern	dbswrdsrch();

keyer	dbsktab[] = {
		{CTRYALL, dbstryall},
		{CWRDSRCH, dbswrdsrch},
		{CNEXTBLOCK, dbsnxtblk},
		{CPREVBLOCK, dbsprvblk},
		{CGO_UP, dbsup},
		{CGO_DOWN, dbsdown},
		{CGO_LEFT, dbsleft},
		{CGO_RIGHT, dbsright},
		{CUNDO, dbsundo},
		{CDELF, dbsdelf},
		{CDELB, dbsdelb},
		{CINSERT, dbskey},
		{CRETURN, dbskey},	/* Special case return key. */
		{0, NULL},
		};



/* Private data for the decryption block storage. */

#include 	"dblock.h"

char	mcbuf[BLOCKSIZE+1];		/* Static buffer for now. */
int	mpbuf[BLOCKSIZE+1];		/* Static buffer for now. */
int	moperm[BLOCKSIZE+1];		/* Static buffer for now. */
char	mmbuf[BLOCKSIZE+1];		/* Static buffer for now. */
int	mcmdbuf[BLOCKSIZE+1];		/* Static buffer for now. */

dbsinfo dbsprivate;



/* Window for the decryption block label. */

displine	dblline1 = {
		DBLROW,1,		/* Origin. */
		1,DBWIDTH,		/* Height and width. */
		1,1,			/* Init (relative) cursor position */
		NULL,			/* No private data. */
		wl_setcur,		/* Firstime = restore cursor pos. */
		wl_noop,		/* Lasttime = do nothing. */
		wl_dldraw,		/* Default dispaly line draw routine */
		dokey,			/* Default keystroke handler. */
		arwktab,		/* Basic arrow keystroke handler. */
		1,DBWIDTH,		/* Min and Max col for cursor. */
};

displine	*dbllines[] = {
		&dblline1,		/* List of lines for the label. */
		NULL,
};

twindow		dblabel = {
		DBLROW,1,		/* Origin. */
		1,DBWIDTH,		/* Height and width. */
		1,1,			/* Init (relative) cursor position */
		NULL,			/* No private info. */
		wl_setcur,		/* Firstime = restore cursor pos. */
		wl_noop,		/* Lasttime = do nothing. */
		wl_twdraw,		/* Simple draw routine. */
		dokey,			/* Default keystroke handler. */
		arwktab,		/* Basic arrow keystroke handler. */
		dbllines,
};


/* Window for the decrytion block. */

extern	int	dbsdraw();
extern	int	dbsfirst();
extern	int	dbslast();

gwindow		dbstore = {
		DBSROW,1,		/* Origin. */
		DBHEIGHT,DBWIDTH,	/* Height and width. */
		TOPROW,1,		/* Initial cursor position */
		((char *)&dbsprivate),	/* Info about current block. */
		dbsfirst,		/* Firstime */
		dbslast,		/* Lasttime */
		dbsdraw,		/* Draw routine. */
		dokey,			/* Default keystroke handler. */
		dbsktab,		/* Arrow keystroke handler. */
};



/* Initialize the decrypted block label, and return a ptr to it.
 */
gwindow	*(idblabel())
{
	displine	*line;

	line = dblabel.dlines[0];
	clrdline(line);
	return ((gwindow *) &dblabel);
}


/* Set the block number in the label.
 * The argument, num, is displayed as it, it is not zero adjusted.
 * The cursor is not moved, and the window is redisplayed.
 */
dblbnum(label, num)
twindow	*label;
int	num;
{
	int	row,col;

	row = rowcursor();
	col = colcursor();

	sprintf(statmsg, BLOCKFORMAT, num);
	setrange(label->dlines[0], statmsg, 1, WIRECOL-1);
	wl_dldraw(label->dlines[0]);
	setcursor(row, col);
}


/* Set the known wire number in the label.
 * The argument, num, is displayed as it, it is not zero adjusted.
 * The cursor is not moved, and the window is redisplayed.
 */
dblpcount(label, num)
twindow	*label;
int	num;
{
	int	row,col;

	row = rowcursor();
	col = colcursor();

	sprintf(statmsg, WIREFORMAT, num);
	setnadline(label->dlines[0], statmsg, WIRECOL);
	wl_dldraw(label->dlines[0]);
	setcursor(row, col);
}



/* Initialize the decryption block storage, and return a ptr to it.
 * Reads in cipher block from the file named by cipherfile.
 * If errors occur, a message is put in the status area.
 */
gwindow	*(idbstore())
{
	gwindow		*dbs;
	dbsinfo		*dbsi;
	FILE		*fd;

	dbs = &dbstore;
	dbsi = ((dbsinfo *) dbs->wprivate);

	dbsi->cbuf = mcbuf;
	dbsi->blknum = 0;
	fillcbuf(dbsi->blknum, dbsi->cbuf);
	dbsi->perm = refperm(dbsi->blknum);
	dbsi->pbuf = mpbuf;
	dbsi->mbuf = mmbuf;
	dbsi->cmdbuf = mcmdbuf;
	dbsi->operm = moperm;

	dbsinit(dbsi);

	return (dbs);
}


/* Initialize the private data.
 * Requires that the cipherblock and permutation have already been loaded.
 * The plaintext is decoded from the ciphertext and permutation.
 * Updates the label display.
 */
dbsinit(dbsi)
dbsinfo	*dbsi;
{
	int		i;

	dbsi->wirecnt = permwcount(dbsi->perm);
	dbsi->cmdloc = 0;
	dbsi->cmdnext = 0;
	dbsi->cmdbuf[0] = 0;
	dblbnum(&dblabel, dbsi->blknum);
	dblpcount(&dblabel, dbsi->wirecnt);

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		dbsi->operm[i] = dbsi->perm[i];
		dbsi->mbuf[i] = FALSE;
		}

	decode(dbsi->cbuf, dbsi->pbuf, dbsi->perm);
}



/* Atomically merge the given permutation into the current one.
 * The current one is not changed if any conflicts are detected.
 * Updates the display and plaintext buffer.
 * Does setup to allow an undo.
 * Return TRUE if suceesful.
 */
int	dbsmerge(dbs, perm)
gwindow	*dbs;		/* Ptr to dbstore */
int	perm[];		/* Permutation */
{
	int	i;
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	/* Check for conflicts, display msg if so. */
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (perm[i] != NONE  &&  dbsi->perm[i] != NONE
		 && perm[i] != dbsi->perm[i]) {
			sprintf(statmsg, "Guess conflicts with current plaintext!");
			usrstatus(&user, statmsg);
			return(FALSE);
			}
		}

	/* Use dbssperm to set the guess.  Save old perm for undo. */
	dbsi->cmdnext = 0;
	dbsi->cmdloc = dbsrc2pos(dbs->wcur_row, dbs->wcur_col);
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		dbsi->operm[i] = dbsi->perm[i];
		}

	dbsrmarks(dbs);
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (perm[i] != NONE  &&  perm[i] > i  &&  dbsi->perm[i] == NONE) {
			dbsswire(dbs, i, perm[i]);
			}
		}

	sprintf(statmsg, "Sucessful merge.");
	usrstatus(&user, statmsg);
	dbsi->wirecnt = permwcount(dbsi->perm);
	dblpcount(&dblabel, dbsi->wirecnt);
	return(TRUE);
}


/* Undo the last command.
 * Copy the old permutation into the current one,
 * recompute the plaintext, and update the display.
 * Move the cursor back to where it was.
 */
dbsundo(dbs)
gwindow	*dbs;
{
	int	i;
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		dbsi->mbuf[i] = FALSE;
		dbsi->perm[i] = dbsi->operm[i];
		}
	decode(dbsi->cbuf, dbsi->pbuf, dbsi->perm);
	dbsdraw(dbs);

	dbsi->wirecnt = permwcount(dbsi->perm);
	dblpcount(&dblabel, dbsi->wirecnt);
	usrstatus(&user, "Command undone.");
	wl_setcur(dbs, dbsp2row(dbsi->cmdloc), dbsp2col(dbsi->cmdloc));
}



/* (re)Draw the window.
 */
dbsdraw(dbs)
gwindow	*dbs;
{
	int	i;
	int	row, col;
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	row = dbs->wcur_row;
	col = dbs->wcur_col;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (i%LINELEN == 0) {
			wl_setcur(dbs, dbsp2row(i), dbsp2col(i));
			}
		plnchars(1, char2sym(dbsi->pbuf[i]));
		}

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (i%LINELEN == 0) {
			wl_setcur(dbs, dbsp2row(i)+1, dbsp2col(i));
			}
		if (dbsi->mbuf[i]) {
			plnchars(1, SUNDERLINE);
			}
		else  {
			plnchars(1, ' ');
			}
		}

	for (i = dbsp2row(BLOCKSIZE) ; i <= DBHEIGHT ; i++) {
		wl_setcur(dbs, i, 1);
		plnchars(LINELEN, ' ');
		}
	for (i = 1 ; i < dbsp2row(0) ; i++) {
		wl_setcur(dbs, i, 1);
		plnchars(LINELEN, ' ');
		}

	for (i = 1 ; i <= DBHEIGHT ; i++) {
		wl_setcur(dbs, i, LINELEN+1);
		plnchars(dbs->wwidth - LINELEN, ' ');
		}

	wl_setcur(dbs, row, col);

}



/* Draw the plaintext characters on the screen.
 * Does not change the cursor position.
 */
dbsdpbuf(dbs)
gwindow	*dbs;
{
	int	i;
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		dbsdpchar(dbs, i, dbsi->pbuf[i]);
		}
}


/* Display the given plaintext character at the given cipher block position.
 * Cipher block positions are zero-based.
 * Handles mapping of block positions to window coordinates.
 * It does not move the cursor.
 * It does set pbuf.
 */
dbsdpchar(dbs, pos, pchar)
gwindow	*dbs;
int		pos;
int		pchar;				/* -1 means no char. */
{
	int	row, col;			/* Original position. */
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	row = dbs->wcur_row;
	col = dbs->wcur_col;

	wl_setcur(dbs, dbsp2row(pos), dbsp2col(pos));
	plnchars(1, char2sym(pchar));
	dbsi->pbuf[pos] = pchar;
	wl_setcur(dbs, row, col);
}



/* Convert cipher block position to window row coordinate.
 */
dbsp2row(pos)
int		pos;
{
	return(TOPROW + 2*(pos/LINELEN));
}


/* Convert cipher block position to window column coordinate.
 */
dbsp2col(pos)
int		pos;
{
	return(1 + (pos%LINELEN));
}


/* Convert window row and column positions into a  cipher block position.
 */
int	dbsrc2pos(row, col)
int		row, col;
{
	return( ((row-TOPROW)/2)*LINELEN  +  (col-1) );
}



/* Reset all the character marks that are set and update the display.
 */
dbsrmarks(dbs)
gwindow	*dbs;
{
	int	i;
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (dbsi->mbuf[i])  dbscmark(dbs, i);
		}
}


/* (re)Draw all the set character marks.
 * Assumes that the window has been erased.
 * Cursor restored to its original place.
 */
dbsdmarks(dbs)
gwindow	*dbs;
{
	int	i;
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (dbsi->mbuf[i])  {
			dbssmark(dbs, i);
			}
		}
}


/* Set a mark under the given cipher block position and
 * update the mark flags.
 * Doesn't change the cursor position.
 */
dbssmark(dbs, pos)
gwindow	*dbs;
{
	int	row, col;			/* Original position. */
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	row = dbs->wcur_row;
	col = dbs->wcur_col;

	wl_setcur(dbs, 1+dbsp2row(pos), dbsp2col(pos));
	plnchars(1, SUNDERLINE);
	dbsi->mbuf[pos] = TRUE;

	wl_setcur(dbs, row, col);
}


/* Clear the mark under the given cipher block position and
 * update the mark flags.
 * Doesn't change the cursor position.
 */
dbscmark(dbs, pos)
gwindow	*dbs;
{
	int	row, col;			/* Original position. */
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	row = dbs->wcur_row;
	col = dbs->wcur_col;

	wl_setcur(dbs, 1+dbsp2row(pos), dbsp2col(pos));
	plnchars(1,' ');
	dbsi->mbuf[pos] = FALSE;

	wl_setcur(dbs, row, col);
}



/* Set the permutation to reflect the fact that the
 * character at pos is pchar.
 * Update the display to reflect the changes.
 * Highlight all changes.
 * Add the character to the command string, clearing the old
 * marks if this is the first command character.
 * By setting pchar to NONE, this can be used to clear the permutation.
 * The cursor position is not changed.
 */
dbssperm(dbs, pos, pchar)
gwindow	*dbs;
int	pos;
int	pchar;
{
	int	i;
reg	dbsinfo	*dbsi;
	char	*p;
	int	x;		/* Shifted up cipher text character. */
	int	y;		/* Shifted up plain text character. */

	dbsi = ((dbsinfo *) dbs->wprivate);

	if (dbsi->cmdnext == 0)  {		/* Starting new command. */
		dbsrmarks(dbs);
		for (i = 0 ; i < BLOCKSIZE ; i++)  {
			dbsi->operm[i] = dbsi->perm[i];
			}
		dbsi->cmdloc = pos;
		}
	dbsi->cmdbuf[dbsi->cmdnext++] = pchar;

	if (pchar == NONE) {		/* Just clear the permutation. */
		x = (dbsi->cbuf[pos] + pos) & MODMASK;
		y = dbsi->perm[x];
		if (y != NONE)  dbscwire(dbs, x, y&MODMASK);
		return;
		}

	x = (dbsi->cbuf[pos] + pos) & MODMASK;
	y = (pchar + pos) & MODMASK;
	dbsswire(dbs, x, y);
}


/* Clear the wiring for perm[x] equals y and update the display.
 * Requires that x be in fact wired to y.
 */
dbscwire(dbs, x, y)
gwindow	*dbs;
int	x, y;
{
	int	i;
	dbsinfo	*dbsi;
	char	*p;

	dbsi = ((dbsinfo *) dbs->wprivate);
	if (dbsi->perm[x] != y  ||  x == NONE)  return;
	if (y != NONE)  dbsi->wirecnt--;

	permchgflg = TRUE;
	x = x&MODMASK;
	y = y&MODMASK;
	dbsi->perm[x] = NONE;
	dbsi->perm[y] = NONE;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if ( ((((dbsi->cbuf[i])+i)&MODMASK) == x)
		  || ((((dbsi->cbuf[i])+i)&MODMASK) == y) ) {
			dbsdpchar(dbs, i, NONE);
			dbscmark(dbs, i);
			}
		}

}


/* Set the wiring for perm[x] equals y and update the display.
 * Clear any wiring that was set.
 * Requires x and y not be NONE.
 */
dbsswire(dbs, x, y)
gwindow	*dbs;
int	x, y;
{
	int	i;
	char	*p;
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	if (x == NONE  ||  y == NONE)  return;
	x = x&MODMASK;
	y = y&MODMASK;
	permchgflg = TRUE;

	if (dbsi->perm[x] != y)  {
		if (dbsi->perm[x] != NONE)  dbscwire(dbs, x, dbsi->perm[x]);
		if (dbsi->perm[y] != NONE)  dbscwire(dbs, y, dbsi->perm[y]);
		}
	if (dbsi->perm[x] == NONE)  dbsi->wirecnt++;
	dbsi->perm[x] = y;
	dbsi->perm[y] = x;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if ((((dbsi->cbuf[i])+i)&MODMASK) == x)  {
			dbsi->pbuf[i] = (y - i) & MODMASK;
			}
		else if ((((dbsi->cbuf[i])+i)&MODMASK) == y)  {
			dbsi->pbuf[i] = (x - i) & MODMASK;
			}
		else  {continue;}
		dbsdpchar(dbs, i, dbsi->pbuf[i]);	/* Found one. */
		dbssmark(dbs, i);
		}
}



/* Behavior when cursor enters the window.
 * Indicate that we are at the beginning of a command.
 * Put up help message.
 */
dbsfirst(dbs, row, col)
gwindow	*dbs;
int	row, col;		/* Relative to window's origin. */
{
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	dbsi->cmdnext = 0;
	usrhelp(&user, DBSHELP);
	wl_setcur(dbs, dbs->wcur_row, col);
}


/* Behavior when cursor leaves the window.
 * Complete the command and give it to the history window.
 */
dbslast(dbs)
gwindow	*dbs;
{
	dbscmddone(dbs);
}


/* A command may be done, if so, send it to the history window.
 * Setup for undo.
 */
dbscmddone(dbs)
gwindow	*dbs;
{
	int		i;
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	if (dbsi->cmdnext != 0)  {
		dbsi->cmdbuf[dbsi->cmdnext++] = 0;
/*		hstadd(&history, dbsi->cmdbuf);
*/
		dbsi->cmdnext = 0;
		}
}



/* Cursor movement commands.
 * Keep the cursor on the pchar lines.
 * Moving off the end of a line advances to the next or previous line.
 * Moving the cursor also terminates any command that might
 * have been entered.
 */
dbsup(dbs, k)
gwindow	*dbs;
{
	int	row, col;		/* Current relative cursor position. */
	
	row = dbs->wcur_row;
	col = dbs->wcur_col;
	
	if (row <= TOPROW)  {
		wl_setcur(dbs, 1, col);
		dbs->wcur_row = TOPROW;
		jogcursor(1);
		if (wl_hascur(dbs))
		  	wl_rcursor(dbs);
	}
	else {
		jogup(dbs, k);
		jogup(dbs, k);
	}
	dbscmddone(dbs);
}

dbsdown(dbs, k)
gwindow	*dbs;
{
	int	row, col;		/* Current relative cursor position. */
	
	row = dbs->wcur_row;
	col = dbs->wcur_col;
	
	if (row >= BOTROW)  {
		wl_setcur(dbs, DBHEIGHT, col);
		dbs->wcur_row = BOTROW;
		jogcursor(2);
		if (wl_hascur(dbs))
		  	wl_rcursor(dbs);
		}
	else {
		jogdown(dbs, k);
		jogdown(dbs, k);
		}
	dbscmddone(dbs);
}

dbsleft(dbs, k)
gwindow	*dbs;
{
	int	row, col;		/* Current relative cursor position. */
	
	row = dbs->wcur_row;
	col = dbs->wcur_col;
	
	dbsprev(dbs);
	dbscmddone(dbs);
}

dbsright(dbs, k)
gwindow	*dbs;
{
	int	row, col;		/* Current relative cursor position. */
	
	row = dbs->wcur_row;
	col = dbs->wcur_col;
	
	dbsnext(dbs);
	dbscmddone(dbs);
}


/* Backup the cursor to the previous position without terminating
 * a command.
 */
dbsprev(dbs)
gwindow	*dbs;
{
	int	row, col;		/* Current relative cursor position. */

	row = dbs->wcur_row;
	col = dbs->wcur_col;

	if (col <= 1  &&  row <= TOPROW)  {
		}
	else if (col <= 1)  {
		wl_setcur(dbs, row-2, LINELEN);
		}
	else {
		jogleft(dbs);
		}
}


/* Advance the cursor to the next position without terminating
 * a command.
 */
dbsnext(dbs)
gwindow	*dbs;
{
	int	row, col;		/* Current relative cursor position. */

	row = dbs->wcur_row;
	col = dbs->wcur_col;

	if (col >= LINELEN  &&  row >= BOTROW)  {
		}
	else if (col >= LINELEN)  {
		wl_setcur(dbs, row+2, 1);
		}
	else {
		jogright(dbs);
		}
}



/* Add the character to the permutation.
 */
dbskey(dbs, k)
gwindow	*dbs;
int	k;
{
	int	pos;		/* plaintext block position. */
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	pos = dbsrc2pos(dbs->wcur_row, dbs->wcur_col);
	dbssperm(dbs, pos, k & CHARM);
	dbsnext(dbs);
	dblpcount(&dblabel, dbsi->wirecnt);
}



/* Delete forward.
 * Clear the wiring due to the character at the current position,
 * and update the display.
 * The cursor moves forward one position.
 */
dbsdelf(dbs)
gwindow	*dbs;
{
	int	pos;		/* plaintext block position. */
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	pos = dbsrc2pos(dbs->wcur_row, dbs->wcur_col);

	dbssperm(dbs, pos, NONE);
	dbsnext(dbs);
	dblpcount(&dblabel, dbsi->wirecnt);
}



/* Delete backwards.
 * Clear the wiring due to the character at the previous position,
 * and update the display.
 * The cursor moves backwards one position.
 */
dbsdelb(dbs)
gwindow	*dbs;
{
	int	pos;		/* plaintext block position. */
	dbsinfo	*dbsi;

	dbsi = ((dbsinfo *) dbs->wprivate);
	pos = dbsrc2pos(dbs->wcur_row, dbs->wcur_col);
	if (pos == 0)  return;
	pos = pos - 1;

	dbssperm(dbs, pos, NONE);
	dbsprev(dbs);
	dblpcount(&dblabel, dbsi->wirecnt);
}



/* Advance to the next cipher text block (if any).
 */
dbsnxtblk(dbs)
gwindow	*dbs;
{
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	dbssetblk(dbs, dbsi->blknum + 1);
}


/* Backup to the previous cipher text block (if any).
 */
dbsprvblk(dbs)
gwindow	*dbs;
{
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	dbssetblk(dbs, dbsi->blknum - 1);
}


/* Jump to a particular block number.
 * Get a new permutation and update the display.
 * Even if the block number hasn't change, the permutation may have,
 * so we must re-decode the block.
 */
dbssetblk(dbs, blocknum)
gwindow	*dbs;
int	blocknum;
{
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	if (fillcbuf(blocknum, dbsi->cbuf)
	 && (dbsi->perm = refperm(blocknum))) {
		dbsi->blknum = blocknum;
		dbsinit(dbsi);
		dbsdraw(dbs);
		usrstatus(&user, "Ready.");
		}
	else {
		usrstatus(&user, "Block number is out of range.");
		}
}


/* Return the number of the current block.
 */
dbsgetblk(dbs)
gwindow	*dbs;
{
	dbsinfo	*dbsi;
	dbsi = ((dbsinfo *) dbs->wprivate);

	return(dbsi->blknum);
}
