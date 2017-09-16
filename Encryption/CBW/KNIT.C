/*
 * Use serveral mostly solved blocks to solve the knitting equation
 * and deduce the rotor and reflector wirings.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"


extern	char	gcbuf[];		/* All guess displays use same buffers. */
extern	int		gpbuf[];
extern	int		gperm[];


#define KNTHELP	"F2 = next guess, F3 = enter guess, ^G = Undo enter."
#define STARTMSG "Knitting from %d to %d.   Known Zee: %d of 256."
#define GUESSMSG "guesscount = %d, xi=%d, yi=%d.   Known Zee: %d of 256."
#define UNDOMSG  "Undone.  Current known Zee: %d of 256"
#define	BIG		1000		/* Size of try stack in kntadvance(). */


/* Pack and unpack two bytes into an integer. */
#define pack(x,y)		(((x&0377)<<8) + y)
#define unpack(x,y,v)	tmpv = v; x = ((tmpv>>8)&0377);  y = (tmpv&0377);


/* Keystroke handler table. */

extern	int	kntadvance();
extern	kntundo();
extern	kntnextg();
extern	kntenter();

keyer	kntktab[] = {
		{CNEXTGUESS, kntnextg},
		{CACCEPT, kntenter},
		{CUNDO, kntundo},
		{CGO_UP, jogup},
		{CGO_DOWN, jogdown},
		{CGO_LEFT, jogleft},
		{CGO_RIGHT, jogright},
		{0, NULL},
};



/* Private data structure for guess blocks. */

#define	kntinfo		struct	xkntinfo
struct	xkntinfo	{
		char	*cbuf;		/* The cipher block. */
		int		*pbuf;		/* The derived guess plaintext, -1 = none. */
		int		*perm;		/* Permutation of block highbnum+1. */
		int		xindex;		/* Starting position of next x guess. */
		int		yindex;		/* Starting position of next y guess. */
		int		*zee;		/* Knitting matrix. */
		int		*zeeinv;	/* Its inverse. */
		int		*ustkp;		/* Undo stack pointer. */
		int		*savedustkp;	/* Undo stack pointer. */
		int		*undostk;	/* Undo stack. */
		int		lowbnum;	/* Block number of lowest source. */
		int		highbnum;	/* Block number of highest source. */
		int		min_show;	/* Smallest count to show. */
		};


/* Private buffers. */
int		kzee[BLOCKSIZE+1];
int		kzeeinv[BLOCKSIZE+1];
int		kustk[BLOCKSIZE+1];

kntinfo	kntprivate;

int		kntinit	= FALSE;


extern	kntdraw(), kntfirst();		/* Defined below. */


/* This routine is called by the user command to clear the zee matrix.
 */
char	*clearzee(str)
char	*str;		/* Command line */
{
	int		i;
	kntinfo	*knti;

	knti = &kntprivate;
	initknt();
	kntclrzee(knti);

	if (&kntprivate == ((kntinfo *) gbstore.wprivate)) {
		for (i = 0 ; i < BLOCKSIZE ; i++)  {
			knti->perm[i] = -1;
			}
		decode(knti->cbuf, knti->pbuf, knti->perm);
		sprintf(statmsg, GUESSMSG,
				0, knti->xindex, knti->yindex, zeecount(knti));
		gblset(&gblabel, statmsg);
		wl_draw(&gbstore);
		}

	wl_rcursor(&user);
	return(NULL);
}



/* This routine is called to set up the guess block window
 * to be used for guessing the zee matrix.
 * It can be directly invoked by the command interpreter.
 * Set up dbstore to show the block after the last block
 * the the user says to consider complete.
 */
char	*kntguess(str)
char	*str;		/* Command line */
{
	int		i;
	int		from,to;
	gwindow	*knt;
	kntinfo	*knti;

	knt = &gbstore;
	knti = &kntprivate;
	initknt();

	if (!kntinit) {
		kntinit = TRUE;
		kntclrzee(knti);
		}

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		knti->perm[i] = -1;
		}

	from = to = 0;
	if ((i = sscanf(str,"%*[^:]: %d %*[^:]: %d %*[^:]: %d",
					&from, &to, &knti->min_show)) != 3) {
		return("Could not parse all arguments.");
		}
	else {
		if (to <= from)
			return("To: must be less than From:");
		}
	
	dbssetblk(&dbstore, to+1);
	if (!fillcbuf(to+1, knti->cbuf)) {
		return("Bad to: value");
		}
	decode(knti->cbuf, knti->pbuf, knti->perm);
	knti->xindex = 0;
	knti->yindex = 0;
	knti->lowbnum = from;
	knti->highbnum = to;

	gbsswitch(knt,((char *) knti), kntktab, kntfirst, wl_noop, kntdraw);
	sprintf(statmsg, STARTMSG, from, to, zeecount(knti));
	gblset(&gblabel, statmsg);
	kntdraw(knt);

	wl_setcur(knt, 1, 1);
	return(NULL);
}



/* Clear the zee permutation and update any display info.
 */
kntclrzee(knti)
kntinfo	*knti;
{
	int		i;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		knti->zee[i] = -1;
		knti->zeeinv[i] = -1;
		}
}


/* Compute the next successful guess of a wiring of ZEE.
 * Show it to the user for acceptance/rejection.
 */
kntnextg(knt)
gwindow	*knt;
{
	int		guesscnt;
	kntinfo	*knti;
	knti = ((kntinfo *) knt->wprivate);

	kntclrlast(knti);
	while (TRUE) {
		guesscnt = kntadvance(knti);
		if ((guesscnt == 0) || (guesscnt >= knti->min_show))  break;
		kntclrlast(knti);
		}
	if (guesscnt == 0)  {
		gblset(&gblabel, "No more guesses");
		return;
		}
	decode(knti->cbuf, knti->pbuf, knti->perm);

	sprintf(statmsg, GUESSMSG,
			guesscnt, knti->xindex, knti->yindex, zeecount(knti));
	gblset(&gblabel, statmsg);
	kntdraw(knt);
}



/* Clear last guess in zee, zeeinv, perm.
 * Note that perm only holds the results of the last guess.
 */
kntclrlast(knti)
kntinfo	*knti;
{
	int		tmpv;	/* For unpack. */
	int		x,y;
	int		i;

	while (knti->ustkp > knti->undostk)  {
		unpack(x, y, *(--(knti->ustkp)));
		knti->zee[x] = -1;
		knti->zeeinv[y] = -1;
		}
	knti->ustkp = knti->savedustkp = knti->undostk;
		
	for (i = 0 ; i < BLOCKSIZE ; i++) {
		knti->perm[i] = -1;
		}
}



/* Advance to the next acceptable guess at a wiring for Zee.
 * This modifies zee, zeeinv, and perm.  Perm only contains the
 * info derived from this guess, while zee and zeeinv accumulate
 * information from all preceeding accepted guesses.
 * Returns the number of guesses that we derived from the initial one.
 * If out of acceptable guesses, returns 0.
 * Perm must be cleared before calling this.
 */
int	kntadvance(knti)
kntinfo	*knti;
{
	int		guesscount;
	int		i;
	int		tmpv;		/* For unpack. */
	int		x,y;
	int		tx,ty;
	int		u,v;
	int		tu,tv;
	int		*a2;		/* The permutation as in u = A2 x */
	int		*a1;		/* The permutation as in v = A1 y */
	int		*propp;		/* Temp for undo stack propagation. */
	int		*highperm;	/* Perm used to derive next perm. */
	int		trycount;	/* Size of trystk. */
	int		*tstkp;		/* Stack of guesses to check. */
	int		trystk[BIG];

/* kntadvance(knti)
 */
	guesscount = 0;		/* In case loop body never executes. */

	if (knti->xindex >= BLOCKSIZE)  return(0);
	if (knti->yindex >= BLOCKSIZE)  {
		knti->yindex = 0;
		knti->xindex++;
		}

	for (x = knti->xindex ; x < BLOCKSIZE ; x++) {
		if (knti->zee[x] != -1)  {
			knti->yindex = 0;
			continue;
			}
		for (y = knti->yindex ; y < BLOCKSIZE ; y++) {
			if (knti->zeeinv[y] != -1)  continue;
			guesscount = 0;
			tstkp = trystk;					/* Assume ustkp == undostk. */
			trycount = 0;
			*(tstkp++) = pack(x,y);
			trycount++;

			while (tstkp > trystk) {
				unpack(tx, ty, *(--tstkp));
				trycount--;
				if (knti->zee[tx] == -1 && knti->zeeinv[ty] == -1) {
					knti->zee[tx] = ty;
					knti->zeeinv[ty] = tx;
					*((knti->ustkp)++) = pack(tx,ty);
					guesscount++;
					for (i = knti->lowbnum ; (i+1) <= knti->highbnum ; i++) {
						a1 = refperm(i);
						a2 = refperm(i+1);
						tu = a2[tx];
						tv = a1[ty];
						if (tu != -1 && tv != -1 && trycount < BIG) {
							*(tstkp++) = pack(tu, tv);
							trycount++;
							}
						}
					}
				else if (knti->zee[tx] != ty
					  || knti->zeeinv[ty] != tx) {		/* If conflict. */
						while (knti->ustkp > knti->undostk)  {
							unpack(tx, ty, *(--(knti->ustkp)));
							knti->zee[tx] = -1;
							knti->zeeinv[ty] = -1;
							guesscount--;
							}
						knti->ustkp = knti->undostk;
						goto nxtguess;
					  }
				else continue;		/* Already know about it. */
				}

			knti->xindex = x;		/* Zee[x] = y was a good guess. */
			knti->yindex = y+1;
			propp = knti->ustkp;
			highperm = refperm(knti->highbnum);
			while (propp > knti->undostk) {  /* Update perm. */
				unpack(tx, ty, *(--propp));
				v = highperm[ty];
				if (v != -1  &&  (tmpv = knti->zeeinv[v]) != -1)  {
					knti->perm[tx] = tmpv;
					knti->perm[tmpv] = tx;
					}
				}
			return (guesscount);
			nxtguess: ;
			}
		knti->yindex = 0;
		}

	knti->yindex = 0;
	knti->xindex = 0;
	return(guesscount);
}
			 

/* Enter our current guess into the decryption block.
 * Clear out the undo stack.
 */
kntenter(knt)
gwindow	*knt;
{
	kntinfo	*knti;

	knti = ((kntinfo *) knt->wprivate);
	knti->savedustkp = knti->ustkp;		/* If we change our mind. */
	knti->ustkp = knti->undostk;
	if (knti->highbnum+1 != dbsgetblk(&dbstore))
		dbssetblk(&dbstore, knti->highbnum+1);
	dbsmerge(&dbstore, knti->perm);
	wl_rcursor(knt);
}


/* Undo the last guess.
 */
kntundo(knt)
gwindow	*knt;
{
	kntinfo	*knti;

	knti = ((kntinfo *) knt->wprivate);
	knti->ustkp = knti->savedustkp;
	kntclrlast();
	dbsundo(&dbstore);

	sprintf(statmsg, UNDOMSG, zeecount(knti));
	gblset(&gblabel, statmsg);
	wl_rcursor(knt);
}


/* Behavior when first enter the window.
 * Put up a help message.
 * Accept the cursor where it is.
 */
kntfirst(knt, row, col)
gwindow	*knt;
int		row,col;	/* Current coordinates. */
{
	usrhelp(&user, KNTHELP);
	wl_setcur(knt, row, col);
}



/* (re)Draw the window.
 */
kntdraw(knt)
gwindow	*knt;
{
	int			i;
	int			row, col;		/* Original row and column. */
	kntinfo		*knti;

	knti = ((kntinfo *) knt->wprivate);
	row = knt->wcur_row;
	col = knt->wcur_col;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		if (i%LINELEN == 0) {
			wl_setcur(knt, gbspos2row(i), gbspos2col(i));
			}
		plnchars(1, char2sym(knti->pbuf[i]));
		}

	for (i = gbspos2row(BLOCKSIZE) ; i <= GBHEIGHT ; i++) {
		wl_setcur(knt, i, 1);
		plnchars(LINELEN, ' ');
		}

	for (i = 1 ; i <= GBHEIGHT ; i++) {
		wl_setcur(knt, i, LINELEN+1);
		plnchars(knt->wwidth - LINELEN, ' ');
		}

	wl_setcur(knt, row, col);
}


/* Return number of known wires in Zee.
 * Max is 256.
 */
int	zeecount(knti)
kntinfo	*knti;
{
	return(permcount(knti->zee));
}


/* Store Zee permutation on a file.
 */
storezee(fd)
FILE	*fd;
{
	writeperm(fd, kzee);
}


/* Load the Zee permutation from a file.
 * Update display if necessary.
 */
loadzee(fd)
FILE	*fd;
{
	int		i;
	kntinfo	*knti;

	knti = &kntprivate;
	initknt();
	kntinit = TRUE;
	kntclrzee(knti);		/* Clear zeeinv */

	readperm(fd, kzee);	
	for (i = 0 ; i < BLOCKSIZE ; i++) {
		if (kzee[i] != -1)  {kzeeinv[kzee[i]] = i;}
		}

	if (knti == ((kntinfo *) gbstore.wprivate)) {
		for (i = 0 ; i < BLOCKSIZE ; i++)  {
			knti->perm[i] = -1;
			}
		decode(knti->cbuf, knti->pbuf, knti->perm);
		sprintf(statmsg, GUESSMSG,
				0, knti->xindex, knti->yindex, zeecount(knti));
		gblset(&gblabel, statmsg);
		wl_draw(&gbstore);
		wl_setcur(&gbstore, 1, 1);
		}
}


/* Set up all the pointers in kntprivate.
 */
initknt()
{
	int		i;
	gwindow	*knt;
	kntinfo	*knti;

	knt = &gbstore;
	knti = &kntprivate;

	knti->zee = kzee;
	knti->zeeinv = kzeeinv;

	knti->cbuf = gcbuf;
	knti->pbuf = gpbuf;
	knti->perm = gperm;

	knti->undostk = kustk;
	knti->ustkp = knti->savedustkp = knti->undostk;
}
