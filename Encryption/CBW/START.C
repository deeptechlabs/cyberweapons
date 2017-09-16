/*
 * Start up module for the crypt breaking editor.
 * Much of the global behavior of the program is set here.
 *
 * Robert W. Baldwin, December 1984.
 *
 * Bob Baldwin, 10/86:
 *  Added cmd to jump to user window.
 *  Handle C-Z to suspend CBW and abort commands.
 */


#include	<stdio.h>
#include	<signal.h>
#include	<setjmp.h>
#include	"window.h"
#include	"terminal.h"
#include	"layout.h"
#include	"specs.h"


/* Shell variable names. */
#define	LETTERSTATS	"LETTERSTATS"
#define	BIGRAMSTATS	"BIGRAMSTATS"
#define	TRIGRAMSTATS	"TRIGRAMSTATS"

#define	QUITMSG	"Permutations not saved.  Type 'y' if you want to quit."


/* Keystroke behavior that is the same in all windows.
 */
extern		alldraw(), jumpcmd();
extern	char	*getenv();

keyer	topktab[] = {
		{CREFRESH, alldraw},
		{CJUMPCMD, jumpcmd},
		{0, NULL},
		};


/* Table of all top-level windows.  Terminated by NULL.
 */
gwindow		*wtable[WINDNUM+1];
char		cfilebuf[100];
char		pfilebuf[100];

/* Saved stack state for suspending the program.
 */
jmp_buf		saved_stack;


main(argc, argv)
int		argc;
char	*argv[];
{
	extern	stop_handler();
	extern	kill_handler();
	char	*q, *pp, *pc;

	if (argc < 2)  {
		printf("Usage: %s FileNameRoot\n", argv[0]);
		printf("\tThe extensions .cipher and .perm will be used.");
		printf("\n\tThe shell variables");
		printf(" %s, %s, %s,", LETTERSTATS, TRIGRAMSTATS, BIGRAMSTATS);
		printf("\n\tand TERM must be defined.");
		printf("\n\tThe shell variables");
		printf(" %s and %s", GRAPHICSVAR, KEYMAPVAR);
		printf(" may be defined.");
		printf("\n");
		exit(0);
		}
	q = argv[1];
	pc = cipherfile = cfilebuf;
	pp = permfile = pfilebuf;
	while (*pp++ = *pc++ = *q++);
	pp--;
	pc--;
	q = ".cipher";
	while (*pc++ = *q++);
	q = ".perm";
	while (*pp++ = *q++); 

	load_tables();

	set_term();
	signal(SIGTSTP, stop_handler);
	signal(SIGINT, kill_handler);

	initwindows();

	/* Control returns here when program restarted after C-Z. */
 	setjmp(saved_stack);

	alldraw();
	usrstatus(&user, "Ready.");
	usrfirst(&user, 1, 1);		/* Start in user window. */
	
	wl_driver(wtable);
	done(0);			/* Fell off windows, we're done. */
}


/* Handle C-Z signal (suspend program).
 * Restore screen and exit.
 * On restart, setup screen, redraw screen, and abort to top loop.
 */
stop_handler()
{
	setcursor(MAXHEIGHT, 1);
	fflush(stdout);
	unset_term();
	
	kill(getpid(), SIGSTOP);

	/* Return here when/if program restarted. */
	/* Note that the signal mask is restored by longjmp. */
	set_term();
	longjmp(saved_stack, 0);
}


/* Handle C-C signal (kill program).
 * Restore screen and exit.
 */
kill_handler()
{
	setcursor(MAXHEIGHT, 1);
	printf("\n");
	fflush(stdout);
	unset_term();
	
	kill(getpid(), SIGKILL);
}


/* Load stat tables.
 */
load_tables()
{
	printf("\n\nLoading letter statistics ...");
	fflush(stdout);
	if ((letterstats = getenv(LETTERSTATS)) == NULL)  {
		printf("The shell variable %s is not defined.\n", LETTERSTATS);
		exit(0);
		}
	load_1stats_from(letterstats);
	printf(" done.\n");

	printf("\n\nLoading bigram statistics ...");
	fflush(stdout);
	if ((bigramstats = getenv(BIGRAMSTATS)) == NULL)  {
		printf("The shell variable %s is not defined.\n", BIGRAMSTATS);
		exit(0);
		}
	load_2stats_from(bigramstats);
	printf(" done.\n");

	printf("\n\nLoading trigram statistics ...");
	fflush(stdout);
	if ((trigramstats = getenv(TRIGRAMSTATS)) == NULL)  {
		printf("The shell variable %s is not defined.\n",TRIGRAMSTATS);
		exit(0);
		}
	load_tri_from(trigramstats);
	printf(" done.\n");
	
	permchgflg = FALSE;
}


/* Quit command
 * This is the prefered way to leave the program.
 */
char *quitcmd(arg)
char	*arg;
{
	char	c;

	if (permchgflg)  {
		usrstatus(&user, QUITMSG);
		c = getchar();
		if (!(c == 'y'  ||  c == 'Y'))
		  	return(NULL);
		}
	done(0);
}


/* Exit the program after cleaning up the terminal.
 */
done(status)
int	status;
{
	unset_term();
	printf("\n");
	exit(status);
}


/* (re)Draw all the windows.
 */
alldraw()
{
	wl_refresh(wtable);
}


/* Jump to the command window.
 * Tell the current window, that it is losing the cursor, and
 * then tell the user window that it's got the cursor.
 */
jumpcmd(w)
gwindow	*w;
{
	(*(w->wlast))(w);
	usrfirst(&user, 1, 1);		/* Given row, col ignored. */
}


/* Fill in the window table.
 */
initwindows()
{
	int	i;

	i = 0;
	wtable[i++] = iuser();
	wtable[i++] = ibanner();
	wtable[i++] = idblabel();
	wtable[i++] = idbstore();
	wtable[i++] = igblabel();
	wtable[i++] = igbstore();
	wtable[i++] = iwebster();

	if (i != WINDNUM)  {
		disperr("inittables: WINDNUM value is wrong");
		setcursor(2,1);
		exit(0);
		}

	wtable[i] = ((gwindow *) NULL);
}


/* Get keystroke routine.
 * Responsible for clearing the status area before every keystroke.
 */
key	u_getkey()
{
	key	k;

	k = getcmd();
	usrstatus(&user, "");

	return(k);
}
