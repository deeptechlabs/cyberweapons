#include <stdio.h>
#include <signal.h>
#include <sgtty.h>

#define	TTY	"/dev/tty"	/* Change to "con" for MS-DOS */

/* Issue prompt and read reply with echo turned off */
char *
getpass(prompt)
char *prompt;
{
	struct sgttyb ttyb,ttysav;
	register char *cp;
	int c;
	FILE *tty;
	static char pbuf[128];
	int (*signal())(),(*sig)();

	if ((tty = fdopen(open(TTY, 2), "r")) == NULL)
		tty = stdin;
	else
		setbuf(tty, (char *)NULL);
	sig = signal(SIGINT, SIG_IGN);
	ioctl(fileno(tty), TIOCGETP, &ttyb);
	ioctl(fileno(tty), TIOCGETP, &ttysav);
	ttyb.sg_flags |= RAW;
	ttyb.sg_flags &= ~ECHO;
	ioctl(fileno(tty), TIOCSETP, &ttyb);
	fprintf(stderr, "%s", prompt);
	fflush(stderr);
	cp = pbuf;
	for (;;) {
		c = getc(tty);
		if(c == '\r' || c == '\n' || c == EOF)
			break;
		if (cp < &pbuf[127])
			*cp++ = c;
	}
	*cp = '\0';
	fprintf(stderr,"\r\n");
	fflush(stderr);
	ioctl(fileno(tty), TIOCSETP, &ttysav);
	signal(SIGINT, sig);
	if (tty != stdin)
		fclose(tty);
	return(pbuf);
}
