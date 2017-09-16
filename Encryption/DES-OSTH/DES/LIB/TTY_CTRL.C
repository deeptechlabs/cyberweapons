#include	<stdio.h>
#include	"tty.h"

/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 * Additional restrictions due to national laws governing the use, import or
 * export of cryptographic software is the responsibility of the software user,
 * importer or exporter to follow.
 *
 *					     _
 *					Stig Ostholm
 *					Department of Computer Engineering
 *					Chalmers University of Technology
 */

/*
 * TTY modification routines.
 */

typedef	struct sgttyb	tty_mode;


extern int	tty_disable_echo(
#ifdef __STDC__
	FILE		*tty,
	tty_state	*orig_tty_state)
#else
	tty, orig_tty_state)
FILE		*tty;
tty_mode	*orig_tty_state;
#endif
{
	register int	status;
	tty_mode	no_echo;


	status = gtty(fileno(tty), orig_tty_state);
	if (!status) {
		bcopy((char *) orig_tty_state , (char *) & no_echo,
		      sizeof(tty_state));
		no_echo.sg_flags &= ~ ECHO;
		status = stty(fileno(tty), &no_echo);
	}
	return status;
}

extern int	tty_reset(
#ifdef __STDC__
	FILE		*tty,
	tty_state	*orig_tty_state)
#else
	tty, orig_tty_state)
FILE		*tty;
tty_mode	*orig_tty_state;
#endif
{
	return stty(fileno(tty), orig_tty_state);
}
