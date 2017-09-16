#include	<sgtty.h>

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

typedef	struct sgttyb	tty_state;


extern int	tty_disable_echo(
#ifdef __STDC__
	FILE		*tty,
	tty_state	*orig_tty_state
#endif
);

extern int	tty_reset(
#ifdef __STDC__
	FILE		*tty,
	tty_state	*orig_tty_state
#endif
);
