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
 * prompt_key
 *
 *	This routine shows the string `prompt' on the current tty and reads
 *	a line from the current tty. If the `verify' argument is non-zero,
 *	then a second prompt requesting verification is shown. If the first
 *	and second lines do not match, then the process is tried again until
 *	both match.
 *
 *	The input echo is switched off during the operation.
 *
 *	If the key can not be read from the tty, NULL is returned and the
 *	global variable `prompt_key_error' set to -2. `prompt_key_error'
 *	is set -1 is there was any problems with terminal echo manipulation.
 *
 */

/*
 * Global error information.
 */

extern int	prompt_key_error;


extern char	*prompt_key(
#ifdef __STDC__
	char	*prompt,
	int	verify
#endif
);
