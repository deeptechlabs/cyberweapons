#include	<stdio.h>
#include	<strings.h>
#include	<setjmp.h>
#include	<signal.h>
#include	"des.h"
#include	"compile.h"
#include	"prompt.h"
#include	"read.h"
#include	"tty.h"
#include	"sig.h"

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

#ifdef __STDC__
extern void	free(char *);
#endif

/*
 * Signal catch routine;
 */

static int	has_set_jmp = 0;
static jmp_buf	signal_jmp;

static int	catch_signal()
{
	if (has_set_jmp)
		longjmp(signal_jmp, 1);
	/* To keep some compilers happy. */
	return 0;
}

/*
 * Global error information.
 */

int	prompt_key_error;


char	*prompt_key(
#ifdef __STDC__
	char	*prompt,
	int	verify)
#else
	prompt, verify)
char	*prompt;
int	verify;
#endif
{
	register int	retry, tty_modified;
	register char	*strkey, *vstrkey;
	FILE		*ttywfd, *ttyrfd;
	tty_state	old_tty_state;


	tty_modified = 0;
	strkey = vstrkey = NULL;
	ttywfd = ttyrfd = NULL;
	if (setjmp(signal_jmp))
		goto error;
	has_set_jmp = 1;
#ifdef TTY
	ttywfd = fopen(TTY, "w");
	if (ttywfd == NULL)
		goto error;
	ttyrfd = fopen(TTY, "r");
	if (ttyrfd == NULL)
		goto error;
#else  /* TTY */
	ttywfd = stdout;
	ttyrfd = stdin;
#endif /* TTY */

	push_signals((signal_func) catch_signal);
	if (tty_disable_echo(ttyrfd, & old_tty_state) < 0)
		prompt_key_error = -1;
	else
		tty_modified = 1;

	do {
		fputs(prompt, ttywfd);
		fflush(ttywfd);
		if (ferror(ttywfd))
			goto error;
		strkey = read_line(ttyrfd);
		fputc('\n', ttywfd);
		if (!strkey)
			goto error;

		if (verify) {
			
			fputs("Verify ", ttywfd);
			fputs(prompt, ttywfd);
			fflush(ttywfd);
			if (ferror(ttywfd))
				goto error;
			vstrkey = read_line(ttyrfd);
			fputc('\n', ttywfd);
			if (!vstrkey)
				goto error;

			retry = strcmp(strkey, vstrkey);

			free(vstrkey);
			vstrkey = NULL;
			if (retry) {
				free(strkey);
				strkey = NULL;
				fputs("Keys don't match, try again\n", ttywfd);
				if (ferror(ttywfd))
					goto error;
			}

		} else
			retry = 0;

	} while (retry);

	if (tty_modified) {
		if (tty_reset(ttyrfd, & old_tty_state) < 0)
			prompt_key_error = -1;
		tty_modified = 0;
	}
	pop_signals();

#ifdef TTY
	VOID fclose(ttywfd);
	VOID fclose(ttyrfd);
#endif TTY

	return strkey;

error:
	if (tty_modified) {
		if (tty_reset(ttyrfd, & old_tty_state) < 0)
			prompt_key_error = -1;
		tty_modified = 0;
	}
	pop_signals();
	if (ttywfd != NULL) {
		VOID fclose(ttywfd);
		ttywfd = NULL;
	}
	if (ttyrfd != NULL) {
		VOID fclose(ttyrfd);
		ttyrfd = NULL;
	}
	if (strkey) {
		free(strkey);
		strkey = NULL;
	}
	if (vstrkey) {
		free(vstrkey);
		vstrkey = NULL;
	}
	prompt_key_error = -2;
	return NULL;
}
