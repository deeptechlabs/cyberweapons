#include	"des.h"
#include	"compile.h"
#include	"prompt.h"
#include	"version.h"

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
 * des_read_password
 *
 *	This routine shows the string `prompt' on the current tty and reads
 *	a line from the current tty. If the `verify' argument is non-zero,
 *	then a second prompt requesting verification is shown. If the first
 *	and second lines do not match, then the process is tried again until
 *	both match.
 *
 *	The input echo is switched off during the operation.
 *
 *	The string (excluding any newline) is converted to a DES key by use
 *	of `des_string_to_key'.
 *
 *	`des_read_password' returns 0 if the operation was successful,
 *	-1 if the echo could not be switched off or -2 if the input string
 *	could not be obtained. In teh last case, no key is generated.
 */

extern	free(
#ifdef __STDC__
	void *
#endif
);


int	des_read_password(
#ifdef __STDC__
	des_cblock	*key,
	char		*prompt,
	int		verify)
#else
	key, prompt, verify)
des_cblock	*key;
char		*prompt;
int		verify;
#endif
{
	register char	*keystr;


	keystr = prompt_key(prompt, verify);

	/* Make a des key from the string key. */
	if (keystr) {
		VOID des_string_to_key(keystr, *key);
		free(keystr);
	}

	return prompt_key_error;
}
