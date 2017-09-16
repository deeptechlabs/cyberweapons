#include	<stdio.h>
#include	"read.h"
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
 * These routines are not declared on all systems.
 */

extern char	*malloc(
#ifdef __STDC__
	unsigned
#endif
);

extern char	*realloc(
#ifdef __STDC__
	void *, unsigned
#endif
);

#ifdef __STDC__
extern void	free(char *);
#endif


/*
 * read_line
 *
 *	`read_line' read from `fd' up to a newline or end of file.
 *	and returns a null terminated string with the result.
 *
 *	If any read error was detected or no storage space could be
 *	allocated, null is retuned.
 */

char	*read_line(
#ifdef __STDC__
	FILE *fd)
#else
	fd)
FILE	*fd;
#endif
{
	register unsigned	size, n;
	register char		*str, *tmp;
	register int		c;


	size = 16;
	str = malloc(size);
	if (str == NULL)
		return NULL;

	for (n = 0;; n++) {

		c = fgetc(fd);
		if (ferror(fd)) {
			free(str);
			return NULL;
		}

		/* End of string */
		if (c == '\n' || c == EOF)
			break;

		if (n + 1 >= size) {
			size += 8;
			tmp = realloc(str, size);
			/* was the memory allocatin successful ? */
			if (tmp == NULL) {
				/* The area pointed to by str may be	*/
				/* destroyed. So a free	may cause	*/
				/* disaster. 				*/
				/* Is this true on all systems ? 	*/
#ifdef NOTDEF
				free(str);
#endif
				return NULL;
			}
			str = tmp;
		}

		str[n] = (char) c;
	}

	str[n] = '\0';

	return str;
}
