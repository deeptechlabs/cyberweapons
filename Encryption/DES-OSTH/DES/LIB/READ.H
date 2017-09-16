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
 * read_line
 *
 *	`read_line' read from `fd' up to a newline or end of file.
 *	and returns a null terminated string with the result.
 *
 *	The string returned is dynamicaly allocated.
 *
 *	If any read error was detected or no storage space could be
 *	allocated, null is retuned.
 */

extern char	*read_line(
#ifdef __STDC__
	FILE *fd
#endif
);
