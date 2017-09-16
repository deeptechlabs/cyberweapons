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
 * Functions to store and restore signal status.
 * The stack has only one level.
 */

typedef	int		(*signal_func)();


extern	push_signals(
#ifdef __STDC__
	signal_func	func
#endif
);

extern	pop_signals();
