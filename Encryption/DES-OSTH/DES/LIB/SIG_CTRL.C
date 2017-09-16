#include	<signal.h>
#include	"compile.h"
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
 * Functions to store and restore signal status.
 * The stack has only one level.
 */

static signal_func	orig_sig_func[NSIG];



push_signals(
#ifdef __STDC__
	signal_func	func)
#else
	func)
signal_func	func;
#endif
{
	orig_sig_func[SIGHUP]  = (signal_func) signal(SIGHUP,  func);
	orig_sig_func[SIGINT]  = (signal_func) signal(SIGINT,  func);
	orig_sig_func[SIGTERM] = (signal_func) signal(SIGTERM, func);
	orig_sig_func[SIGQUIT] = (signal_func) signal(SIGQUIT, func);
}

pop_signals()
{
	register int	i;


	for (i = 0; i < NSIG; i++)
		if (orig_sig_func[i]) {
			VOID signal(i, orig_sig_func[i]);
			orig_sig_func[i] = (signal_func) 0;
		}
}
