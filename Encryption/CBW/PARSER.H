/*
 * Header for command parsing and completing routines.
 *
 * Robert W. Baldwin, December 1984.
 */



#define	CMDBAD	"I don't know how to do that."


/* A command table is an array of cmdent's terminated by a
 * cmdent that has a cmdname = NULL.
 * The command name can contain helpful noise words since
 * the comparision is only done on characters upto the first space.
 * The cmdproc is passed the full command string (including cmd name),
 * and returns a pointer to a status message.  The return pointer should
 * be NULL is everything goes ok.
 *
 * The command table should have atleast two non-empty entries for completion
 * to work properly.
 */

#define	cmdent	struct xcmdent

struct	xcmdent	{
		char	*cmdname;	/* Comparison done up to first blank. */
		char	*(*cmdproc)(/* cmd-string */);
		};
