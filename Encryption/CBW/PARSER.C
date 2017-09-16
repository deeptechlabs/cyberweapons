/* 
 * Command completion and parsing routines.
 *
 * Robert W. Baldwin, December 1984.
 */


#include	<stdio.h>
#include	"window.h"
#include	"specs.h"
#include	"parser.h"


/* Return TRUE if the cmdstring equals the model string up to and including
 * the first space.
 */
int	cmpword(model, cmdstring)
char	*model, *cmdstring;
{
	while (*model != 0  &&  *cmdstring != 0) {
		if (*model == *cmdstring  &&  *model == ' ')  return (TRUE);
		if (*model != *cmdstring)  break;
		model++;
		cmdstring++;
		}
	if (*model == 0)  return(TRUE);
	return(FALSE);
}


/* Return TRUE if the first word of the cmdstring is a substring
 * of the first word of model string.
 */
int	submatch(model, cmdstring)
char	*model;
char	*cmdstring;
{
	while (*model != 0  &&  *cmdstring != 0) {
		if (*cmdstring == ' ')  break;
		if (*model != *cmdstring)  return(FALSE);
		if (*model == ' ')  break;
		model++;
		cmdstring++;
		}

	return(TRUE);
}



/* Lookup and perform a command from a command table.
 * If not found, return an error message.
 */
char	*cmddo(cmdtab, cmdstring)
cmdent	*cmdtab;
char	*cmdstring;
{
	for ( ; cmdtab->cmdname != 0 ; cmdtab++)  {
		if (cmpword(cmdtab->cmdname, cmdstring))  {
			return((*(cmdtab->cmdproc))(cmdstring));
			}
		}

	return(CMDBAD);
}



/* Do automatic completion of the string based on the
 * command choices in the command table.
 * Be careful to avoid doubly expanding a string, by requiring that
 * the first few characters to match, but the whole word must not match.
 * If sucessful, return a pointer to the template string
 * in the command table.  Otherwise return NULL.
 */
char	*cmdcomplete(cmdtab, cmdstring)
cmdent	*cmdtab;
char	*cmdstring;
{
	cmdent	*centp;
	char	*close;

	for (centp = cmdtab ; centp->cmdname != 0 ; centp++)  {
		if (cmpword(centp->cmdname, cmdstring))  {
			return(NULL);	/* Has been expanded. */
			}
		}

	close = NULL;
	for (centp = cmdtab ; centp->cmdname != 0 ; centp++)  {
		if (submatch(centp->cmdname, cmdstring))  {
			if (close != NULL)  return(NULL);	/* Not yet unique. */
			close = centp->cmdname;
			}
		}

	return(close);
}
