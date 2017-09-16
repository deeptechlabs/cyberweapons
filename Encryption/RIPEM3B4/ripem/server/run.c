/*--- run.c -- Routine(s) to run a Unix program and wait for the
 * output, collecting it in a buffer.
 *
 * Mark Riordan   9 Aug 1992
 * Public domain.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include "runprot.h"

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

/*--- function RunAndGetOutput -----------------------------------------
 *
 *  Run a program, and read its output (from stdout) into a buffer in 
 *  memory.
 *
 *  Entry:	prog		is the name of a program to run.
 *				argv		is a vector of arguments to pass.
 *	
 *	 Exit:	retval	is the return code of the run program.
 *				retbuf	points to a buffer in memory containing the output.
 *				bufsize  is the number of bytes in the buffer.
 *				errbuf   points to a buffer containing the stderr output.
 *				errbufsize  is the number of bytes in errbuf.
 */
int
RunAndGetOutput(prog,argv,retval,retbuf, bufsize,errbuf,errbufsize)
char *prog;
char *argv[];
int *retval;
char **retbuf;
int *bufsize;
char **errbuf;
int *errbufsize;
{
#define ALLOC_INC 2048
	static int p[2], errpipe[2];
	int stat;
	int alloc_size = ALLOC_INC;
	int nbytes_read, nbytes_left;
#ifdef __MACH__
	union wait statusp;
#else
	union __wait statusp;
#endif

	fflush(stdout);
	pipe(p);
	pipe(errpipe);
	if((stat = fork()) == 0) {
		/* This is the child process 
		 */
		 
		close(p[0]);
		dup2(p[1],STDOUT_FILENO);
		close(p[1]);
		
		close(errpipe[0]);
		dup2(errpipe[1],STDERR_FILENO);
		close(errpipe[1]);
		execv(prog,argv);
		/* If we get here, the exec didn't work. */
	} else if(stat > 0) {
		/* This is the parent process.
		 */
		*retbuf = malloc(alloc_size);
		*errbuf = malloc(alloc_size);
		nbytes_left = alloc_size;
		close(p[1]);
		close(errpipe[1]);
		
		while((nbytes_read = read(p[0],*retbuf,nbytes_left)) > 0 ) {
			nbytes_left -= nbytes_read;
			if(nbytes_left <= 0) {
				alloc_size += ALLOC_INC;
				nbytes_left += ALLOC_INC;
				*retbuf = realloc(*retbuf,alloc_size);
			}
		}
		*bufsize = alloc_size - nbytes_left;
		
		*errbufsize = read(errpipe[0],*errbuf,ALLOC_INC);
		
		close(p[0]);
		close(errpipe[0]);
		
		wait(&statusp);
		*retval = statusp.w_retcode;
	
		return 0;
	}
	return 1;
}
