/*--- sendnetmail.c -- Routine to send a mail message.
 *
 *  Mark Riordan  11 July 1992, from an earlier version by me in
 *  March 1988, from a routine by someone else.
 */
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include "../main/list.h"
#include "../main/listprot.h"
 
#define MAIL	"/usr/lib/sendmail"
#define NOFILE	20

#ifndef lint
static	char sccsid[] = "%W% (%Y%) %G%";
		/* from SMI 1.1 86/09/25 from UCB 4.11 83/05/19 */
#endif

/* Start of Correction History
 *
 *
 * End of Correction History
 */

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

/*--- function SendNetMail --------------------------------------------------
 *
 *  Send an email message.
 *
 *  Entry:	eMailAddr	is an address acceptable to "sendmail" to which
 *								the message should be sent.
 *				lineList		points to a list of pointers to zero-terminated lines
 *								which comprise the message.  No newlines are
 *								embedded in these lines.  
 *
 *	 Exit:	Returns zero if successful.
 */
int
SendNetMail(eMailAddr,lineList)
char *eMailAddr;
TypList *lineList;
{
#define BUFSIZE 4096
#define THRESHOLD 3000
	static int p[2];
	TypListEntry *entry_ptr = lineList->firstptr;
	int stat;
	register char *cp;
	char buf[BUFSIZE], *bufptr, *lptr;
	int sendfd;

	fflush(stdout);
	pipe(p);
	if ((stat = fork()) == 0) {		
		/* This is the child process.
		 *
		 * Close the write end of the pipe, as we only read from it.
		 * Then link the read end of the pipe to standard input.
		 */
		 
		close(p[1]);
		dup2(p[0], STDIN_FILENO);
		close(p[0]);  /* Close this descriptor, as we no longer need it. */

		/* Find the base name of the mail program to include as the
		 * "argv[0]" of the exec'ed sendmail.
		 */
		if ((cp = (char *)rindex(MAIL, '/')) != NULL)
			cp++;
		else
			cp = MAIL;
		execl(MAIL, cp, eMailAddr, 0);
		exit(0);
	} else if (stat > 0) {	
		/* This is the parent process.
		 *
		 * Close the read end of the pipe, as we don't use it.
		 */
		close(p[0]);
		sendfd = p[1];
		
		/* Write the lines out to the pipe, where the child can read them.
		 * Because we are using descriptors and not streams, we use "write"
		 * rather than something like "fputs".
		 */
		bufptr = buf;
		for(; entry_ptr; entry_ptr = entry_ptr->nextptr) {
			for(lptr=(char *)entry_ptr->dataptr; *lptr; lptr++) {
				*(bufptr++) = *lptr;
			}
			*(bufptr++) = '\r';
			*(bufptr++) = '\n';
			if(bufptr-buf>THRESHOLD) {
				write(sendfd,buf,bufptr-buf);
				bufptr = buf;
			}
		}
		if(bufptr != buf) {
			write(sendfd,buf,bufptr-buf);
		}
		(void) close(sendfd);
	}
#if 0
	/* Wait for the child (sendmail) to complete. */
	wait(&stat);
#endif
	return 0;
}
