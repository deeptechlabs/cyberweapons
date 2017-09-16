/*--- copymail -- Program to copy incoming mail to a unique file name.
 *
 *  This program copies an incoming mail message, in particular a request
 *  to register a RIPEM public key, into a directory for later processing.
 *  The technique of copying mail messages first to a file and then
 *  later processing them is presumed to be more reliable than 
 *  trying to process the message "live", where something could go
 *  wrong during database access and the message lost.
 *
 *  This program is meant to be called by the mail system;
 *  put a line in /etc/aliases that looks something like:
 *  ripem-keys: |/home/scss3/mrr/cip/ripem/mailserv
 *  
 *  With this arrangement, the message is available on standard input.  
 *
 *  By Mark Riordan   10 July 1992.
 *  This program is in the public domain.
 */

#include <stdio.h>
#include "srvfiles.h"

extern int mkstemp(char *template);

int
main(argc,argv)
int argc;
char *argv[];
{
#define BUFSIZE 8192
	int keyfd, ch, nitems;
	char buf[BUFSIZE];
	extern char *optarg;
	
	strcpy(buf,SERVER_INCOMING_KEY_DIR);  /* Set default directory name. */
	
   while(-1 != (ch = getopt(argc,argv,"d:"))) {
      switch(ch) {
			case 'd':  /* directory name */
				strcpy(buf,optarg);
				break;
			default:
				fputs("copymail: program to copy incoming mail to a directory.\n",stderr);
				fputs("Usage:  copymail [-d directory_name]\n",stderr);
				return 1;
				break;
		}
	}

	chdir(buf);
	strcpy(buf,KEY_FILE_TEMPLATE);
	keyfd = mkstemp(buf);
	if(keyfd < 0) {
		fprintf(stderr,"Can't create key file.\n");
		return 1;
	}
	
	fchmod(keyfd,0666);  /* Allow group & others to read & write */
	
	while(nitems=fread(buf,1,BUFSIZE,stdin)) {
		write(keyfd,buf,nitems);
	}
	return 0;
}