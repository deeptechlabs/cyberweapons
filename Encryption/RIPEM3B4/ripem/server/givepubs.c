/*--- givepubs -- Program to respond to an email request for a file.
 *
 *  This program responds to an incoming mail message, in particular a request
 *  for the RIPEM public key database.
 *  It reads the request message from standard input.  It
 *  constructs a reply message from the headers of that message and
 *  copies the contents of a specified file into that reply message.
 *  It then sends the reply message.
 *
 *  This program is meant to be called by the mail system;
 *  put a line in /etc/aliases that looks something like:
 *  ripem-get-keys: |/home/scss3/mrr/cip/ripem/givepubs
 *  
 *  With this arrangement, the message is available on standard input.  
 *
 *  By Mark Riordan   1 August 1992.
 *  This program is in the public domain.
 */

#include <stdio.h>
#include "boolean.h"
#include "srvfiles.h"
#include "strutilp.h"
#include "givepubp.h"
#include "startnep.h"
#include "getretap.h"

extern int mkstemp(char *template);

int
main(argc,argv)
int argc;
char *argv[];
{
#define BUFSIZE 8192
	int msgfd;
	char *file_name = SERVER_KEY_FLAT_FILE;
	char *subject = "RIPEM Public Keys";
	char *return_addr;
	int ch, nitems;
	char buf[BUFSIZE];
	extern char *optarg;
	FILE *file_stream, *instream=stdin, *msgstream;
	
	
	strcpy(buf,KEY_FILE_TEMPLATE);  /* Set default directory name. */
	
   while(-1 != (ch = getopt(argc,argv,"f:s:"))) {
      switch(ch) {
			case 'f':  /* file name */
				file_name = optarg;
				break;
			case 's':  /* subject */
				subject = optarg;
				break;
			default:
				fputs("givepubs: program to respond to email request.\n",stderr);
				fputs("Usage:  copymail [-f filename] [-s subject]\n",stderr);
				return 1;
				break;
		}
	}

	file_stream = fopen(file_name,"r");
	if(!file_stream) {
		fprintf(stderr,"Can't open file %s\n",file_name);
		return 1;
	}
	
	return_addr = GetReturnAddress(instream);
	if(!return_addr) {
		fprintf(stderr,"Can't find return address.\n");
		return 2;
	}
	
	if(StartNetMail(return_addr,&msgfd)) {
		fprintf(stderr,"Can't start sending mail message.\n");
		return 3;
	}
	
	msgstream = fdopen(msgfd,"w");
	
	fprintf(msgstream,"To: %s\n",return_addr);
	fprintf(msgstream,"Subject: %s\n",subject);
	fprintf(msgstream,"\n");
	
	while(nitems=fread(buf,1,BUFSIZE,file_stream)) {
		fwrite(buf,1,nitems,msgstream);
	}
	fclose(msgstream);
	fclose(file_stream);
	
	return 0;
}
