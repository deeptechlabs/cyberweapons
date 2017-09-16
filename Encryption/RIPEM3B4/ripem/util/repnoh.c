/*--- repnoh.c -- Filter out the headers from a mail message
 * being replied to.
 * Input looks like this:
 * 
 *   From: xxx
 *   To: xxxx
 *   (etc., other mail headers)
 *   
 *=  > From
 *=  > Received: xxx
 *=  > (other mail headers from message being replied to)
 *=  >
 *   > Start of text of message being replied to.
 *   > etc.
 *
 * Our job is to remove the old mail headers, those marked with "=" above.
 *
 * Mark Riordan   19 May 93
 */

#include <stdio.h>

int
main(argc, argv)
int argc;
char *argv[];
{
#define LINELEN 2048

	enum {ST_OURHEAD, ST_REPHEAD, ST_REST} state = ST_OURHEAD;
	char line[LINELEN];
	
	while(fgets(line,LINELEN,stdin)) {
		switch(state) {
			case ST_OURHEAD:
				fputs(line,stdout);
				if(line[0] == '\n') state = ST_REPHEAD;
				break;
			case ST_REPHEAD:
				if(line[0] != '>') {
					fputs(line,stdout);
					state = ST_REST;
				} else if(line[1]=='\n' || (line[1]==' ' && line[2]=='\n')) {
					state = ST_REST;
				}
				break;
			case ST_REST:
				fputs(line,stdout);
				break;
		}
	}
	return 0;
}
