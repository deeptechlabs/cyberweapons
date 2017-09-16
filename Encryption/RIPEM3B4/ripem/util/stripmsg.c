/*--- stripmsg.c -- Quick & dirty program to extract the encrypted
 *  message text from an encapsulated Privacy Enhanced Mail message.
 *  Better done in sed or awk, but I can't rely upon those on all
 *  platforms.
 * 
 *  Mark Riordan   13 May 1991
 *  This program is in the public domain (of course).
 */

#include <stdio.h>
#include <string.h>

main(argc,argv)
int argc;
char *argv[];
{
#define LINELEN 120
#define HEADER "-----PRIVACY-ENHANCED MESSAGE BOUNDARY-----"

	char line[LINELEN];
	enum enum_state {LOOKBEG, LOOKMSG, COPYLINES} state = LOOKBEG;

	if(argc > 1) {
		fputs("Usage:  stripmsg <rpem_enciphered_msg >enciphered_text_only",stderr);
		return 1;
	}
	while(fgets(line,LINELEN,stdin)) {
		switch(state) {
			case LOOKBEG:
				if(strncmp(line,HEADER,strlen(HEADER)) == 0) {
					state = LOOKMSG;
				}
				break;

			case LOOKMSG:
				if(line[0] == '\n') state = COPYLINES;
				break;
		
			case COPYLINES:
				if(strncmp(line,HEADER,strlen(HEADER)) == 0) {
					return 0;
				} else {
					fputs(line,stdout);
				}
				break;
		}
	}
}

