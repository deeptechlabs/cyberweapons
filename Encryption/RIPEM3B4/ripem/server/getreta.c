/*--- getreta.c ---*/

#include <stdio.h>
#include <string.h>
#include "boolean.h"
#include "strutilp.h"

/*--- function GetReturnAddress ------------------------------------------
 *
 *  Read the header section of a file containing an electronic mail
 *  message, and extract the email address of the sender.
 *  Look for a "Reply-To:", or else a "From:" line.
 *
 *  Entry	instream		is a stream containing lines of an email message.
 *
 *	 Exit		Returns a pointer to the sender's address, else NULL.
 *				The string (if any) is alloc'ed.
 *				instream is positioned after the first blank line.
 */
 
char *
GetReturnAddress(instream)
FILE *instream;
{
	enum {GOT_NOTHING, GOT_FROM, GOT_REPLY_TO} state = GOT_NOTHING;
#define LINELEN 1024
	char line[LINELEN];
	BOOL processing = TRUE;
	char *reply_addr = NULL, *cptr;
	
	while(processing) {
		if(!fgets(line,LINELEN,instream)) break;
			
		if(LineIsWhiteSpace(line)) break;
		
		if(matchn(line,"Reply-To:",9)) {
			cptr = ExtractEmailAddr(line+9);
			if(reply_addr) free(reply_addr);
			strcpyalloc(&reply_addr,cptr);
			break;
		} else if(matchn(line,"From:",5) && state == GOT_NOTHING) {
			/* Accept a From: only if it's the first one & we've seen no 
			 * Reply-To: 
			 */
			state = GOT_FROM;
			cptr = ExtractEmailAddr(line+5);
			if(reply_addr) free(reply_addr);
			strcpyalloc(&reply_addr,cptr);
		}
	}
	
	return reply_addr;
}

