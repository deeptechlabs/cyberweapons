/*--- man2code.c -- Program to read a text file and generate
 *  C source code to make strings.
 *  Used for making program "Usage" messages from man pages.
 *
 *  Mark Riordan   12 May 92
 */
#include <stdio.h>
#include <string.h>
#include "../cmdline/getoptpr.h"
#include "../main/version.h"

int
main(argc,argv)
int argc;
char *argv[];
{
#define LINELEN 200
	char line[LINELEN];
	int curlen, lastlen=99, linenum=0;
   FILE *instream=stdin, *outstream=stdout;
	int ch;
	char *cptr, mych;
	extern char *optarg;

	while((ch = getopt(argc,argv,"i:o:")) != -1) {
      switch (ch) {
			case 'i':
				instream = fopen(optarg,"r");
            if(!instream) {
					fprintf(stderr,"Cannot open %s\n",optarg);
					return 1;
				}
				break;
			case 'o':
				outstream = fopen(optarg,"w");
            if(!outstream) {
					fprintf(stderr,"Cannot open %s\n",optarg);
					return 1;
				}
				break;
			default:
				fputs("Usage: man2code -i manpage -o c_code\n",stderr);
				return 1;
		}
	}

	fputs("char *usage_msg[] = {\n",outstream);

	for(; fgets(line,LINELEN,instream); lastlen = curlen,linenum++) {
		/* For multiple blank lines, only put out one blank line. */
		curlen = strlen(line);
		if(curlen+lastlen <= 2) continue;

		/* Quote special characters in the input text with \ */
		fputs(" \"",outstream);
		for(cptr=line; *cptr; cptr++) {
			if(*cptr != '\n') {
	         mych = *cptr;
				if(mych == '\"') putc('\\',outstream);
				else if(mych == '\\') putc('\\',outstream);
				putc(mych,outstream);
			}
		}
		/* Tack on the version number to the first line */
		if(linenum==0) {
			fputs(VERSION,outstream);
		}
		fputs("\",\n",outstream);
	}
	fputs("(char *)0\n",outstream);
	fputs("};\n",outstream);

	return 0;
}
