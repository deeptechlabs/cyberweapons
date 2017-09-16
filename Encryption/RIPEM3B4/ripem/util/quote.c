/* quote.c -- Read a mail message and "quote" it, writing the
 * message with a ">" at the beginning of each line.
 *
 * Mark Riordan  22 July 92 & 8 Nov 92
 * Vesselin Bontchev 18 January 93
 */
#include <stdio.h>
#include <string.h>

#define QUOTE_STRING	"> "
#define LINELEN 2000

static char *author = "Mark Riordan  mrr@scss3.cl.msu.edu  8 Nov 92";
int
main(argc,argv)
int argc;
char *argv[];
{
	static char line[LINELEN], to_line[LINELEN];
	extern char *optarg;
	FILE *instream=stdin, *outstream=stdout;
	int keep_headers=0, in_headers=1, you_wrote=0;
	int ch;

	while((ch = getopt(argc,argv,"i:o:h")) != -1) {
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
		case 'h':
			keep_headers = 1;
			break;
		default:
			fputs("Usage: quote [-i msg] [-o outmsg] [-h]\n",stderr);
			fputs("  where -h means pass the mail headers through unmodified.\n",stderr);
			return 1;
		}
	}

	while(fgets(line,LINELEN,instream)) {
		if(in_headers && keep_headers) {
			fputs(line,outstream);
			if (strncmp (line,"From: ",6) == 0)
				strncpy (to_line,line+6,strlen(line)-6-1);
			if(line[0]=='\n')
				in_headers = 0;
		} else {
			if(!you_wrote) {
				fputs(to_line,outstream);
				fputs(" writes:\n",outstream);
				you_wrote = 1;
			}
			fputs(QUOTE_STRING,outstream);
			fputs(line,outstream);
		}
	}
	return 0;
}
