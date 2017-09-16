/* quote.c -- Read a mail message and "quote" it, writing the
 * message with a ">" at the beginning of each line.
 *
 * Mark Riordan  22 July 92 & 8 Nov 92
 */
#include <stdio.h>

static char *author = "Mark Riordan  mrr@scss3.cl.msu.edu  8 Nov 92";
int
main(argc,argv)
int argc;
char *argv[];
{
#define LINELEN 2000
	char line[LINELEN];
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

	while(fgets(line,LINELEN,stdin)) {
		if(in_headers && keep_headers) {
			fputs(line,outstream);
			if(line[0]=='\n') in_headers = 0;
		} else {
			if(!you_wrote) {
				fputs("You wrote:\n",outstream);
				you_wrote = 1;
			}
			fputs("> ",outstream);
			fputs(line,outstream);
		}
	}
	return 0;
}
