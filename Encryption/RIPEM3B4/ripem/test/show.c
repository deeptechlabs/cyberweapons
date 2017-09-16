/*--- show.c -- display a range of lines.
 *
 *  Mark Riordan   29 Dec 1990
 */
 
#include <stdio.h>

#define BUFLEN 32768

char buf[BUFLEN+1];

static char *author = "Mark Riordan  1100 Parker  Lansing, MI  48912  Dec 1990";
 
int
main(argc,argv)
int argc;
char *argv[];
{
	int inhand, outhand;
	int read_chars;
	long int start_line, end_line, cur_line=1L;
	char *endptr = &buf[BUFLEN], *begptr;
	register char *cptr = endptr;
	
	buf[BUFLEN] = 'E';
	if(argc != 2) usage();
	if(2 != sscanf(argv[1],"%ld-%ld",&start_line,&end_line)) {
		usage();
	}
	inhand = fileno(stdin);
	outhand = fileno(stdout);
	
	while(cur_line < start_line) {
		while(cptr<endptr && *cptr != '\n') cptr++;
		if(cptr == endptr) {
			read_chars = read(inhand,buf,BUFLEN);
			if(read_chars <= 0) exit(0);
			endptr = &buf[read_chars];
			cptr = buf;
		} else {
			cur_line++;
			cptr++;
		}
	}
	begptr = cptr;
	
	while(cur_line <= end_line) {
		while(cptr<endptr && *cptr != '\n') cptr++;
		if(cptr >= endptr) {
			write(outhand,begptr,endptr-begptr);
			read_chars = read(inhand,buf,BUFLEN);
			if(read_chars <= 0) exit(0);
			endptr = &buf[read_chars];
			begptr = buf;
			cptr = buf;
		} else {
			cur_line++;
			cptr++;
		}
	}
	
	write(outhand,begptr,cptr-begptr);
	return 0;
}

usage()
{
	fputs("Usage:  show startline-endline <in >out\n",stdout);
	exit(1);
}
