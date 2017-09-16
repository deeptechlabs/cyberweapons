/* uuencode.c - convert files to ascii-encoded form
 * Usage: uuencode [filename] < infile
 *
 * If [filename] isn't specified, "/dev/stdout" is the default.  This allows
 * use of my uudecode as a pipeline filter.
 *
 * Written and placed in the public domain by Phil Karn, KA9Q
 * 31 March 1987
 */
#include <stdio.h>
#define	LINELEN	45
main(argc,argv)
int argc;
char *argv[];
{
	char linebuf[LINELEN];
	register char *cp;
	int linelen;

	if(argc > 1)
		printf("begin 0666 %s\n",argv[1]);
	else
		printf("begin 0666 /dev/stdout\n");
	for(;;){
		linelen = fread(linebuf,1,LINELEN,stdin);
		if(linelen <= 0)
			break;
		putchar(' ' + linelen);	/* Record length */
		for(cp = linebuf; cp < &linebuf[linelen]; cp += 3){
		        putchar(' ' + ((cp[0] >> 2) & 0x3f));
			putchar(' ' + (((cp[0] << 4) & 0x30) | ((cp[1] >> 4) & 0xf)));
			putchar(' ' + (((cp[1] << 2) & 0x3c) | ((cp[2] >> 6) & 0x3)));
			putchar(' ' + (cp[2] & 0x3f));
		}
		putchar('\n');
	}
	printf(" \n");	/* 0-length null record */
	printf("end\n");
}

