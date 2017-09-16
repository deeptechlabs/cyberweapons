/*--- testrun.c -- Simple program to test "run.c".
 *
 */
#include <stdio.h>
#include "runprot.h"

char *myargv[] = {"date","junk",NULL};

int
main(argc,argv)
int argc;
char *argv[];
{
	char *buf, *errbuf;
	int retcode, j, bufsize, errbufsize;
	
	RunAndGetOutput("one",myargv,&retcode,&buf, &bufsize, &errbuf, &errbufsize);

	printf("Retcode = %d.   Buffer has %d chars:\n",retcode, bufsize);
	for(j=0; j<bufsize; j++) putchar(buf[j]);
	printf("\nErrbuf contains %d chars:\n",errbufsize);
	for(j=0; j<bufsize; j++) putchar(errbuf[j]);

	return 0;
}