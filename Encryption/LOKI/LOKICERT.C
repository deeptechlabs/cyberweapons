/*
 *	lokicert.c - invoke the LOKI library with data from a certification
 *		database, to validate its correct operation.
 *
 *  Author: Lawrence Brown <lpb@cs.adfa.oz.au>      Dec 1987
 *      Computer Science, UC UNSW, Australian Defence Force Academy,
 *          Canberra, ACT 2600, Australia.
 *
 *	Based on PD program by Phil Karn, KA9Q <karn@flash.bellcore.com>
 *
 *  Copyright 1989 by Lawrence Brown and UNSW. All rights reserved.
 *      This program may not be sold or used as inducement to buy a
 *      product without the written permission of the author.
 */


#include "loki.h"
#include <stdio.h>

#ifndef lint
static char rcsid[]  = "$Header: lokicert.c,v 2.1 90/07/18 10:51:41 lpb Exp $";
#endif

char	*Name = "";		/* name this program was called by */
char	*usage = "lokicert [testfile]";
FILE	*filein = stdin;	/* input file to be processed                */

main(argc, argv)
int	argc;
char	**argv;
{
	char	ikey[20], iplain[20], ianswer[20];
	Long	key[2],plain[2],cipher[2],answer[2];
	int	test = 0,			/* current test number*/
		fail = 0,			/* failure indicator  */
		failcnt = 0;			/* count of failures  */
	char	buf[256];			/* input buffer, hex block */

	/* parse input args if any */
	Name = argv[0];
	if (argc > 1) {			/* get input file name */
        	if ((filein = fopen(argv[1], "r")) == NULL) {
                	fprintf(stderr,"%s: unable to open input file %s\n",
				Name, argv[1]);
			perror(Name);
			exit(1);
		}
	}

	while ( fgets(buf, sizeof(buf), filein) != NULL) { /* read next line  */
		if (buf[0] == '#')
			continue;	/* skip comment lines                 */
		test++;
	    	sscanf(buf, "%s %s %s", ikey, iplain, ianswer);
		get8(ikey, (char *)key);
		get8(iplain, (char *)plain);
		get8(ianswer, (char *)answer);

		printf("Test %2d, ", test);
		printf(" K: "); put8((char *)key);
		printf(" P: "); put8((char *)plain);
		printf(" C: "); put8((char *)answer);

		setlokikey((char *)key);

		cipher[0] = plain[0]; cipher[1] = plain[1];
		enloki((char *)cipher);

		fail = 0;
		if ((cipher[0] != answer[0]) || (cipher[1] != answer[1])) {
			printf("Encrypt failed, got: "); 
			put8((char *)cipher);
			fail++;
		} 

		deloki((char *)cipher);

		if ((cipher[0] != plain[0]) || (cipher[1] != plain[1])) {
			printf("Decrypt failed, got: "); 
			put8((char *)cipher);
			fail++;
		}

		if (!fail)
			printf("OK");
		else
			failcnt++;
		printf("\n");
		fflush(stdout);
	}
	printf("lokicert: %d failures in %d tests\n", failcnt, test);
	exit(failcnt);				/* exit with status set */
}

get8(inp, cp)
char *inp, *cp;
{
	int i,t[8];

	sscanf(inp, "%2x%2x%2x%2x%2x%2x%2x%2x",
		&t[0], &t[1], &t[2], &t[3], &t[4], &t[5], &t[6], &t[7]);
	for(i=0;i<8;i++){
		cp[i] = t[i];
	}
}

put8(cp)
char *cp;
{
	int i;

	for(i=0;i<8;i++){
		printf("%02x",*cp++ & 0xff);
	}
	putchar(' ');
}
