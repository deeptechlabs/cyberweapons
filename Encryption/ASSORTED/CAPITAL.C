/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

#include "header.h"

int main(int argc, char * argv[])
{
    char c;
    int z;
    int lowercase = FALSE;
    extern char * optarg;
    extern int opterr;
    int errflg = 0;

    opterr = 0;
    while ((z = getopt(argc, argv, "li:o:")) != EOF) {
	switch ((char)z) {
	case 'i':
	    if (freopen(optarg, "r", stdin) == NULL) {
		file_open_error();
	    }
	    break;
	case 'o':
	    if (freopen(optarg, "w", stdout) == NULL) {
		file_open_error();
	    }
	    break;
	case 'l':
	    lowercase = TRUE;
	    break;
	case '?':
	    errflg = TRUE;
	}
    }
    if (errflg) {
	usage(CAPITAL_USAGE);
    }

    while ((z = getchar()) != EOF) {
	c = (char)z;
	if (isalpha(c)) {
	    if (lowercase) {
		c = tolower(c);
	    } else {
		c = toupper(c);
	    }
	}
	putchar(c);
    } 
    return(0);
}
