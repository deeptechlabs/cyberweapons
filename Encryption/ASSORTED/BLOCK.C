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
    int chars = 0;
    int blocks = 0;
    int chars_per_block = BLOCK_DEFAULT_CHARS_PER_BLOCK;
    int blocks_per_line = 0;
    extern int opterr;
    extern char *optarg;
    int errflg = 0;

    opterr = 0;
    while ((z = getopt(argc, argv, "c:b:i:o:")) != EOF) {
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
	case 'b':
	    blocks_per_line = atoi(optarg);
	    break;
	case 'c':
	    chars_per_block = atoi(optarg);
	    break;
	case '?':
	    errflg = TRUE;
	}
    }
    if (errflg) {
	usage(BLOCK_USAGE);
    }

    if (blocks_per_line <= 0) {
	blocks_per_line = 80 / (chars_per_block + 1);
    }

    z = getchar();
    do {
	c = (char)z;
	printf("%c", c);
	chars++;
	if (chars == chars_per_block) {
	    chars = 0;
	    blocks++;
	    if (blocks == blocks_per_line) {
		blocks = 0;
		printf("\n");
	    } else {
		printf(" ");
	    }
	}
    } while ((z = getchar()) != EOF);
    if (blocks != 0 || chars != 0) {
	printf("\n");
    }
    return(0);
}
