/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

#include "header.h"

int main(int argc,char *argv[])
{
    char c;
    char * key = NULL;
    int z;
    int decrypt = 0;
    extern int optind, opterr;
    extern char * optarg;
    
    /* parse the arguments and find the key */
    opterr = 0;
    while ((z = getopt(argc, argv, "dk:i:o:")) != EOF) {
	switch (z) {
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
	case 'd':
	    decrypt = 1;
	    break;
	case 'k':
	    key = get_key(optarg);
	    break;
	case '?':
	    usage(CAESAR_USAGE);
	}
    }
    if (key == NULL) {
	if (argv[optind] == NULL) {
	    usage(CAESAR_USAGE);
	}
	key = get_key(argv[optind]);
    }

    if (strlen(key) != 1) {
	die("Key must be a single character\n", -43);
    }
    
    while ((z = getchar()) != EOF) {
	c = (char)z;
        if (isalpha(c)) {
	    c = l2n(c);
	    if (! decrypt) {
		c = (c + l2n(*key)) % ALPHABET_LEN;
	    } else {
		c = (c + ALPHABET_LEN - l2n(*key)) % ALPHABET_LEN;
	    }
	    c = n2l(c);
        }
	putchar(c);
    } 
    return(0);
}
