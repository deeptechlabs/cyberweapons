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
    char key_shift;
    int i,key_len;
    int z;
    int alpha_len = ALPHABET_LEN;
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
	    usage(VIGENERE_USAGE);
	}
    }
    if (key == NULL) {
	if (argv[optind] == NULL) {
	    usage(VIGENERE_USAGE);
	}
	key = get_key(argv[optind]);
    }

    key_len = strlen(key);
    i = 0;
    while ((z = getchar()) != EOF) {
	c = (char)z;
        if (isalpha(c)) {
	    c = l2n(c);
	    key_shift = l2n(*(key + i));
	    if (! decrypt) {
		c = (c + key_shift) % alpha_len;
	    } else {
		c = (c + alpha_len - key_shift) % alpha_len;
	    }
	    c = c + (isupper(*(key + i)) ? 'A' : 'a');
            i++;
            i %= key_len;
        }
	putchar(c);
    }
    return(0);
}
