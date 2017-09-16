/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

#include "header.h"

int main(int argc, char * argv[])
{
    int alpha_len = 26;
    int * trigrams;
    int * digrams;
    int * monograms;
    int use_everything = FALSE;
    int do_2 = FALSE;
    int do_3 = FALSE;
    int tmp;
    unsigned int curr = 0;
    unsigned int prev = 0;
    unsigned int prevprev = 0;
    int i, j, k;
    int total_read;
    int z;
    char c;
    extern char * optarg;
    extern int opterr;
    int errflg = 0;
    double entropy;
    double probability;
    opterr = 0;
    while ((z = getopt(argc, argv, "e23i:o:")) != EOF) {
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
	case 'e':
	    use_everything = TRUE;
	    alpha_len = 256;
	    break;
	case '2':
	    do_2 = TRUE;
	    break;
	case '3':
	    do_2 = TRUE;
	    do_3 = TRUE;
	    break;
	case '?':
	    errflg++;
	}
    }
    if (errflg) {
	usage(ENTROPY_USAGE);
    }

    /* compute the stats */
    total_read = 0;
    monograms = (int *)malloc(alpha_len * sizeof(int));
    if (monograms == NULL) {
	memory_error();
    }
    memset((void *)monograms, 0,
	   alpha_len * sizeof(int));
    if (do_2) {
	digrams = (int *)malloc(alpha_len2 * sizeof(int));
	if (digrams == NULL) {
	    memory_error();
	}
	memset((void *)digrams, 0, alpha_len2 * sizeof(int));
    }
    if (do_3) {
	trigrams = (int *)malloc(alpha_len3 * sizeof(int));
	if (trigrams == NULL) {
	    memory_error();
	}
	memset((void *)trigrams, 0, alpha_len3 * sizeof(int));
    }
    while ((tmp = getchar()) != EOF) {
	if (use_everything || ((tmp >= 0) && isalpha((char)tmp))) {
	    if (use_everything) {
		curr = (unsigned)tmp;
	    } else {
		c = (char)tmp;
		c = (char)tolower(c);
		curr = (int)(c - 'a');
	    }
	    if (curr < (unsigned int)alpha_len) {
		total_read++;
		monograms[(int)curr]++;
		if (do_2 && (total_read > 1)) {
		    digrams[(int)prev * 26 + (int)curr]++;
		    if (do_3 && (total_read > 2)) {
			trigrams[(int)prevprev * alpha_len2 +
				 (int)prev * alpha_len + (int)curr]++;
		    }
		}
		prevprev = prev;
		prev = curr;
	    }
	}
    }

    printf("\tTotal processed: %d characters\n", total_read);

    entropy = 0;
    for (i = 0; i < alpha_len; i++) {
	if (monograms[i] != 0) {
	    probability = (double)monograms[i] / (double)total_read;
	    entropy = entropy - probability * log2(probability);
	}
    }
    printf("\t1-gram entropy = %g, max possible = %g\n",
	   entropy, log2(alpha_len));

    if (do_2) {
	entropy = 0;
	for (i = 0; i < alpha_len; i++) {
	    for (j = 0; j < alpha_len; j++) {
		if (digrams[i * alpha_len + j] != 0) {
		    probability = (double)digrams[i * alpha_len + j] /
			(double)(total_read - 1);
		    entropy = entropy - probability * log2(probability);
		}
	    }
	}
	printf("\t2-gram entropy = %g, max possible = %g\n",
	       entropy, log2(alpha_len2));
    }
    
    if (do_3) {
	entropy = 0;
	for (i = 0; i < alpha_len; i++) {
	    for (j = 0; j < alpha_len; j++) {
		for (k = 0; k < alpha_len; k++) {
		    if (trigrams[i * alpha_len2 + j * alpha_len + k] != 0) {
			probability =
			    (double)trigrams[i * alpha_len2 +
					     j * alpha_len + k] /
						 (double)(total_read - 2);
			entropy = entropy - probability * log2(probability);
		    }
		}
	    }
	}
	printf("\t3-gram entropy = %g, max possible = %g\n",
	       entropy, log2(alpha_len3));
    }
    
    return(0);
}
