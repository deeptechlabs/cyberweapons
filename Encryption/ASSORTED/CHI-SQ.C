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
    double chi_sq;
    double expected;
    double observed;
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
	usage(CHI_SQ_USAGE);
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

    chi_sq = 0;
    for (i = 0; i < alpha_len; i++) {
	expected = (double)total_read / (double)alpha_len;
	observed = (double)monograms[i];
	chi_sq += (observed - expected) * (observed - expected) / expected;
    }
    printf("\t1-gram chi_sq = %g, v = %d\n", chi_sq, alpha_len - 1);

    if (do_2) {
	chi_sq = 0;
	for (i = 0; i < alpha_len; i++) {
	    for (j = 0; j < alpha_len; j++) {
		expected = (double)total_read / (double)alpha_len2;
		observed = (double)digrams[i * alpha_len + j];
		chi_sq += (observed - expected) *
		    (observed - expected) / expected;
	    }
	}
	printf("\t2-gram chi_sq = %g, v = %d\n", chi_sq, alpha_len2 - 1);
    }
    
    if (do_3) {
	chi_sq = 0;
	for (i = 0; i < alpha_len; i++) {
	    for (j = 0; j < alpha_len; j++) {
		for (k = 0; k < alpha_len; k++) {
		    expected = (double)total_read / (double)alpha_len3;
		    observed = (double)trigrams[i * alpha_len2 +
						j * alpha_len + k];
		    chi_sq += (observed - expected) *
			(observed - expected) / expected;
		}
	    }
	}
	printf("\t3-gram chi_sq = %g, v = %d\n", chi_sq, alpha_len3 - 1);
    }
    
    return(0);
}
