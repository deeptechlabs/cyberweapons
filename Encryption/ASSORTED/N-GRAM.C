/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

/* compute letter frequency stats for stdin text */

#include "header.h"

int main(int argc, char * argv[])
{
    int * trigrams;
    int * digrams;
    int * monograms;
    int suppress_other = FALSE;
    int print_tables = FALSE;
    int do_di = FALSE;
    int do_tri = FALSE;
    int tmp;
    int alpha_len = ALPHABET_LEN;
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
    opterr = 0;

    while ((z = getopt(argc, argv, "edtpsi:o:")) != EOF) {
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
	case 'p':
	    print_tables = TRUE;
	    break;
	case 's':
	    suppress_other = TRUE;
	    break;
	case 'd':
	    do_di = TRUE;
	    break;
	case 't':
	    do_di = TRUE;
	    do_tri = TRUE;
	    break;
	case '?':
	    errflg++;
	}
    }
    if (errflg) {
	usage(N_GRAM_USAGE);
    }

    /* compute the stats */
    total_read = 0;
    monograms = (int *)malloc(alpha_len * sizeof(int));
    if (monograms == NULL) {
	memory_error();
    }
    memset((void *)monograms, 0, alpha_len * sizeof(int));
    if (do_di) {
	digrams = (int *)malloc(alpha_len2 * sizeof(int));
	if (digrams == NULL) {
	    memory_error();
	}
	memset((void *)digrams, 0, alpha_len2 * sizeof(int));
    }
    if (do_tri) {
	trigrams = (int *)malloc(alpha_len3 * sizeof(int));
	if (trigrams == NULL) {
	    memory_error();
	}
	memset((void *)trigrams, 0, alpha_len3 * sizeof(int));
    }
    while ((tmp = getchar()) != EOF) {
	if ((tmp >= 0) && isalpha((char)tmp)) {
	    c = (char)tmp;
	    c = (char)tolower(c);
	    curr = (int)(c - 'a');
	    if (curr < (unsigned int)alpha_len) {
		total_read++;
		monograms[(int)curr]++;
		if (do_di && (total_read > 1)) {
		    digrams[(int)prev * 26 + (int)curr]++;
		    if (do_tri && (total_read > 2)) {
			trigrams[(int)prevprev * alpha_len2 +
				 (int)prev * alpha_len + (int)curr]++;
		    }
		}
		prevprev = prev;
		prev = curr;
	    }
	}
    }

    printf("\n");
    printf("Total read: %d characters\n", total_read);
    printf("\n");

    if (print_tables) {
	if (!(suppress_other && do_di)) {
	    /* display single letter frequencies */
	    for (i = 0; i < 13; i++) {
		printf("                    %c %8d                 %c %8d\n",
		       (i + 'A'), monograms[i], (i + 'N'), monograms[i + 13]);
	    }
	    printf("\n");
	}

	if (do_di && !(suppress_other && do_tri)) {
	    /* display double letter frequencies */
	    printf("  ");
	    for (c = 'A'; c <= 'M'; c++) {
		printf("     %c", c);
	    }
	    printf("\n");
	    for (i = 0; i < 26; i++) {
		printf(" %c", (i + 'A'));
		for (j = 0; j < 13; j++) {
		    printf("%6d", digrams[i * 26 + j]);
		}
		printf("\n");
	    }
	    printf("\n  ");
	    for (c = 'N'; c <= 'Z'; c++) {
		printf("     %c", c);
	    }
	    printf("\n");
	    for (i = 0; i < 26; i++) {
		printf(" %c", (i + 'A'));
		for (j = 13; j < 26; j++) {
		    printf("%6d", digrams[i * alpha_len + j]);
		}
		printf("\n");
	    }
	    printf("                  (First letter down, second across)\n");
	}

	if (do_tri) {
	    /* display triple letter frequencies */
	    for (k = 0; k < 26; k++) {
		printf("\n  ");
		for (c = 'A'; c <= 'M'; c++) {
		    printf("     %c", c);
		}
		printf("\n");
		for (i = 0; i < 26; i++) {
		    printf("%c%c", (char)(k + 'A'), (char)(i + 'A'));
		    for (j = 0; j < 13; j++) {
			printf("%6d", trigrams[k * alpha_len2 +
					       i * alpha_len + j]);
		    }
		    printf("\n");
		}
		printf("\n  ");
		for (c = 'N'; c <= 'Z'; c++) {
		    printf("     %c", c);
		}
		printf("\n");
		for (i = 0; i < 26; i++) {
		    printf("%c%c", (char)(k + 'A'), (char)(i + 'A'));
		    for (j = 13; j < 26; j++) {
			printf("%6d", trigrams[k * alpha_len2 +
					       i * alpha_len + j]);
		    }
		    printf("\n");
		}
		printf("           (First two letters down, third across)\n");
	    }
	}
    }
    return(0);
}
