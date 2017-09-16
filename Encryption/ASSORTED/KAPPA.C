/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

/*
  program to slide a text against itself looking for matches

  NOTE: It does NOT strip out non-alpha characters or uppercase anything.
  use another program for that.
  
  should be re-written to operate without loading everything into memory first.
  */
    
#include "header.h"

int main(int argc, char * argv[])
{
    int * hits;
    int period;
    int i;
    int length = 0;
    int bufsize;
    char * buffer;
    int maxkey = KAPPA_DEF_MAXKEY;
    float hitrate;
    float threshold = KAPPA_DEF_THRESHOLD;
    int z;
    extern int opterr;
    extern char *optarg;
    int errflg = 0;
    
    opterr = 0;
    while ((z = getopt(argc, argv, "m:t:i:o")) != EOF) {
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
	case 'm':
	    maxkey = atoi(optarg);
	    break;
	case 't':
	    threshold = atof(optarg);
	    break;
	case '?':
	    errflg = TRUE;
	}
    }
    if (errflg) {
	usage(KAPPA_USAGE);
    }
    
    hits = (int *)malloc((maxkey + 1) * sizeof(int));
    bufsize = (maxkey > 63) ? maxkey + 1 : 64;
    buffer = (char *)malloc(bufsize * sizeof(char));
    if (hits == NULL || buffer == NULL) {
	memory_error();
    }
    
    for (i = 0; i <= maxkey; i++) {
	hits[i] = 0;
    }

    while ((z = getchar()) != EOF) {
	buffer[length % bufsize] = (char)z;
	for (period = 1; period <= maxkey; period++) {
	    if (length >= period) {
		if (buffer[length % bufsize] ==
		    buffer[(length - period) % bufsize]) {
		    hits[period]++;
		}
	    }
	}
	length++;
    } 

    printf("Offset\t Hits\t  %% Hits\n");
    for (period = 1; period <= maxkey; period++) {
	hitrate = (float)hits[period] * 100 / (float)(length - (period));
	printf("%4d\t%5d\t%10.6f", period, hits[period], hitrate);
	if (hitrate > threshold) {
	    printf("  <===\n");
	} else {
	    printf("\n");
	}
    }	
    printf("Total letters checked: %d\n", length);
    return(0);
}
