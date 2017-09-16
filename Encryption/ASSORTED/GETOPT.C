/*
  getopt.c
  
  get option letter from argument vector

  Based on a version posted in volume 1 of comp.sources.unix
  */

#include <stdio.h>

int opterr = 1,
    optind = 1,
    optopt;
    char *optarg;
      
#define BADCH (int)'?'
#define EMSG ""
#define tell(s) fputs(*nargv,stderr);fputs(s,stderr); \
                fputc(optopt,stderr);fputc('\n',stderr);return(BADCH);
      
int getopt(int nargc,char ** nargv,char * ostr)
{
    static char *place = EMSG;
    register char *oli;
    char *index();
    
    if (!*place) {
	if (optind >= nargc || *(place = nargv[optind]) != '-' || !*++place) {
	    return(EOF);
	}
	if (*place == '-') {
	    ++optind;
	    return(EOF);
	}
    }
    if ((optopt = (int)*place++) == (int)':' || !(oli = index(ostr,optopt))) {
	if (!*place) {
	    ++optind;
	}
	tell(": illegal option -- ");
    }
    if (*++oli != ':') {
	optarg = NULL;
	if (!*place) {
	    ++optind;
	}
    } else {
	if (*place) {
	    optarg = place;
	} else if (nargc <= ++optind) {
	    place = EMSG;
	    tell(": option requires an argument -- ");
	} else {
	    optarg = nargv[optind];
	}
	place = EMSG;
	++optind;
    }
    return(optopt);
}
