/*
 * Copyright (c) 1991 David G. Koontz.
 * All rights reserved.
 *
 * Redistribution and use in  source and binary  forms  are permitted
 * provided that the  above copyright  notice  and this paragraph are
 * duplicated in all  such forms.  Inclusion  in a product or release
 * as part of  a  package  for  sale is not  agreed to.  Storing this
 * software in a  nonvolatile  storage  device  characterized  as  an 
 * integrated circuit providing  read  only  memory (ROM), either  as
 * source code or  machine executeable  instructions is similarly not
 * agreed to.  THIS  SOFTWARE IS  PROVIDED ``AS IS'' AND  WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT  LIMITATION, THE
 * IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE
 */
/*
 *	diag.c - diagnostic test operation for des.c
 */
#include "./des.h"

void
do_des_test(verbose) 
int verbose;
{
    unsigned char testinput[128], testkey[17],key[8];
    unsigned char testplain[17], testcipher[17], testresult[17];
    union LR_block data;

    int len;
    int testerrors = 0;
    int totalerrors = 0;
    int testcount = 0;
 
	while (fgets(testinput,(sizeof testinput) -1, stdin) != NULL ) {

	    if ( strncmp(testinput,"encrypt",7) == 0) { /* mode = encode */
	        set_des_mode(ENCRYPT);
	        fprintf(stderr,"%s",testinput);
	    }
	    else
	    if ( strncmp(testinput,"decrypt",7) == 0) { /* mode = decode */
	        fprintf(stderr,"%s",testinput);
	        set_des_mode(DECRYPT);
	    }
	    else 
	    if ( strncmp(testinput," ",1) == 0) { /* key, plain & cipher */
		testcount++;
	        len = sscanf(testinput,"%s%s%s*",
	    	    testkey, testplain, testcipher);
		if ( verbose )  {
		    fprintf(stderr," %s %s %s\n", testkey, testplain,
							   testcipher);
		}
		strxtoc(testkey,key);
		loadkey(key,NOSHIFT);
		strxtoc(testplain,data.string);
		des(&data);
		strctox(data.string,testresult);
		if ( (len = strncmp(testcipher,testresult,16)) != 0 ) {
		    fprintf(stderr,"Test: %d -- ERROR expected %s got %s\n",
			    testcount,testcipher,testresult);
		    testerrors++;
		}
	    }
	    else {				  /* nothing but eyewash */
		if ( testcount ) {
		    fprintf(stderr," %d tests performed\n",testcount);
		    fprintf(stderr," ERRORS on these tests : %d\n",testerrors);
		    totalerrors +=testerrors;
		    testcount = 0;
		    testerrors = 0;
		}
		fprintf(stderr,"%s",testinput);
	    }
	}
    fprintf(stderr,"Total Errors = %d\n",totalerrors);
}
