/*
 * Copyright (c) 1991 David G. Koontz.
 * All rights reserved.
 *
 * Redistribution and use in source and  binary  forms are  permitted
 * provided that the above  copyright  notice  and this paragraph are
 * duplicated  in  all  such   forms   and  that  any  documentation,
 * advertising  materials,  and   other  materials  related  to  such
 * distribution and use acknowledge that  the  software was developed
 * by the above mentioned individual.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE
 */
#ifndef lint
char copyright[]=
    "@(#) Copyright (c) 1991 David G. Koontz\n All rights reserved.\n";
#endif

/*  des -- perform encryption/decryption using DES algorithm */
#include "./des.h"
extern int  optind,opterr;
extern char *optarg;

char *getpass();
void *des(), *no_ip_des(), *loadkey(), *set_des_mode();

main (argc,argv)
int argc;
char **argv;
{
    union LR_block data;
    unsigned long temp;
    unsigned char key[8];
    unsigned len,c; 
    int verbose = FALSE;
    int op_mode = NORMAL_OP;
    int needkey = TRUE;
    char padchar = 0x20;	/* default pad character is space */

    if (argc < 2)
	goto usage;

    set_des_mode(ENCRYPT);	/* default to encrypt mode */


    while (( c = getopt(argc,argv,"ednk:K:p:tv")) != EOF) {

	switch (c){	    /* 'e' is a do nothing */
	    case 'd':
		set_des_mode(DECRYPT);
		break;
	    case 'n':
		if ( op_mode != TESTMODE)
		    op_mode = DES_NO_IP;
	    break;
	    case 'k':
		if (needkey) {
		    needkey = FALSE;
		    if ( (c = strlen(optarg)) != 8) {
			fprintf(stderr,"%s: key must be 8 char\n",argv[0]);
			exit(1);
		    }
		    loadkey(optarg,SHIFT);
		}
		else {
		    fprintf(stderr,"%s: too many keys\n",argv[0]);
		    exit(1);
		}
		break;
	    case 'K':
		if ( needkey ) {
		    needkey = FALSE;
		    strxtoc(optarg,key);  /* will complain about bad format */
		    while (*optarg) *optarg++ = 0;
		    loadkey(key,NOSHIFT);
		}
		else {
		    fprintf(stderr,"%s: too many keys\n",argv[0]);
		    exit(1);
		}
		break;
	    case 'p':
		padchar = (unsigned char) strtol(optarg,0,TODEC);
		break;
	    case 't':
		op_mode = TESTMODE;
		needkey = FALSE;
		break;
	    case 'v':
		verbose = TRUE;
		break;
	    case '?':
usage:		fprintf(stderr,"Usage: %s -e | -d ",argv[0]);
		fprintf(stderr,"[-k key | -K hex_key] ");
		fprintf(stderr,"[-n] [-p hex_pad_char]\n\n");
		fprintf(stderr,"   Or: %s -t [-v]\n\n",argv[0]);
		exit(1);
		break;
	}
    }

    if (needkey) {
	strncpy(key,getpass("key: "),8);
	if ( (c = strlen(key)) < 8)  {
	    fprintf(stderr,"%s: key must be 8 char\n",argv[0]);
	    exit(1);
        }
	loadkey(key,SHIFT);
    }

    switch ( op_mode) {
    
    case DES_NO_IP:
	while ((len = fread(data.string, 1, 8, stdin)) > 0) {
	    no_ip_des(&data);

	    temp = data.LR[0];
	    data.LR[0] = data.LR[1];		/* switch output to R16L16 */
	    data.LR[1] = temp;

	    fwrite(data.string, 1, 8, stdout);
	}
	if (len) {  /* there was residue, else len == 0 */
	    while (len < 8)
		data.string[len++]=padchar;
	    fwrite(data.string, 1, 8, stdout);
	}
    break;
    case NORMAL_OP:
	while ((len = fread(data.string, 1, 8, stdin)) > 0) {
	    des(&data);
	    fwrite(data.string, 1, 8, stdout);
	}
	if (len) {  /* there was residue, else len == 0 */
	    while (len < 8)
		data.string[len++]=padchar;
	    fwrite(data.string, 1, 8, stdout);
	}
    break;
    case TESTMODE:
    do_des_test(verbose);
    break;
    }
}
