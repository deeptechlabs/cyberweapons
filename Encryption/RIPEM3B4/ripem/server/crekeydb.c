/*--- crekeydb.c -- Create a GDBM database of public keys from a flat
 *  file of keys.  The input file is of the format that would result from
 *  concatenating the output from several RIPEM -g -P runs, or from running
 *  db2flat.  The output file is in a format suitable for rkeyserv.
 *
 *  Program to create a dummy GDBM database.
 *
 *  Mark Riordan   13 June 1992
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gdbm.h"
#include "../main/keyfield.h"
#include "crekeydp.h"
#include "../main/boolean.h"
#include "../main/pubinfop.h"

int Debug = 0;
FILE *DStream = stderr;

int
main(argc,argv)
int argc;
char *argv[];
{
   extern char *optarg;
	char *dbname = "testkey.gdbm";
	char *pubfile = "testpub";
	datum dat;
	GDBM_FILE dbf;
	int n_items=100, fast=0, ch;
	FILE *instream;

	while(-1 != (ch = getopt(argc,argv,"D:fn:o:p:"))) {
		switch(ch) {
			case 'D':
				Debug = atoi(optarg);
				break;
			case 'f':
				fast = 1;
				break;
			case 'n':
				n_items = atoi(optarg);
				break;
			case 'p':
				pubfile = optarg;
				break;
			case 'o':
				dbname = optarg;
				break;
			case '?':
				fputs("crekeydb: GDBM key database from flat file.\n",stderr);
				fputs("Usage:  crekeydb [-p flatfile] [-o dbname] [-f] [-n numrecs] \n",stderr);
				fputs("   -f means fast; no unnecessary system calls.\n",stderr);
				return 1;
		}
	}

	dbf = gdbm_open(dbname,0,GDBM_WRCREAT,0744,0);
	if(!dbf) {
		fprintf(DStream,"Error opening database %s.\n",dbname);
		return 1;
	}

	instream = fopen(pubfile,"r");
	if(!instream) {
		fprintf(DStream,"Cannot open input file %s\n",pubfile);
		return 1;
	}

	FillDatabase(instream,dbf,n_items);
	gdbm_close(dbf);

	return 0;
}

/*--- function FillDatabase -----------------------------------------------
 */
int
FillDatabase(FILE *instream,GDBM_FILE dbf, int n_items)
{
#define BUFLEN 4000
#define NAMELEN 200
	int jit;
	int usernum,keystuff,domainnum;
	unsigned int data_len;
	int ret, first_user, user_field_len=strlen(USER_FIELD);
	char first_name[NAMELEN];
	char dbuf[BUFLEN], kbuf[NAMELEN];
	char *bptr;
	datum key,dat;


	while((ret = ReadUserRecord(instream,dbuf,BUFLEN,&data_len))) {
		if(Debug>1) {
			fprintf(DStream,"PubInfo gotten: %s\n",dbuf);
		}
		first_user = 1;
		bptr = dbuf;
		do {
			if(strncmp(bptr,USER_FIELD,user_field_len)==0) {
				if(first_user) {
					first_user = 0;
					ExtractValue(bptr,first_name,NAMELEN);
					if(Debug > 1) {
						fprintf(DStream,
						"CrackName returned first_name=%s\n",first_name);
					}
					key.dptr = first_name;
					key.dsize = strlen(first_name);
					dat.dptr = dbuf;
					dat.dsize = data_len;
				} else {
					ExtractValue(bptr,kbuf,NAMELEN);
					key.dptr = kbuf;
					key.dsize = strlen(kbuf);
#ifdef ADD_SAME_AS
					sprintf(dbuf,"%s %s\nSameAs: %s\n",USER_FIELD,kbuf,first_name);
					dat.dptr = dbuf;
					dat.dsize = strlen(dbuf)+1;
#endif
				}
				if(Debug) {
					fprintf(DStream,"Ready to store %d bytes; key=\"%s\" data=%s\n",
						dat.dsize,key.dptr,dat.dptr);
				}
				ret = gdbm_store(dbf,key,dat,GDBM_INSERT);
				if(ret>0) {
					fprintf(DStream,"Duplicate key: %s\n",key.dptr);
				}
			}
		} while(NextLineInBuf(&bptr));
	}
	return 0;
}

