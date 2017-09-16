/*--- credumpb.c -- Create a file of dummy public keys.
 *
 *  The file created by this program can be used to
 *  create a dummy GDBM database via the program crekeydb.
 *
 *  Mark Riordan   14 June 1992
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int WriteBigPubFile(FILE *stream, int n_items);

FILE *DStream = stderr;

int
main(argc,argv)
int argc;
char *argv[];
{
	extern char *optarg;
	char *pubfile = "testpub";
	int n_items=100, ch;
	FILE *outstream;
	extern char *optarg;

	while(-1 != (ch = getopt(argc,argv,"n:P:"))) {
		switch(ch) {
			case 'n':
				n_items = atoi(optarg);
				break;
			case 'P':
				pubfile = optarg;
				break;
			case '?':
				fputs("credumpb: Creates dummy key flat file.\n",stderr);
				fputs("Usage:  crekeydb [-P outfile] [-n numrecs] \n",stderr);
				return 1;
		}
	}

	outstream = fopen(pubfile,"w");
	if(!outstream) {
		fprintf(DStream,"Error opening %s for write.\n",pubfile);
		return 1;
	}

	WriteBigPubFile(outstream,n_items);

	return 0;
}

int
WriteBigPubFile(FILE *stream, int n_items)
{
	int jit;
	int usernum,keystuff,domainnum;
	int ret;
	char *dbuf, *kbuf;

	dbuf = malloc(4000);
	kbuf = malloc(200);

	for(jit=0; jit<n_items; jit++) {
		usernum = rand() % (10*n_items);
		domainnum = rand() % 5;
		keystuff = rand() % 100000;
		sprintf(kbuf,"j%d@my%d.com",usernum,domainnum);
		fprintf(stream,"User: %s\n\
PublicKeyInfo:\n\
 MFkwCgYEVQgBAQICAgQDSwAwSAJBCcVXx4EuHCsiJgidWtNPyWyTuA5CiTqcKWT8\n\
 MFkwCgYEVQgBAQICAgcDSwAwSAJBaP/XKe5xz5D1k8Q2PdtJFNhhoXrCBWkDA2Td\n\
 %-5.5dMqcSh/iRVO8+nugWDTNwG3LaERzfNe5wLznNpyNSKBwoQcCAwEAAf==\n\
MD5OfPublicKey: C83F5DF84BBF1E0CCCA1914A659CB603\n\n",
		  kbuf,keystuff);

	}
	return 0;
}
