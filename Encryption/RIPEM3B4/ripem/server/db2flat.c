/*--- db2flat -- Program to create a flat ASCII line file from 
 *  a random-access RIPEM public key database.
 *  The random file is in GDBM format.
 *
 *  Mark Riordan   28 July 1992
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define MAIN
#define TRUE   1
#define FALSE  0
#define BOOL int

#include "gdbm.h"
#include "opeclopr.h"
#include "db2flatp.h"
#include "srvfiles.h"

#define LINESIZE 2000

static char *author =
"Written by Mark Riordan  1100 Parker  Lansing MI 48912  28 July 1992";

FILE *DStream = stderr;
FILE *OutStream = stdout;
char *DFile = NULL, *OutFile = SERVER_KEY_FLAT_FILE;
int Debug = 0;
char *DBName = SERVER_KEY_DATABASE;
int DatabaseOpened = FALSE;
int PleaseClose = FALSE;
GDBM_FILE dbf;
extern gdbm_error gdbm_errno;

int
main(argc,argv)
int argc;
char *argv[];
{
#define BUFSIZE 8192
#define LINELEN 256
	char hostname[LINELEN],domain[LINELEN];
	char *err_msg;
	int ch, retval, selval;
	int timeout_sec;
	time_t mytime;
	int retcode=0;
   extern char *optarg;

   while(-1 != (ch = getopt(argc,argv,"D:g:Z:t:o:"))) {
      switch(ch) {
			case 'g':  /* GDBM key database */
				DBName = optarg;
				break;
			case 'D':  /* Debugging */
				Debug = atoi(optarg);
				break;
			case 't':
				timeout_sec = atof(optarg);
				break;
			case 'o':
				OutFile = optarg;
				break;
			case 'Z':
				DFile = optarg;
				DStream = fopen(DFile,"w");
				break;
			case '?':
				fputs("db2flat: Copy random key database to flat file.\n",stderr);
				fputs("Usage:  db2flat [-g dbname] [-D debug] [-t timeout]\n",stderr);
				fputs("  [-o out_file] [-Z debug_file] \n",stderr);
				fputs("   -f means fast; no unnecessary system calls.\n",stderr);
				fputs("   -t specifies the select timeout in seconds (floating point)\n",stderr);
				return 1;
		}
	}
	
	err_msg = OpenKeyDatabase(DBName,FALSE,&dbf);
	if(err_msg) {
		fprintf(stderr,"%s\n",err_msg);
		return 1;
	}
	
	OutStream = fopen(OutFile,"w");
	if(!OutStream) {
		fprintf(stderr,"Can't open output flat file %s\n",OutFile);
		return 2;
	}
	
	gethostname(hostname,LINELEN);
	getdomainname(domain,LINELEN);
	if(domain[0]) {
		strcat(hostname,".");
		strcat(hostname,domain);
	}
	time(&mytime);
#if 0
	fprintf(OutStream,"# Created on %s at %s\n",hostname,ctime(&mytime));
#else
	fprintf(OutStream,"# Created on %s\n",ctime(&mytime));
#endif
	retcode = DumpIt(dbf,OutStream);
	
	CloseKeyDatabase(dbf);	
	return retcode;
}

/*--- function DumpIt --------------------------------------------------------
 *
 *  Go through the random key database sequentially (in random order,
 *  unfortunately), retrieving the regular public key records and
 *  copying them to a standard ASCII line file.
 *  For users who have registered their key under multiple names,
 *  there will not be multiple occurrences of a record.
 *
 *  Entry: 	dbf			is the opened random database.
 *
 *	 Exit:	outStream 	has a sequential version of the database.
 *  			Returns 0 upon success.
 */
int
DumpIt(dbf,outStream)
GDBM_FILE dbf;
FILE *outStream;
{
	datum key, nextkey, dat, junk_dat;
	char *byteptr;
	char dummy[4];
	int len;
#ifdef CHECKDUPS	
	GDBM_FILE dbf_temp;
	char *temp_file = "temp.gdbm";

	dbf_temp = gdbm_open(temp_file,0,GDBM_WRCREAT,0744,0);
	if(!dbf_temp) return 1;
	junk_dat.dptr = dummy;
	junk_dat.dsize = 0;
#endif
	
	key = gdbm_firstkey(dbf);
	if(key.dptr) {
		do {
			dat = gdbm_fetch(dbf,key);
			if(!CrackKeyField(dat.dptr,"SameAs:",dummy,4)) {
				/* Copy this record to output only if it's not a SameAs: record.
				 * Note: SameAs: records are a holdover from an earlier version
				 * of rkeyreg.
				 */
				 
				/* Copy this record only if it is not a duplicate of another
				 * record we have already written.
				 * We keep track of this by creating a temporary database
				 * which uses the value of the public key record as its key.
				 */
#ifdef CHECKDUPS
				if(!gdbm_store(dbf_temp,dat,junk_dat,GDBM_INSERT)) {
					/* If we get here, the insertion into the temporary 
					 * database succeeded--which means this is a new record
					 * that we have not previously written out.
					 * So, write it out to the ASCII file.
					 */
					len = dat.dsize;
					byteptr = dat.dptr;
					while(len--) putc(*(byteptr++),outStream);
					putc('\n',outStream);
				}
#endif
				WriteKeyRec(key,dat,outStream);
			}
			free(dat.dptr);
			nextkey = gdbm_nextkey(dbf,key);
			free(key.dptr);
			key = nextkey;
		} while(nextkey.dptr);
	}
#ifdef CHECKDUPS
	gdbm_close(dbf_temp);
	unlink(temp_file);
#endif
	
	return 0;
}

/*--- function WriteKeyRec -----------------------------------------
 *
 *  Write out the key record for the user onto a flat file.
 *  Suppress any User: data embedded in the key record; instead,
 *  generate our own from the gdbm key.
 *
 *	 Entry:	key		is a gdbm datum containing the user's email address.
 *				dat		is the record containing the public key.
 * 
 *	 Exit:	The record has been written to outStream.
 */
void
WriteKeyRec(key,dat,outStream)
datum key;
datum dat;
FILE *outStream;
{
	int j;
	char *cptr = dat.dptr, *cp;

	fputs("User: ",outStream);
	for(j=0; j<key.dsize; j++) putc(key.dptr[j],outStream);
	putc('\n',outStream);

	/* Loop through the lines in the key record, copying to 
	 * outStream those that don't start with User:
  	 */
	do {
		if(strncmp(cptr,"User:",5) != 0) {
			for(cp=cptr; *cp!='\n'; cp++) putc(*cp,outStream);
			putc('\n',outStream);
		}
	} while(NextLineInBuf(&cptr) && cptr-dat.dptr<dat.dsize);
	
	putc('\n',outStream);
}
