/*--- rkeyreg.c -- Program to register RIPEM public keys.
 *
 *  This program reads keys from flat files and "registers" them by
 *  inserting them into the GDBM database that comprises the "official"
 *  public key database.  The flat files are typically created by
 *  "copymail", from email messages.
 *  
 *  After processing, each flat file is appended to a transaction
 *  log file for safekeeping.
 *
 *  rkeyreg scans a directory for new files periodically.  When it
 *  needs to write to the GDBM database, it signals rkeyserv (which
 *  normally has the database opened) to release the file.
 *
 *  NOTE:  This program will probably be overhauled significantly before
 *  being placed into production.
 *
 *  Written by Mark Riordan   10 July 1992
 *  This program has been placed in the public domain.
 */
 
#define TRUE   1
#define FALSE  0
#define BOOL int
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef sun
#include <dirent.h>
#endif
#ifdef __MACH__
#include <sys/dir.h>
#endif
#include <signal.h>
#include <time.h>
#include "gdbm.h"
#define DEF
#include "headers.h"
#include "srvfiles.h"
#include "getretap.h"

typedef struct struct_userkey {
	char *username;
	BOOL addedOK;
} TypUserKey;


#include "../main/list.h"
#include "../main/listprot.h"
#include "../main/strutilp.h"
#include "rkeyregp.h"
#include "../main/keyfield.h"
#include "srvfiles.h"
#include "getretap.h"

#define SLEEP_SECS_BETWEEN_UPDATES 10


#define NUM_ACTS 3
#define ACT_ADD 0
#define ACT_CHANGE 1
#define ACT_REMOVE 2
char *Incoming_dirs[NUM_ACTS] = {
	SERVER_INCOMING_KEY_DIR, 
	SERVER_CHANGE_KEY_DIR,
	SERVER_REMOVE_KEY_DIR };
char *Act_desc[NUM_ACTS] = {"Adding","Changing","Removing"};
char *Act_verb[NUM_ACTS] = {"add","change","remove"};


int Debug = 0;
FILE *DStream = stderr;
GDBM_FILE dbf;
char *DBName = SERVER_KEY_DATABASE;
char *Log_file = SERVER_LOG_FILE;
char *PidFile=SERVER_PID_FILE;
int PidToNotify=0;
time_t PidModtime = 0;
FILE *PidStream;
unsigned int Timeout_sec=3;
unsigned int Timeout_scan = SLEEP_SECS_BETWEEN_UPDATES;
BOOL Processing=TRUE;
BOOL DatabaseOpened=FALSE;

extern gdbm_error gdbm_errno;

int
main(argc,argv)
int argc;
char *argv[];
{
   extern char *optarg;
	struct dirent *dp;
	time_t modtime, prev_mod_time[NUM_ACTS] = {0,0,0};
	struct stat statbuf;
	char *err_file=NULL; 
	char *err_msg;
	FILE *pidstream;
	int  ch, iact;
	DIR *dirp[NUM_ACTS];
	int dir_fds[NUM_ACTS];
	int which_act = ACT_ADD;

	/* Parse the command line arguments. */
	while(-1 != (ch = getopt(argc,argv,"a:r:c:D:d:t:s:o:p:l:Z:"))) {
		switch(ch) {
			case 'D':
				Debug = atoi(optarg);
				break;
			case 'a':
				Incoming_dirs[ACT_ADD] = optarg;
				break;
			case 'r':
				Incoming_dirs[ACT_REMOVE] = optarg;
				break;
			case 'c':
				Incoming_dirs[ACT_CHANGE] = optarg;
				break;
			case 't':
				Timeout_sec = atoi(optarg);
				break;
			case 's':
				Timeout_scan = atoi(optarg);
				break;
			case 'p':
				PidFile = optarg;
				break;
			case 'o':
				DBName = optarg;
				break;
			case 'l':
				Log_file = optarg;
				break;
			case 'Z':
				err_file = optarg;
				break;
			case '?':
				fputs("rkeyreg: Register keys into public key database.\n",stderr);
				fputs("Usage:  rkeyreg [-a add_key_directory] [-r remove_key_dir]\n",stderr);
				fputs("   [-c change_key_dir] [-p pidfile] [-o dbname] [-D debug_lev]\n",stderr);
				fputs("   [-Z debugfile] [-t timeout] [-s timeout_scan]\n",stderr);
				fputs("  -d specifies the name of the incoming directory.\n",stderr);
				fputs("  -p specifies the name of the file containing the process\n",stderr);
				fputs("     id of the a process that may hold a lock on dbname.\n",stderr);
				return 1;
		}
	}
	
	if(err_file) {
		DStream = fopen(err_file,"w");
	}
	
	
	/* Set up our signal handler. */
	signal(SIGTERM,SigHandler);
	
	for(iact=0; iact<NUM_ACTS; iact++) {
		dirp[iact] = opendir(Incoming_dirs[iact]);
		if(!dirp[iact]) {
			fprintf(stderr,"Cannot open dir %s\n",Incoming_dirs[iact]);
			return 1;
		} else if(Debug>2){
			fprintf(DStream,"Opened dir %s\n",Incoming_dirs[iact]);
		}
		dir_fds[iact] = dirp[iact]->dd_fd;
	}
	
	while(Processing) {
		fstat(dir_fds[which_act],&statbuf);
		modtime = statbuf.st_mtime;
		if(modtime != prev_mod_time[which_act]) {
			prev_mod_time[which_act] = modtime;
			err_msg = ScanDir(dirp[which_act],which_act);
		} else {
			sleep(Timeout_scan);
			if(Debug>3) {
				fprintf(DStream,"Woke up to look at incoming dir again.\n");
			}
			err_msg = NULL;
		}
		if(err_msg) {
			fprintf(stderr,"%s\n",err_msg);
			return 1;
		}
		which_act++;
		if(which_act >= NUM_ACTS) which_act = ACT_ADD;
	}
}


/*--- function ScanDir -------------------------------------------
 *
 *  Scan a directory, looking for key files.  For each
 *  key file, take the appropriate action based on "action".
 *
 *  Entry	dirp  	is the directory structure for the incoming key dir.
 *				action   is the action (add, change, remove).
 *
 *	 Exit		The files in the directory have been processed.
 *          All key files that have been successfully processed
 *				  have been appended to a log file.
 */
char *
ScanDir(dirp,action)
DIR *dirp;
int action;
{
#ifdef __MACH__
	struct direct *dp;
#else
	struct dirent *dp;
#endif
	struct struct_entry *entryp, *ep, *prevp;
	char file_name[1024];
	char *err_msg=NULL;

	if(Debug >2) {
		fprintf(DStream,"Scanning directory %s\n",Incoming_dirs[action]);
	}
	/* The following loop is what I assume must appear in every
    * "ls"-like program.
    */
	rewinddir(dirp);
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		/* puts(dp->d_name); */
		/* Process only files whose name starts with "key." */
		if(strncmp(dp->d_name,"key.",4)==0) {
			/* For each key file, process the
			 * file, and wait a bit before going
			 * on to the next one.  We don't want to hog the database.
			 */
			sprintf(file_name,"%s/%s",Incoming_dirs[action],dp->d_name);
			switch(action) {
				case ACT_ADD:
					err_msg = ProcessAddFile(file_name,TRUE);
					if(err_msg) return err_msg;
					break;
				case ACT_CHANGE:
					err_msg = ProcessChangeFile(file_name,TRUE,action);
					if(err_msg) return err_msg;
					break;
				case ACT_REMOVE:
					err_msg = ProcessChangeFile(file_name,TRUE,action);
					if(err_msg) return err_msg;
					break;
			}
			sleep(Timeout_sec);
			if(Debug>2) fprintf(DStream,"Woke up to look at next file in dir.\n");
		}
	}
	return 0;
}


/*--- function ProcessAddFile -----------------------------------------------
 *
 *  Process an incoming file of public keys.
 *
 *  Entry:	fileName		is the name of the file with public keys.
 *				replyToUser is true if we should send a mail message to
 *								the sender of this file when the file has been
 *								processed.
 *
 *  For each public key record in the incoming file:
 * 	For the first (and usually only) User: in the file,
 *			add the public key in the database under the user's name.
 *		For each subsequent User:, add a record to the database which
 *			points to the canonical name above.
 *	 	Keep track of 
 *
 *	 Then send an email message to the sender of the incoming file.
 */
char *
ProcessAddFile(fileName,replyToUser) 
char *fileName;
int replyToUser;
{
	FILE *instream;
#define BUFLEN 4000
#define NAMELEN 200
	int jit;
	int nkeys=0,keystuff,domainnum;
	unsigned int data_len;
	int ret, first_user, user_field_len=strlen(USER_FIELD);
	char first_name[NAMELEN];
	char dbuf[BUFLEN], kbuf[NAMELEN];
	char *bptr, *return_addr, *user, *err_msg;
	datum key,dat;
	TypList email_list;
	TypListEntry entry;
	TypUserKey *user_key;
	
	err_msg = OpenKeyDatabase(&dbf);
	if(err_msg) {
		return err_msg;
	}
 		
	InitList(&email_list);
 
	instream = fopen(fileName,"r");
	if(Debug>2) fprintf(DStream,"Processing file %s\n",fileName);
	return_addr = GetReturnAddress(instream);
	
	while((ret = ReadUserRecord(instream,dbuf,BUFLEN,&data_len))) {
		nkeys++;
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
					LowerCaseString(first_name);
					key.dptr = first_name;
					key.dsize = strlen(first_name);
					dat.dptr = dbuf;
					dat.dsize = data_len;
				} else {
					/* This is a second or subsequent user in the same record.
					 * Add him as a separate record in the database.
					 */
					ExtractValue(bptr,kbuf,NAMELEN);
					LowerCaseString(kbuf);
					key.dptr = kbuf;
					key.dsize = strlen(kbuf);
#ifdef ADD_SAMEAS
					/* If this code is executed, we add this record as a
					 * SameAs: record pointing to the first_name record.
					 * Otherwise, just add the entire key record.
					 */
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
				
				strcpyalloc(&user,(char *)key.dptr);
				user_key = (TypUserKey *)malloc(sizeof *user_key);
				if(!user_key) return "Can't allocate memory.";
				user_key->username = user;
				user_key->addedOK = !ret;
				AddToList(NULL,user_key,sizeof user_key,&email_list);
				
				if(ret>0 && Debug) {
					fprintf(DStream,"Duplicate key: %s\n",key.dptr);
				}
			}
		} while(NextLineInBuf(&bptr));
	}
	
	LogKeyFile(instream,ACT_ADD);
	fclose(instream);
	unlink(fileName);
	CloseKeyDatabase(dbf);
	
	ReportViaEmail(return_addr,&email_list,nkeys);
	FreeList(&email_list);
	if(return_addr) free(return_addr);
	return NULL;
}

char *Ripem_argv[] = {
  "ripem","-i","<Replace with filename>","-d",
  "-y","rpub.cl.msu.edu","-Y","s",
  NULL};
  
/*--- function ProcessChangeFile ---------------------------------------------
 *
 *  Process a file containing a request to change a public key.
 *
 *  Entry:	fileName		is the name of the file with public keys.
 *				replyToUser is true if we should send a mail message to
 *								the sender of this file when the file has been
 *								processed.
 *				action		states whether this is an add or delete.
 *
 *  For each public key record in the incoming file:
 * 	For the first (and usually only) User: in the file,
 *			add the public key in the database under the user's name.
 *		For each subsequent User:, add a record to the database which
 *			points to the canonical name above.
 *	 	Keep track of 
 *
 *	 Then send an email message to the sender of the incoming file.
 */
char *
ProcessChangeFile(fileName,replyToUser,action) 
char *fileName;
int replyToUser;
int action;
{
	FILE *instream;
	int retval=1,j,nmax;
	char *bptr, *return_addr;
	datum key,dat;
	char *ripem_out=NULL, *ripem_errmsg=NULL;
	char *err_msg=NULL;
	char user[NAMELEN], misc_buf[BUFLEN];
	int nripem_bytes, nripem_err_bytes;
	int msgfd;
	FILE *msgstream;
	
	if(Debug>2) fprintf(DStream,"%s keys using file %s\n",
	   Act_desc[action],fileName);
	 		
	/* Run RIPEM to validate the signature on this file. */
	
	Ripem_argv[2] = fileName;		
 	if(RunAndGetOutput("/usr/local/bin/ripem",Ripem_argv,&retval,
	 &ripem_out,&nripem_bytes,&ripem_errmsg,&nripem_err_bytes)) {
	 	/* We failed to run RIPEM (it didn't even start to run) */
		if(Debug) {
			fprintf(DStream,"Could not run RIPEM.\n");
			goto donekey;
		}
	}
	
	if(Debug>2) {
		fprintf(DStream,"Results of running RIPEM:  retval=%d\n",retval);
		fprintf(DStream,"  %d-byte output started: '",nripem_bytes);
		for(j=0; j<nripem_bytes; j++) {
			putc(ripem_out[j],DStream);
		}
		putc('\'',DStream); putc('\n',DStream);
		fprintf(DStream,"  %d-byte error output started: '",nripem_err_bytes);
		for(j=0; j<nripem_err_bytes; j++) {
			putc(ripem_errmsg[j],DStream);
		}
		putc('\'',DStream); putc('\n',DStream);
	}
		

	/* Open the input file and read it enough to get the user's
	 * return email address.  We need to do this even if the input file
	 * is invalid.
	 */
	instream = fopen(fileName,"r");
	return_addr = GetReturnAddress(instream);
	if(!return_addr) {
		if(Debug) {
			fprintf(DStream,"Couldn't find return address in '%s'\n",fileName);
			goto donekey;
		}
	}
	 
	/* Initiate the process of sending a reply message, even though at
	 * this point we aren't certain what we'll say. 
	 */
	StartNetMail(return_addr,&msgfd);
	msgstream = fdopen(msgfd,"w");
	fprintf(msgstream,"To: %s\n",return_addr);
	
	if(retval) {
		fprintf(msgstream,"Subject: Error %s RIPEM public key\n",
		  Act_desc[action]);
		fprintf(msgstream,"\n");
		fprintf(msgstream,"While running RIPEM to authenticate the signature on the message you sent\nto the key server, I received the following error:\n\n");
		for(j=0; j<nripem_err_bytes; j++) putc(ripem_errmsg[j],msgstream); 
		fprintf(msgstream,"\nPlease correct the problem and try again.\n");
		if(Debug) {
			fprintf(DStream,"Error authenticating request\n");
		}
	} else {
		if(GetFileLine(instream,SENDER_FIELD,user,NAMELEN)) {
			LowerCaseString(user);
			key.dptr = user;
			key.dsize = strlen(user);
			
			if(action == ACT_REMOVE) {
				/* The message must start with "RemoveKey" to be legit. */
				
				if(!matchn(ripem_out,"RemoveKey",9)) {
					/* The message wasn't really a Request to remove a key */
					fprintf(msgstream,"Subject: Error removing RIPEM key\n");
					fprintf(msgstream,"\n");
					fprintf(msgstream,"Your request to remove the key for \"%s\"\n",
	 					user);
					fprintf(msgstream,"was not processed because it did not start with the string \"RemoveKey\".\n");
					if(Debug) {
						fprintf(DStream,"Remove request not satisfied; bad request format.\n");
						fprintf(DStream,"  %d-byte message started: '",nripem_bytes);
						for(j=0; j<(nripem_bytes<40 ? nripem_bytes : 40); j++) {
							putc(ripem_out[j],DStream);
						}
						putc('\n',DStream);
					}
				} else {			
					/* It's OK to try to delete this key. */		
					OpenKeyDatabase(&dbf);
					if(gdbm_delete(dbf,key)) {
						/* Error trying to delete */
						fprintf(msgstream,"Subject: Error removing RIPEM key\n");
						fprintf(msgstream,"\n");
						if(gdbm_errno == GDBM_ITEM_NOT_FOUND) {
							fprintf(msgstream,"User  %s  could not be found in the database.\n",user);
							fprintf(msgstream,"Therefore, the request to remove this user failed.\n");
						} else {
							fprintf(msgstream,"I received error code %d trying to remove the RIPEM public key\n",gdbm_errno);
							fprintf(msgstream,"for user %s\n",user);
						}
						if(Debug) {
							fprintf(DStream,"Error trying to delete key.\n");
						}
					} else {
						fprintf(msgstream,"Subject: Removed RIPEM key for \"%s\"\n", user);
						fprintf(msgstream,"\n");
						fprintf(msgstream,"The RIPEM public key for user  %s  was\nsuccessfully removed from the server.\n",user);
						if(Debug) {
							fprintf(DStream,"Removed key for %s\n",user);
						}
					}
				}
			} else {
				/* This must be a request to change the key. 
				 * Check to make sure the file the user looks like a public 
				 * key file.
				 */
				ripem_out[nripem_bytes] = '\0';
				if(CrackKeyField(ripem_out,PUBLIC_KEY_FIELD,misc_buf,BUFLEN)) {
					dat.dptr = ripem_out;
					dat.dsize = nripem_bytes;
					OpenKeyDatabase(&dbf);
					if(gdbm_store(dbf,key,dat,GDBM_REPLACE)) {
						fprintf(msgstream,"Subject: Error changing RIPEM public key\n");
						fprintf(msgstream,"\n");
						fprintf(msgstream,"When attempting to change the public key for \"%s\",\n",user);
						fprintf(msgstream,"I received error code %d.\n",gdbm_errno);
						if(Debug) {
							fprintf(DStream,"Error trying to replace key in database\n");
						}
					} else {
						fprintf(msgstream,"Subject: RIPEM public key changed\n");
						fprintf(msgstream,"\n");
						fprintf(msgstream,"Your request to change the RIPEM public key\nfor user %s was processed successfully.\n",user);
						if(Debug) {
							fprintf(DStream,"Changed key for %s\n",user);
						}
					}
				} else {
					/* CrackKeyField couldn't find PubKeyInfo: */
					fprintf(msgstream,"Subject: Failed request to change public key\n");
					fprintf(msgstream,"\n");
					fprintf(msgstream,"I did not change your RIPEM public key because your request\ndid not include anything that looked like a new key.\n");
					if(Debug) {
						fprintf(DStream,"Error changing key:  request doesn't contain new key.\n");
						fprintf(DStream,"  %d-byte message started: '",nripem_bytes);
						for(j=0; j<(nripem_bytes<40 ? nripem_bytes : 40); j++) {
							putc(ripem_out[j],DStream);
						}
						putc('\'',DStream); putc('\n',DStream);
					}
				}
			} /* end of if(action == ... ) */		
			
		} else {
			fprintf(msgstream,"Subject: Error %s RIPEM public key\n",
			  Act_desc[action]);
			fprintf(msgstream,"\n");
			fprintf(msgstream,"I can't find your name in the RIPEM-encrypted request you sent.\n");
			fprintf(msgstream,"Therefore, I did not change your key.\n");
			if(Debug) {		
				fprintf(DStream,"Can't find Originator-Name: in incoming request\n");
			}
		}
	}  /* End of if(retval) ... */

		
	fprintf(msgstream,"\nSincerely, the RIPEM key server.\n");
	fprintf(msgstream,"(This is an automated message; do not reply to it.)\n");
	fclose(msgstream);
donekey:;
	LogKeyFile(instream,action);
	fclose(instream);
	unlink(fileName);
	CloseKeyDatabase(dbf);
	
	if(return_addr) free(return_addr);
	if(ripem_out) free(ripem_out);
	if(ripem_errmsg) free(ripem_errmsg);
	return err_msg;
}


/*--- function OpenKeyDatabase --------------------------------------
 *
 *  Open the key database for writing.
 *
 *  Entry:	DBName	(global) is the file name of the database.
 *
 *	 Exit:   dbf		(global) is the database pointer.
 *				Returns NULL upon success.
 */
char *
OpenKeyDatabase(dbf)
GDBM_FILE *dbf;
{
	char *err_msg = NULL;
	int opening=1;

	while(opening) {
      *dbf = gdbm_open(DBName,0,GDBM_WRCREAT,0744,0);
	   if(!*dbf) {
		   if(gdbm_errno == GDBM_CANT_BE_WRITER) {
				/* Someone else has the file locked.  Send the process a signal
				 * to release the database, wait a bit, then try again. 
				 */
				GetPidToNotify();
				if(PidToNotify) {
					kill(PidToNotify,SIGUSR1);
			   	sleep(2);
				}
         } else {
		   	err_msg = "Error opening database.";
				opening = 0;
			}
	   } else {
		   opening = 0;
			DatabaseOpened = TRUE;
			if(Debug) {
				fprintf(DStream,"Opened key database.\n");
			}
	   }
	}
	return err_msg;
}

/*--- function CloseKeyDatabase --------------------------------------
 *
 *  Close the key database for reading.
 *
 *  Entry:	dbf	is the database pointer for the database.
 *
 *	 Exit:
 */
void
CloseKeyDatabase(dbf)
GDBM_FILE dbf;
{
	char *err_msg = NULL;

	if(DatabaseOpened) {
	   gdbm_close(dbf);
		if(Debug) {
			fprintf(DStream,"Closed database.\n");
		}
	}
	DatabaseOpened = FALSE;
}

/*--- function SigHandler -----------------------------------------
 *
 *  Handle the SIGTERM signal, which other processes send to us
 *  to ask that we quit.
 */
void
SigHandler(signo)
int signo;
{
	Processing = FALSE;
	if(Debug) {
		fprintf(DStream,"Got signal to quit.\n");
	}
}

/*--- function ReportViaEmail ---------------------------------------------
 *
 *  Reply to the sender of the public key file, reporting on the results
 *  of our attempt to add the key(s) in the file.
 *
 *  Entry:	emailAddr	is the email address of the intended recipient.
 *				userList 	is the list of users on whom we're reporting.
 *				nKeys			is the total number of keys.
 *
 *	 Exit:
 */
int 
ReportViaEmail(emailAddr,userList,nKeys)
char *emailAddr;
TypList *userList;
int nKeys;
{
#define LINELEN 256
	TypListEntry *entry;
	TypUserKey *ukptr;
	TypList msg_list;
	char *cptr, *lptr, line[LINELEN];
	int n_bad_names=0;
	
	InitList(&msg_list);
	
	sprintf(line,"To: %s",emailAddr);
	AppendLineToList(line,&msg_list);
	if(nKeys==1) {
		sprintf(line,"Subject: RIPEM key server processed your key");
	} else {
		sprintf(line,"Subject: RIPEM key server processed %d keys",nKeys);
	}
	AppendLineToList(line,&msg_list);
	AppendLineToList("",&msg_list);
	if(nKeys == 1) {
		sprintf(line,"You sent a file containing a RIPEM public key.");
	} else {
		sprintf(line,"You sent a file containing %d RIPEM public keys.",nKeys);
	}
	AppendLineToList(line,&msg_list);
	sprintf(line,"Here are the results from adding the usernames and aliases:");
	AppendLineToList(line,&msg_list);
	AppendLineToList("",&msg_list);
	
	for(entry=userList->firstptr; entry; entry=entry->nextptr) {
		ukptr = (TypUserKey *) entry->dataptr;
		
		if(ukptr->addedOK) {
			cptr = "Added";
		} else {
			n_bad_names++;
			cptr = "** Didn't add";
		}
		sprintf(line,"%s %s",cptr,ukptr->username);	
		AppendLineToList(line,&msg_list);
		if(Debug>1) {
			fprintf(DStream,"  %s %s\n",ukptr->addedOK ? "ok" : "NO",
			 ukptr->username);
		}
	}
	
	if(n_bad_names) {
		AppendLineToList("",&msg_list);
		AppendLineToList("** These names duplicated existing names in the public key database.",&msg_list);
	}
	
	AppendLineToList("",&msg_list);
	AppendLineToList("Sincerely, the RIPEM key registration server.",&msg_list);
	AppendLineToList(
	 "(This is automated; please do not attempt to respond to this message.)",
	 &msg_list);
	SendNetMail(emailAddr,&msg_list);
	
	FreeList(&msg_list);
	return TRUE;
}

/*--- function LogKeyFile --------------------------------------------------
 *
 *  Log the input file of keys to a log file, just for safekeeping.
 *
 *  Entry:	instream		is the opened stream of the input file.
 *
 *  Exit:	The file has been written to the log file.
 */
int
LogKeyFile(instream, action)
FILE *instream;
int action;
{
#define BUFSIZE 4096
	char buf[BUFSIZE];
	FILE *outstream;
	size_t nbytes;
	time_t mytime;
	
	outstream = fopen(Log_file,"a");
	if(!outstream) return 1;
	rewind(instream);
	
	time(&mytime);
	fprintf(outstream,"%s key(s) on %s",Act_desc[action],ctime(&mytime));
	
	while(nbytes = fread(buf,1,BUFSIZE,instream)) {
		fwrite(buf,1,nbytes,outstream);
	}
	fwrite("\n\001\n",1,3,outstream);
	fclose(outstream);
	return 0;
}

/*--- function GetPidToNotify -----------------------------------------
 *
 *  Obtain the Pid of the process which normally has a read lock on
 *  the database.  This Pid is stored in a file.
 *  Because the other process may be killed and restarted, the PID
 *  in this file may change--so we have to look at the modification time
 *  of the file.
 */
int
GetPidToNotify()
{
	struct stat statbuf;
	time_t modtime;	

	stat(PidFile,&statbuf);
	modtime = statbuf.st_mtime;
	if(modtime != PidModtime) {
		PidModtime = modtime;
		PidStream = fopen(PidFile,"r");
		if(!PidStream) {
			fprintf(stderr,"Can't open pid_file %s\n",PidFile);
			return 1; 
		}
		fscanf(PidStream,"%d",&PidToNotify);
		fclose(PidStream);
		if(!PidToNotify) {
			fprintf(stderr,"Warning: pid_file %s does not contain pid.\n",PidFile);
		} else {
			if(Debug) {
				fprintf(DStream,"Obtained PID %d for process that holds database.\n",PidToNotify);
			}
		}
	}
	return 0;
}
