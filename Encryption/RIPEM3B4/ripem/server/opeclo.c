/*--- opeclo.c -- functions to open and close the random public key
 *  database.
 *  Mark Riordan    29 July 1992
 */

#include <stdio.h>
#include "gdbm.h"
#include "opeclopr.h"

extern gdbm_error gdbm_errno;
extern int Debug;
extern FILE *DStream;

/*--- function OpenKeyDatabase --------------------------------------
 *
 *  Open the key database for reading.
 *
 *  Entry:	DBName	is the file name of the database.
 *  			forWrite is TRUE if we are opening for write.
 *
 *	 Exit:   dbf		is the database pointer.
 *				Returns NULL upon success.
 */
char *
OpenKeyDatabase(DBName,forWrite,dbf)
char *DBName;
int forWrite;
GDBM_FILE *dbf;
{
	char *err_msg = NULL;
	int opening=1;
	int open_mode;

	while(opening) {
		open_mode = forWrite ? GDBM_WRITER : GDBM_READER;
      *dbf = gdbm_open(DBName,0,open_mode,0744,0);
	   if(!*dbf) {
		   if(gdbm_errno == GDBM_CANT_BE_READER || 
			  gdbm_errno == GDBM_CANT_BE_WRITER) {
				/* Someone else has the file locked.  Wait a bit. */
			   sleep(1);
         } else {
		   	err_msg = "Error opening database.";
				opening = 0;
			}
	   } else {
		   opening = 0;
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
   gdbm_close(dbf);
	if(Debug) {
		fprintf(DStream,"Closed database.\n");
	}
}
