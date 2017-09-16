/****************************************************************************
*																			*
*						cryptlib Oracle Mapping Routines					*
*						Copyright Peter Gutmann 1996-1998					*
*																			*
****************************************************************************/

/* TODO:

  - All of the functions are only about 98% complete (I lost the use of the
	Oracle system before I was finished).
  - The code could be rewritten to use dlopen() in a similar manner to the
	ODBC linking under Windows.
*/

#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "misc/keyset.h"

/* !!!! dbtest-only !!!! */
#define DEBUG( x )	x
/* !!!! dbtest-only !!!! */

/* In the following code, the performXXX() functions usually return the
   generic CRYPT_ERROR status since the exact error code returned depends on
   the transaction type (for example returning CRYPT_DATA_READ on a key
   write would be somewhat confusing).  Any necessary translation was
   formerly done by higher-level funcitons, but the code should be updated to
   do it at this level */

#ifdef DBX_ORACLE

/* Get information on an Oracle error */

static void getErrorInfo( KEYSET_INFO *keysetInfo )
	{
	sword length;

	length = oerhms( &keysetInfo->keysetDBMS.lda,
					 keysetInfo->keysetDBMS.cda.rc,
					 keysetInfo->errorMessage, MAX_ERRMSG_SIZE );
	keysetInfo->errorCode = keysetInfo->keysetDBMS.cda.rc;
	DEBUG( printf( "Return code %d, error message %s\n", \
		   keysetInfo->keysetDBMS.cda.rc, keysetInfo->errorMessage ) );
	}

/* Open and close a connection to an Oracle server */

static int openDatabase( KEYSET_INFO *keysetInfo, const char *name,
						 const char *server, const char *user,
						 const char *password )
	{
	char buffer[ 256 ];
	char *namePtr = ( name == NULL ) ? "" : ( char * ) name;
	char *serverPtr = ( server == NULL ) ? "" : ( char * ) server;
	char *userPtr = ( user == NULL ) ? "" : ( char * ) user;
	char *formatString = ( name == NULL ) ? ( server == NULL ) ? "%s" : \
						 "%s@%s" : "%s@%s:%s";
	int status;

	/* Combine the server, database name, and user name into one colon-
	   separated string as required by Oracle */
	if( strlen( userPtr ) + strlen( serverPtr ) + strlen( namePtr ) + 5 > 255 )
		return( CRYPT_DATA_OPEN );
	sprintf( buffer, formatString, userPtr, serverPtr, namePtr );

	/* Connect to the Oracle server and open a cursor */
	status = orlon( &keysetInfo->keysetDBMS.lda, keysetInfo->keysetDBMS.hda,
					buffer, -1, ( char * ) password, -1, 0 );
	if( status )
		{
		getErrorInfo( keysetInfo );
		if( !keysetInfo->errorCode )
			{
			/* Occasionally funny things can happen when we try to log on,
			   for example if the Oracle client has a resource problem
			   orlon() will fail with an error code but oerhms() will return
			   a non-error status, so if there's no apparent error we set
			   the error code to the orlon() return code and put a special
			   string in the buffer to tell the caller what's wrong */
			keysetInfo->errorCode = status;
			strcpy( keysetInfo->errorMessage, "ORA-????: resource error "
					"connecting to database, error text cannot be\n"
					"generated because no connection is established.  See "
					"error code for more\ninformation" );
			}
		return( CRYPT_DATA_OPEN );
		}
	if( oopen( &keysetInfo->keysetDBMS.cda, &keysetInfo->keysetDBMS.lda, 0,
			   -1, -1, 0, -1 ) )
		{
		getErrorInfo( keysetInfo );
		ologof( &keysetInfo->keysetDBMS.lda );
		return( CRYPT_DATA_OPEN );
		}

	/* Turn off auto-commit (this is the default anyway) */
	ocof( &keysetInfo->keysetDBMS.lda );

	/* Get the name of the blob data type for this database */
	strcpy( keysetInfo->keysetDBMS.blobName, "LONG RAW" );
	keysetInfo->keysetDBMS.hasBinaryBlobs = TRUE;

	return( CRYPT_OK );
	}

static void closeDatabase( KEYSET_INFO *keysetInfo )
	{
	oclose( &keysetInfo->keysetDBMS.cda );
	ologof( &keysetInfo->keysetDBMS.lda );
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( KEYSET_INFO *keysetInfo, const char *command )
	{
	/* Perform a deferred parse of the SQL statement */
	if( oparse( &keysetInfo->keysetDBMS.cda, ( char * ) command, -1, 1, 1 ) )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	/* Since the input is coded as part of the command, we don't need to bind
	   any input variables so we move directly to executing the statement */
	if( oexec( &keysetInfo->keysetDBMS.cda ) || keysetInfo->keysetDBMS.cda.rc != 0 )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( KEYSET_INFO *keysetInfo, const char *command )
	{
	ub2 rlen;
	int count, status;

	/* Perform a deferred parse of the SQL statement */
	if( oparse( &keysetInfo->keysetDBMS.cda, ( char * ) command, -1, 1, 1 ) )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	/* We're checking whether a given name or key ID exists by counting the
	   number of occurrences */
	if( odefin( &keysetInfo->keysetDBMS.cda, 1, ( ub1 * ) &count,
				sizeof( int ), SQLT_INT, -1, NULL, 0, -1, -1, &rlen, NULL ) )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	/* Since the input is coded as part of the command, we don't need to bind
	   any input variables so we move directly to executing the statement and
	   fetching the result */
	status = oexfet( &keysetInfo->keysetDBMS.cda, 1, 0, 0 );
	if( status == -904 || status == -942 )
		/* If the table or column doesn't exist, return the appropriate error
		   code */
		return( CRYPT_DATA_NOTFOUND );
	if( status )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	DEBUG( printf( "Rows processed = %d, result count = %d\n",
		   keysetInfo->keysetDBMS.cda.rpc, count ) );
	return( count );
	}

/* Perform a transaction which returns information */

static int performQuery( KEYSET_INFO *keysetInfo, const char *command,
						 char *data, int *dataLength, const int maxLength,
						 const DBMS_QUERY_TYPE queryType )
	{
	ub2 rlen;
	int status;

	/* If this assertion triggers, you need to add handling for the other
	   query types.  See keyset.h and misc/dbxodbc.c for guidance */
	assert( queryType == DBMS_QUERY_NORMAL );

	/* Perform a deferred parse of the SQL statement */
	if( oparse( &keysetInfo->keysetDBMS.cda, ( char * ) command, -1, 1, 1 ) )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	/* We're reading the key data.  Since a VARCHAR can be rather long and we
	   don't pass in a full-length buffer, we set the indicator pointer to
	   NULL to stop Oracle telling us that there could be up to 32K of output
	   even through the buffer we're supplying is only a few K */
	if( odefin( &keysetInfo->keysetDBMS.cda, 1, data, maxLength, SQLT_STR,
				-1, NULL, 0, -1, -1, &rlen, NULL ) )
		{
		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	/* Since the input is coded as part of the command, we don't need to bind
	   any input variables so we move directly to executing the statement and
	   fetching the result */
	if( oexfet( &keysetInfo->keysetDBMS.cda, 1, 0, 0 ) )
		{
		/* If the requested record wasn't found, handle the error
		   specially */
		if( keysetInfo->keysetDBMS.cda.rc == 1403 )
			return( CRYPT_DATA_NOTFOUND );

		getErrorInfo( keysetInfo );
		return( CRYPT_ERROR );
		}

	/* The returned length is the length of the field, not the length of the
	   data element, so we use strlen() to get the exact length */
	*dataLength = strlen( data );

	DEBUG( printf( "Rows processed = %d, dataLength = %d, strlen = %d\n", \
					keysetInfo->keysetDBMS.cda.rpc, rlen, *dataLength ) );
	return( CRYPT_OK );
	}

/* Set up the function pointers to the access methods */

int setAccessMethodOracle( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS.openDatabase = openDatabase;
	keysetInfo->keysetDBMS.closeDatabase = closeDatabase;
	keysetInfo->keysetDBMS.performUpdate = performUpdate;
	keysetInfo->keysetDBMS.performBulkUpdate = NULL;
	keysetInfo->keysetDBMS.performCheck = performCheck;
	keysetInfo->keysetDBMS.performQuery = performQuery;

	return( CRYPT_OK );
	}
#endif /* DBX_ORACLE */
