/****************************************************************************
*																			*
*						  cryptlib mSQL Mapping Routines					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <string.h>
#ifdef INC_CHILD
  #include "../crypt.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "misc/keyset.h"
#endif /* INC_CHILD */

/* !!!! dbtest-only !!!! */
#define DEBUG( x )	x
/* !!!! dbtest-only !!!! */

#define USE_MSQL1

/****************************************************************************
*																			*
*							Unix Database Access Functions					*
*																			*
****************************************************************************/

#ifdef DBX_MSQL

/* The length of the date/time field when encoded as a text string */

#define DATETIME_SIZE		14
#define TEXT_DATETIME_SIZE	"14"

/* mSQL has a few limits compared to standard SQL.  It doesn't implement
   COUNT at all, so we rewrite this as a general select with a limit of two
   items, since all we're interested in is whether 0, 1, or > 1 items exist.
   In addition it doesn't implement VARCHAR so we rewrite it to CHAR, and it
   doesn't support DATETIME so we replace it with CHAR(14) and later format
   the date information ourselves.

   In addition mSQL 1.x doesn't support the variable-length TEXT type, so
   we convert this to CHAR instead.  This is extremely nonoptimal since 
   CHAR fields aren't supposed to be very long (although mSQL seems to handle
   this without any problems), and because the fields are allocated as fixed-
   length records which are searchable and indexable even though they don't
   need to be.  This means that there's a considerable amount of unnecessary
   overhead in this use.

   The following function looks for these special cases and converts the
   query into the format required by mSQL.  Note that we include the '('
   character with the COUNT string to eliminate problems with matches inside
   the base64-encoded data since it isn't a valid base64 char */

static void convertQuery( char *query, const char *command )
	{
	char *strPtr;

	strcpy( query, command );
	if( !strncmp( command, "CREATE", 6 ) || !strncmp( command, "ALTER", 5 ) )
		{
		/* Convert VARCHAR to CHAR, DATETIME to CHAR(14) */
		while( ( strPtr = strstr( query, "VARCHAR" ) ) != NULL )
			memmove( strPtr, strPtr + 3, strlen( strPtr ) + 1 );
		if( ( strPtr = strstr( query, "DATETIME" ) ) != NULL )
			strncpy( strPtr, "CHAR(" TEXT_DATETIME_SIZE ")", 8 );

#ifdef USE_MSQL1
		/* mSQL 1.x doesn't support TEXT, so we convert this to CHAR */
		while( ( strPtr = strstr( query, "TEXT" ) ) != NULL )
			strncpy( strPtr, "CHAR", 4 );
#endif /* USE_MSQL1 */
		}
	if( ( strPtr = strstr( query, "COUNT(" ) ) != NULL )
		{
		/* Convert COUNT(x) to x ... LIMIT 2 */
		memmove( strPtr, strPtr + 6, strlen( strPtr ) + 1 );
		strPtr = strchr( query, ')' );
		memmove( strPtr, strPtr + 1, strlen( strPtr ) + 1 );
		strcat( strPtr, " LIMIT 2" );
		}
	DEBUG( printf( "XFM: %s\n", query ) );
	}

/* Get information on an mSQL error */

static int getErrorInfo( KEYSET_INFO *keysetInfo, const int defaultStatus )
	{
	int length = min( strlen( msqlErrMsg ), MAX_ERRMSG_SIZE - 1 );

	/* mSQL returns error information in a global variable msqlErrMsg (which
	   is going to work really well in a multithreaded environment).  Because
	   we can't get a real error code, we have to pick apart the error string
	   to provide more information on certain types of error */
	strncpy( keysetInfo->errorMessage, msqlErrMsg, length );
	keysetInfo->errorMessage[ length ] = '\0';
	keysetInfo->errorCode = CRYPT_ERROR;	/* No real error code available */

	/* The only information we can get from msqlSelectDB() and msqlQuery() is
	   "OK" or "not OK" (and, in 2.x, the number of items returned for 
	   msqlQuery()), so we have to pick apart the returned error message to
	   find out what went wrong.  This is pretty nasty since it may break if 
	   the error messages are ever changed */
	if( ( !strncmp( keysetInfo->errorMessage, "Table", 5 ) && \
		  !strncmp( keysetInfo->errorMessage + length - 6, "exists", 6 ) ) )
		return( CRYPT_DATA_DUPLICATE );

	DEBUG( printf( "Error message:%s\n", keysetInfo->errorMessage ) );
	return( defaultStatus );
	}

/* Open and close a connection to an mSQL server */

static int openDatabase( KEYSET_INFO *keysetInfo, const char *name,
						 const char *host, const char *user,
						 const char *password )
	{
	char *hostNamePtr = ( char * ) host;
	int status = -1;

	UNUSED( user );
	UNUSED( password );

	/* Connect to the mSQL server and select the database */
	if( host == NULL )
		hostNamePtr = "localhost";	/* Connect to default host */
	keysetInfo->keysetDBMS.sock = msqlConnect( hostNamePtr );
	if( keysetInfo->keysetDBMS.sock != -1 )
		status = msqlSelectDB( keysetInfo->keysetDBMS.sock, ( char * ) name );
	if( status == -1 )
		{
		getErrorInfo( keysetInfo, CRYPT_DATA_OPEN );
		if( keysetInfo->keysetDBMS.sock != -1 )
			msqlClose( keysetInfo->keysetDBMS.sock );
		keysetInfo->keysetDBMS.sock = CRYPT_ERROR;
		return( CRYPT_DATA_OPEN );
		}

	/* Get the name of the blob data type for this database.  mSQL handles
	   this in a somewhat odd manner, the given length isn't a maximum size
	   but the expected average length.  Anything longer than this is split
	   into the data table and external overflow buffers */
	strcpy( keysetInfo->keysetDBMS.blobName,
			"TEXT(" TEXT_MAX_ENCODED_KEYDATA_SIZE ")" );

	return( CRYPT_OK );
	}

static void closeDatabase( KEYSET_INFO *keysetInfo )
	{
	msqlClose( keysetInfo->keysetDBMS.sock );
	keysetInfo->keysetDBMS.sock = CRYPT_ERROR;
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( KEYSET_INFO *keysetInfo, const char *command,
						  const BOOLEAN hasBoundData )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status;

	/* mSQL doesn't support ALTER, this is used to change an existing table
	   to add key database-related fields.  The only time this can occur is
	   when the table already exists, so we return CRYPT_DATA_DUPLICATE to
	   tell the caller that it already exists.  This means an existing non-
	   key-database table can't be altered to become a key database like it
	   can for other databases, but at least the behaviour is consistent */
	if( !strncmp( command, "ALTER", 5 ) )
		return( CRYPT_DATA_DUPLICATE );

#ifdef USE_MSQL1
	/* mSQL 1.x doesn't support explicit indexing, so we convert this into
	   a NOP.  Note that this can cause problems later since we rely on the
	   index rejecting duplicate values for the various key ID fields.
	   Without this check, it's possible to insert keys with duplicate key
	   ID's into the database.  This is extremely unlikely (2^-80) for 
	   keyID's, and theoretically impossible (which means it'll happen 
	   every now and then) for issuerID's and nameID's */
	if( !strncmp( command, "CREATE INDEX", 12 ) || \
		!strncmp( command, "CREATE UNIQUE INDEX", 19 ) )
		return( CRYPT_OK );
#endif /* USE_MSQL1 */

	/* Submit the query to the mSQL server */
	convertQuery( query, command );
	if( hasBoundData )
		{
		/* mSQL doesn't support DATETIME (and 1.x doesn't support any time-
		   related data type at all) so we fake it using a CHAR field */
		struct tm *timeInfo = gmtime( &keysetInfo->keysetDBMS.date );
		char *datePtr = strchr( query, '?' );
		int length = strlen( query ), ch;

		/* If we can't add the date information, return a data overflow
		   error */
		if( length > MAX_SQL_QUERY_SIZE - DATETIME_SIZE )
			return( CRYPT_OVERFLOW );

		/* Poke the date info into the query string.  This encodes the data
		   in the ISO 8601 format, which allows comparisons like < and > 
		   to work properly.  When calculating the size, we use 
		   DATETIME_SIZE + 2 to account for the extra ''s needed to demarcate
		   the date string */
		if( datePtr == NULL )
			assert( NOTREACHED );
		memmove( datePtr + DATETIME_SIZE + 1, datePtr,
				 strlen( datePtr ) + 1 );
		ch = datePtr[ DATETIME_SIZE + 2 ];
		sprintf( datePtr, "'%04d%02d%02d%02d%02d%02d'",
				 timeInfo->tm_year + 1900, timeInfo->tm_mon + 1,
				 timeInfo->tm_mday, timeInfo->tm_hour, timeInfo->tm_min,
				 timeInfo->tm_sec );
		datePtr[ DATETIME_SIZE + 2 ] = ch;	/* Restore value zapped by '\0' */
		}

	status = msqlQuery( keysetInfo->keysetDBMS.sock, query );
	if( status == -1 )
		return( getErrorInfo( keysetInfo, CRYPT_DATA_WRITE ) );

	return( CRYPT_OK );
	}

/* Perform a transaction which returns information */

static int performQuery( KEYSET_INFO *keysetInfo, const char *command,
						 char *data, int *dataLength, const int maxLength,
						 const DBMS_QUERY_TYPE queryType )
	{
	m_result *result = NULL;
	char query[ MAX_SQL_QUERY_SIZE ];
	int status = CRYPT_OK;

	/* If this assertion triggers, you need to add handling for the other
	   query types.  See misc/dbxodbx.c for guidance */
	assert( queryType == DBMS_QUERY_NORMAL );

	/* Submit the query to the mSQL server */
	convertQuery( query, command );
	if( msqlQuery( keysetInfo->keysetDBMS.sock, query ) == -1 )
		return( getErrorInfo( keysetInfo, CRYPT_DATA_READ ) );

	/* Store the information returned in a result handle and fetch the
	   returned row (this is always just a single value, the key data).
	   The behaviour for this changed from version 1 to 2, and in
	   addition some odd 1.x variants may exhibit the version 2 
	   behaviour, so we check for both cases */
	result = msqlStoreResult();
	if( result == NULL )					/* Version 1.x behaviour */
		status = CRYPT_DATA_NOTFOUND;
	else
		{
		m_row row;

		row = msqlFetchRow( result );
		if( row == NULL )
			status = CRYPT_DATA_NOTFOUND;	/* Version 2.x behaviour */
		else
			{
			*dataLength = strlen( row[ 0 ] );
			if( *dataLength >= maxLength )
				{
				/* Too much data returned */
				*dataLength = 0;
				status = CRYPT_BADDATA;
				}
			else
				strcpy( data, row[ 0 ] );
			}
		msqlFreeResult( result );
		}

	DEBUG( printf( "performQuery:dataLength = %d\n", *dataLength ) );
	return( status );
	}

/* Perform a transaction which checks for the existence of an object */

static int performCheck( KEYSET_INFO *keysetInfo, const char *command )
	{
	m_result *result = NULL;
	char query[ MAX_SQL_QUERY_SIZE ];
	int count;

	/* Submit the query to the mSQL server */
	convertQuery( query, command );
	if( msqlQuery( keysetInfo->keysetDBMS.sock, query ) == -1 )
		return( getErrorInfo( keysetInfo, CRYPT_DATA_READ ) );

	/* Store the information returned in a result handle and find out how
	   many rows were returned.  The m_result value depends on the version of
	   mSQL, version 1.x would return a NULL value if no data was matched,
	   version 2.x returns a valid m_result value but subsequent calls to 
	   functions like msqlNumRows() and msqlFetchRow() return no data.  To 
	   work with both versions, we treat a NULL m_result as being equivalent 
	   to a count of 0.  There doesn't seem to be any way to return an error 
	   indicator from msqlStoreResult() */
	result = msqlStoreResult();
	if( result == NULL )
		return( CRYPT_DATA_NOTFOUND );
	count = msqlNumRows( result );
	msqlFreeResult( result );

	DEBUG( printf( "performCheck:count = %d\n", count ) );
	return( count ? CRYPT_OK : CRYPT_DATA_NOTFOUND );
	}

/* Set up the function pointers to the access methods */

int setAccessMethodMSQL( KEYSET_INFO *keysetInfo )
	{
	keysetInfo->keysetDBMS.openDatabase = openDatabase;
	keysetInfo->keysetDBMS.closeDatabase = closeDatabase;
	keysetInfo->keysetDBMS.performUpdate = performUpdate;
	keysetInfo->keysetDBMS.performBulkUpdate = NULL;
	keysetInfo->keysetDBMS.performCheck = performCheck;
	keysetInfo->keysetDBMS.performQuery = performQuery;

	return( CRYPT_OK );
	}
#endif /* DBX_MYSQL */
