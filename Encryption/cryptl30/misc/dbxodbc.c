/****************************************************************************
*																			*
*						 cryptlib ODBC Mapping Routines						*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* ODBC supports a primitive type of background processing, but the level of
   granularity leaves something to be desired since it's done on a per-call
   basis so if you're performing something like SQLExecute(), SQLParamData(),
   SQLPutData() you have to wait for each one to complete before you can call
   the next one.  In addition there isn't any nice wait mechanism, any
   further calls to anything will return SQL_STILL_EXECUTING until the
   function you called has finished (rather than queueing a series of
   requests).  Also, the really slow calls like SQLConnect() are all
   synchronous.  Because of this we don't even try to use any async calls, if
   background processing is needed we do it using Win32 threads */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../crypt.h"
#include "keyset.h"

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on some
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hODBC = NULL_HINSTANCE;

typedef RETCODE ( SQL_API *SQLALLOCENV )( HENV FAR *phenv );
typedef RETCODE ( SQL_API *SQLALLOCCONNECT )( HENV henv, HDBC FAR *phdbc );
typedef RETCODE ( SQL_API *SQLALLOCSTMT )( HDBC hdbc, HSTMT FAR *phstmt );
typedef RETCODE ( SQL_API *SQLBINDPARAMETER )( HSTMT hstmt, UWORD ipar,
				  SWORD fParamType, SWORD fCType, SWORD fSqlType,
				  UDWORD cbColDef, SWORD ibScale, PTR rgbValue, 
				  SDWORD cbValueMax, SDWORD FAR *pcbValue );
typedef RETCODE ( SQL_API *SQLCANCEL )( HSTMT hstmt );
typedef RETCODE ( SQL_API *SQLCONNECT )( HDBC hdbc, UCHAR FAR *szDSN,
				  SWORD cdDSN, UCHAR FAR *szUID, SWORD cbUID,
				  UCHAR FAR *szAuthStr, SWORD cbAuthStr );
typedef RETCODE ( SQL_API *SQLDISCONNECT )( HDBC hdbc );
typedef RETCODE ( SQL_API *SQLERROR )( HENV henv, HDBC hdbc, HSTMT hstmt,
				  UCHAR FAR *szSqlState, SDWORD FAR *pfNativeError,
				  UCHAR FAR *szErrorMsg, SWORD cbErrorMsgMax,
				  SWORD FAR *pcbErrorMsg );
typedef RETCODE ( SQL_API *SQLEXECDIRECT )( HSTMT hstmt, UCHAR FAR *szSqlStr,
				  SDWORD cbSqlStr );
typedef RETCODE ( SQL_API *SQLEXECUTE )( HSTMT hstmt );
typedef RETCODE ( SQL_API *SQLFETCH )( HSTMT hstmt );
typedef RETCODE ( SQL_API *SQLFREECONNECT )( HDBC hdbc );
typedef RETCODE ( SQL_API *SQLFREEENV )( HENV henv );
typedef RETCODE ( SQL_API *SQLFREESTMT )( HSTMT hstmt, UWORD fOption );
typedef RETCODE ( SQL_API *SQLGETDATA )( HSTMT hstmt, UWORD icol,
				  SWORD fCType, PTR rgbValue, SDWORD cbValueMax,
				  SDWORD FAR *pcbValue );
typedef RETCODE ( SQL_API *SQLGETINFO )( HDBC hdbc, UWORD fInfoType,
				  PTR rgbInfoValue, SWORD cbInfoValueMax,
				  SWORD FAR *pcbInfoValue );
typedef RETCODE ( SQL_API *SQLGETTYPEINFO )( HSTMT hstmt, SWORD fSqlType );
typedef RETCODE ( SQL_API *SQLPARAMDATA )( HSTMT hstmt, PTR FAR *prgbValue );
typedef RETCODE ( SQL_API *SQLPREPARE )( HSTMT hstmt, UCHAR FAR *szSqlStr,
				  SDWORD cbSqlStr );
typedef RETCODE ( SQL_API *SQLPUTDATA )( HSTMT hstmt, PTR rgbValue,
				  SDWORD cbValue );
typedef RETCODE ( SQL_API *SQLSETCONNECTOPTION )( HDBC hdbc, UWORD fOption,
				  UDWORD vParam );
typedef RETCODE ( SQL_API *SQLSETSTMTOPTION )( HSTMT hstmt, UWORD fOption,
				  UDWORD vParam );
typedef RETCODE ( SQL_API *SQLTRANSACT )( HENV henv, HDBC hdbc, UWORD fType );
static SQLALLOCCONNECT pSQLAllocConnect = NULL;
static SQLALLOCENV pSQLAllocEnv = NULL;
static SQLALLOCSTMT pSQLAllocStmt = NULL;
static SQLBINDPARAMETER pSQLBindParameter = NULL;
static SQLCANCEL pSQLCancel = NULL;
static SQLCONNECT pSQLConnect = NULL;
static SQLDISCONNECT pSQLDisconnect = NULL;
static SQLERROR pSQLError = NULL;
static SQLEXECDIRECT pSQLExecDirect = NULL;
static SQLEXECUTE pSQLExecute = NULL;
static SQLFETCH pSQLFetch = NULL;
static SQLFREECONNECT pSQLFreeConnect = NULL;
static SQLFREEENV pSQLFreeEnv = NULL;
static SQLFREESTMT pSQLFreeStmt = NULL;
static SQLGETDATA pSQLGetData = NULL;
static SQLGETINFO pSQLGetInfo = NULL;
static SQLGETTYPEINFO pSQLGetTypeInfo = NULL;
static SQLPARAMDATA pSQLParamData = NULL;
static SQLPREPARE pSQLPrepare = NULL;
static SQLPUTDATA pSQLPutData = NULL;
static SQLSETCONNECTOPTION pSQLSetConnectOption = NULL;
static SQLSETSTMTOPTION pSQLSetStmtOption = NULL;
static SQLTRANSACT pSQLTransact = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the ODBC
   driver under a different name */

#ifdef __WIN16__
  #define ODBC_LIBNAME	"ODBC.DLL"
#else
  #define ODBC_LIBNAME	"ODBC32.DLL"
#endif /* __WIN16__ */

/* SQLError() returns error information at various levels and is rather
   unstable in its handling of input parameters (if you pass it a valid hstmt
   then it may GPF after some calls so you need to force a NULL hstmt).  The
   following values define the levels of handle we pass in in order for
   SQLError() to work as advertised */

#define SQL_ERRLVL_0	0
#define SQL_ERRLVL_1	1
#define SQL_ERRLVL_2	2

/* Dynamically load and unload any necessary DBMS libraries */

void dbxInitODBC( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	
	/* If the ODBC module is already linked in, don't do anything */
	if( hODBC != NULL_HINSTANCE )
		return;

	/* Obtain a handle to the module containing the ODBC functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hODBC = LoadLibrary( ODBC_LIBNAME );
	SetErrorMode( errorMode );
	if( hODBC < HINSTANCE_ERROR )
		{
		hODBC = NULL_HINSTANCE;
		return;
		}
#else
	if( ( hODBC = LoadLibrary( ODBC_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pSQLAllocConnect = ( SQLALLOCCONNECT ) GetProcAddress( hODBC, "SQLAllocConnect" );
	pSQLAllocEnv = ( SQLALLOCENV ) GetProcAddress( hODBC, "SQLAllocEnv" );
	pSQLAllocStmt = ( SQLALLOCSTMT ) GetProcAddress( hODBC, "SQLAllocStmt" );
	pSQLBindParameter = ( SQLBINDPARAMETER ) GetProcAddress( hODBC, "SQLBindParameter" );
	pSQLCancel = ( SQLCANCEL ) GetProcAddress( hODBC, "SQLCancel" );
	pSQLConnect = ( SQLCONNECT ) GetProcAddress( hODBC, "SQLConnect" );
	pSQLDisconnect = ( SQLDISCONNECT ) GetProcAddress( hODBC, "SQLDisconnect" );
	pSQLError = ( SQLERROR ) GetProcAddress( hODBC, "SQLError" );
	pSQLExecDirect = ( SQLEXECDIRECT ) GetProcAddress( hODBC, "SQLExecDirect" );
	pSQLExecute = ( SQLEXECUTE ) GetProcAddress( hODBC, "SQLExecute" );
	pSQLFetch = ( SQLFETCH ) GetProcAddress( hODBC, "SQLFetch" );
	pSQLFreeConnect = ( SQLFREECONNECT ) GetProcAddress( hODBC, "SQLFreeConnect" );
	pSQLFreeEnv = ( SQLFREEENV ) GetProcAddress( hODBC, "SQLFreeEnv" );
	pSQLFreeStmt = ( SQLFREESTMT ) GetProcAddress( hODBC, "SQLFreeStmt" );
	pSQLGetData = ( SQLGETDATA ) GetProcAddress( hODBC, "SQLGetData" );
	pSQLGetInfo = ( SQLGETINFO ) GetProcAddress( hODBC, "SQLGetInfo" );
	pSQLGetTypeInfo = ( SQLGETTYPEINFO ) GetProcAddress( hODBC, "SQLGetTypeInfo" );
	pSQLParamData = ( SQLPARAMDATA ) GetProcAddress( hODBC, "SQLParamData" );
	pSQLPrepare = ( SQLPREPARE ) GetProcAddress( hODBC, "SQLPrepare" );
	pSQLPutData = ( SQLPUTDATA ) GetProcAddress( hODBC, "SQLPutData" );
	pSQLSetConnectOption = ( SQLSETCONNECTOPTION ) GetProcAddress( hODBC, "SQLSetConnectOption" );
	pSQLSetStmtOption = ( SQLSETSTMTOPTION ) GetProcAddress( hODBC, "SQLSetStmtOption" );
	pSQLTransact = ( SQLTRANSACT ) GetProcAddress( hODBC, "SQLTransact" );

	/* Make sure we got valid pointers for every ODBC function */
	if( pSQLAllocConnect == NULL || pSQLAllocEnv == NULL || 
		pSQLAllocStmt == NULL || pSQLBindParameter == NULL ||
		pSQLCancel == NULL || pSQLConnect == NULL ||
		pSQLDisconnect == NULL || pSQLError == NULL || 
		pSQLExecDirect == NULL || pSQLExecute == NULL || 
		pSQLFetch == NULL || pSQLFreeConnect == NULL || 
		pSQLFreeEnv == NULL || pSQLFreeStmt == NULL ||
		pSQLGetData == NULL || pSQLGetInfo == NULL ||
		pSQLGetTypeInfo == NULL || pSQLParamData == NULL ||
		pSQLPrepare == NULL || pSQLPutData == NULL ||
		pSQLSetConnectOption == NULL || pSQLSetStmtOption == NULL ||
		pSQLTransact == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hODBC );
		hODBC = NULL_HINSTANCE;
		}
	}

void dbxEndODBC( void )
	{
	if( hODBC != NULL_HINSTANCE )
		FreeLibrary( hODBC );
	hODBC = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Get information on an ODBC error */

static int getErrorInfo( KEYSET_INFO *keysetInfo, const int errorLevel,
						 const int defaultStatus )
	{
	HDBC hdbc = ( errorLevel < 1 ) ? SQL_NULL_HDBC : keysetInfo->keysetDBMS.hDbc;
	HDBC hstmt = ( errorLevel < 2 ) ? SQL_NULL_HSTMT : keysetInfo->keysetDBMS.hStmt;
	char szSqlState[ SQL_SQLSTATE_SIZE ];
	SDWORD dwNativeError;
	SWORD dummy;
	RETCODE retCode;

	retCode = pSQLError( keysetInfo->keysetDBMS.hEnv, hdbc, hstmt,
						 szSqlState, &dwNativeError,
						 keysetInfo->errorMessage, MAX_ERRMSG_SIZE - 1,
						 &dummy );
	keysetInfo->errorCode = ( int ) dwNativeError;	/* Usually 0 */

	/* Some of the information returned by SQLError() is pretty odd.  It
	   usually returns an ANSI SQL2 error state in SQLSTATE, but also returns
	   a native error code in NativeError.  However the NativeError codes
	   aren't documented anywhere, so we rely on SQLSTATE having a useful
	   value.  	We can also get SQL_NO_DATA_FOUND with SQLSTATE set to
	   "00000" and the error message string empty */
	if( !strncmp( szSqlState, "S0002", 5 ) ||	/* ODBC 2.x */
		!strncmp( szSqlState, "42S02", 5 ) ||	/* ODBC 3.x */
		( !strncmp( szSqlState, "00000", 5 ) && retCode == SQL_NO_DATA_FOUND ) ) 
		{
		/* Make sure the caller gets a sensible error message if they
		   try to examine the extended error information */
		if( !*keysetInfo->errorMessage )
			strcpy( keysetInfo->errorMessage, "No data found." );
		return( CRYPT_ERROR_NOTFOUND );
		}

	/* When we're trying to create a key database by augmenting an existing
	   database, the data we're adding may already be present, giving an
	   S0001 (table already exists) or S0021 (column already exists) error.
	   Usually we'd check for this by counting the number of items, but this
	   is incredibly slow using the Jet driver so instead we just try the
	   update anyway and convert the error code to the correct value here if
	   there's a problem */
	if( !strncmp( szSqlState, "S0001", 5 ) ||	/* ODBC 2.x */
		!strncmp( szSqlState, "42S01", 5 ) ||	/* ODBX 3.x */
		!strncmp( szSqlState, "S0021", 5 ) ||	/* ODBC 2.x */
		!strncmp( szSqlState, "42S21", 5 ) )	/* ODBC 3.x */
		return( CRYPT_ERROR_DUPLICATE );

	/* This one is a bit odd: An integrity constraint violation occurred,
	   which means (among other things) that an attempt was made to write a
	   duplicate value to a column constrained to contain unique values.  It
	   can also include things like writing a NULL value to a column
	   constrained to be NOT NULL, but this wouldn't normally happen so we
	   can convert this one to a duplicate data error */
	if( !strncmp( szSqlState, "23000", 5 ) )
		return( CRYPT_ERROR_DUPLICATE );

	return( defaultStatus );
	}

/* Some MS database engines uses nonstandard SQL for primary keys.  Instead 
   of allowing a simple PRIMARY KEY qualifier, they require that the use of 
   a primary key to be given as constraint on a column, which also involves 
   creating an index on that column.  In theory we could rewrite the primary
   key qualifier to create a fixed-name index using the constraint notation,
   however Access and SQL Server go even further and create an implied unique 
   index for the key, making it both useless for its intended purpose 
   (forcing clustering of identical entries) as well as rendering the table
   unusable (since it'll only allow a single value to be added).  Because of
   this we have to remove the PRIMARY KEY qualifier entirely.

   Detecting when this is necessary is tricky, it's required for Access, and 
   SQL Server but not for Foxpro or (probably) any non-MS products, so we 
   check for a DBMS name of "Access" or "SQL Server" and remove it if we find
   either */

static void convertQuery( KEYSET_INFO *keysetInfo, char *query, 
						  const char *command )
	{
	RETCODE retCode;
	SWORD bufLen;
	char *keywordPtr, buffer[ 128 ];

	strcpy( query, command );
	if( strncmp( command, "CREATE TABLE", 12 ) || \
		( keywordPtr = strstr( query, " PRIMARY KEY" ) ) == NULL )
		/* If it's not a CREATE TABLE command or there's no primary key
		   being used, there's nothing to do */
		return;

	/* It's a potential problem command, check for the presence of Access */
	retCode = pSQLGetInfo( keysetInfo->keysetDBMS.hDbc, SQL_DBMS_NAME,
						   buffer, sizeof( buffer ), &bufLen );
	if( ( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO ) && \
		strnicmp( buffer, "Access", 6 ) && \
		strnicmp( buffer, "SQL Server", 10 ) )
		return;		/* It's not Access or SQL Server */

#if 0
	/* Rewrite the PRIMARY KEY qualifier as a constraint on the column.  We
	   use the name 'PrimaryKey' since this is what Access uses by default */
	memmove( keywordPtr + 33, keywordPtr + 12, 
			 ( strlen( keywordPtr ) - 12 ) + 1 );
	memcpy( keywordPtr, "CONSTRAINT PrimaryKey PRIMARY KEY", 33 );
#else
	/* Remove the PRIMARY KEY qualifier */
	memmove( keywordPtr, keywordPtr + 12, strlen( keywordPtr + 12 ) + 1 );
#endif /* 0 */
	}

/* Get the name of the blob and date data type for this data source */

static int getBlobInfo( KEYSET_INFO *keysetInfo )
	{
	RETCODE retCode;
	SDWORD length;
	long count;

	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );

	/* First we see whether the database supports long binary strings (most
	   of the newer ones which are likely to be used do) */
	retCode = pSQLGetTypeInfo( keysetInfo->keysetDBMS.hStmt,
							   SQL_LONGVARBINARY );
	if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
		{
		/* Get the results of the transaction.  If the database doesn't
		   support this, we'll get SQL_NO_DATA_FOUND (status 100) returned */
		retCode = pSQLFetch( keysetInfo->keysetDBMS.hStmt );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			{
			/* Get the type name and maximum possible field length (we only
			   check the second return code since they both apply to the same
			   row) */
			pSQLGetData( keysetInfo->keysetDBMS.hStmt, 1, SQL_C_CHAR,
						 keysetInfo->keysetDBMS.blobName, 64, &length );
			retCode = pSQLGetData( keysetInfo->keysetDBMS.hStmt, 3,
								   SQL_C_LONG, &count, sizeof( long ),
								   &length );
			if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
				{
				keysetInfo->keysetDBMS.hasBinaryBlobs = TRUE;
				keysetInfo->keysetDBMS.blobType = SQL_LONGVARBINARY;
				}
			}
		else
			{
			/* Get the name of the long char type for this data source */
			pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_CLOSE );
			retCode = pSQLGetTypeInfo( keysetInfo->keysetDBMS.hStmt,
									   SQL_LONGVARCHAR );
			if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
				{
				/* Get the results of the transaction */
				retCode = pSQLFetch( keysetInfo->keysetDBMS.hStmt );
				if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
					{
					/* Get the type name and maximum possible field length
					   (we only check the second return code since they both
					   apply to the same row) */
					pSQLGetData( keysetInfo->keysetDBMS.hStmt, 1, SQL_C_CHAR,
								 keysetInfo->keysetDBMS.blobName, 64, &length );
					retCode = pSQLGetData( keysetInfo->keysetDBMS.hStmt, 3,
										   SQL_C_LONG, &count, sizeof( long ),
										   &length );
					keysetInfo->keysetDBMS.blobType = SQL_LONGVARCHAR;
					}
				}
			}
		}
	
	pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	/* Handle any errors.  If we couldn't get a blob type or the type is too
	   short to use, report it back as a database open failure */
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO || \
		count < 4096 )
		return( CRYPT_ERROR_OPEN );
	return( CRYPT_OK );
	}

/* Set up a date structure based on a time_t.  We have to use a full
   TIMESTAMP_STRUCT even though a DATE_STRUCT would do the job because
   the only standardised SQL time type is DATETIME which corresponds
   to a TIMESTAMP_STRUCT */

static void getDateInfo( TIMESTAMP_STRUCT *timestampInfo, time_t timeStamp )
	{
	struct tm *timeInfo = gmtime( &timeStamp );

	memset( timestampInfo, 0, sizeof( DATE_STRUCT ) );
	timestampInfo->year = timeInfo->tm_year + 1900;
	timestampInfo->month = timeInfo->tm_mon + 1;
	timestampInfo->day = timeInfo->tm_mday;
	timestampInfo->hour = timeInfo->tm_hour;
	timestampInfo->minute = timeInfo->tm_min;
	timestampInfo->second = timeInfo->tm_sec;
	}

/****************************************************************************
*																			*
*						 	Database Open/Close Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened ODBC connection.  We have to have this before
   openDatabase() since it may be called by openDatabase() if the open
   process fails.  This is necessary because the complex ODBC open may
   require a fairly extensive cleanup afterwards */

static void closeDatabase( KEYSET_INFO *keysetInfo )
	{
	/* Commit the transaction (the default transaction mode for drivers which
	   support SQLSetConnectOption() is auto-commit so the SQLTransact() call
	   isn't strictly necessary, but we play it safe anyway) */
	if( keysetInfo->keysetDBMS.needsUpdate )
		{
		pSQLTransact( keysetInfo->keysetDBMS.hEnv,
					  keysetInfo->keysetDBMS.hDbc, SQL_COMMIT );
		keysetInfo->keysetDBMS.needsUpdate = FALSE;
		}

	/* Clean up */
	pSQLDisconnect( keysetInfo->keysetDBMS.hDbc );
	pSQLFreeConnect( keysetInfo->keysetDBMS.hDbc );
	pSQLFreeEnv( keysetInfo->keysetDBMS.hEnv );
	keysetInfo->keysetDBMS.hStmt = 0;
	keysetInfo->keysetDBMS.hDbc = 0;
	keysetInfo->keysetDBMS.hEnv = 0;
	}

/* Open a connection to a data source using ODBC.  We don't check the return
   codes for many of the functions since the worst that can happen if they
   fail is that performance will be somewhat suboptimal.  In addition we
   don't allocate statement handles at this point since these are handled in
   various strange and peculiar ways by different ODBC drivers.  The main
   problem is that some drivers don't support mode than one hstmt per hdbc,
   some support only one active hstmt (an hstmt with results pending) per
   hdbc, and some support multiple active hstmt's per hdbc.  For this reason
   we use a strategy of allocating an hstmt, performing a transaction, and
   then immediately freeing it again afterwards */

static int openDatabase( KEYSET_INFO *keysetInfo, const char *name,
						 const char *server, const char *user,
						 const char *password )
	{
	RETCODE retCode;
	SWORD userLen = ( user == NULL ) ? 0 : SQL_NTS;
	SWORD passwordLen = ( password == NULL ) ? 0 : SQL_NTS;
	int status;

	UNUSED( server );

	/* Allocate environment and connection handles */
	pSQLAllocEnv( &keysetInfo->keysetDBMS.hEnv );
	pSQLAllocConnect( keysetInfo->keysetDBMS.hEnv,
					  &keysetInfo->keysetDBMS.hDbc );

	/* Set the access mode to readonly if we can.  The default is R/W, but
	   setting it to readonly optimises transaction management */
	if( keysetInfo->options == CRYPT_KEYOPT_READONLY )
		pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_ACCESS_MODE,
							  SQL_MODE_READ_ONLY );

	/* Set the cursor type to forward-only (which should be the default).
	   Note that we're passing an SQLSetStmtOption() arg.to
	   SQLSetConnectOption() which causes all stmt's allocated for this
	   connection to have the specified behaviour */
	pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_CURSOR_TYPE,
						  SQL_CURSOR_FORWARD_ONLY );

	/* Turn off scanning for escape clauses in the SQL strings, which lets
	   the driver pass the string directly to the data source.  See the
	   comment for the previous call about the arg.being passed */
	pSQLSetConnectOption( keysetInfo->keysetDBMS.hDbc, SQL_NOSCAN,
						  SQL_NOSCAN_ON );

	/* Once everything is set up the way we want it, try to connect to a data
	   source and allocate a statement handle */
	retCode = pSQLConnect( keysetInfo->keysetDBMS.hDbc, ( char * ) name,
						   SQL_NTS, ( char * ) user, userLen,
						   ( char * ) password, passwordLen );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		getErrorInfo( keysetInfo, SQL_ERRLVL_0, CRYPT_ERROR_OPEN );
		pSQLFreeConnect( keysetInfo->keysetDBMS.hDbc );
		pSQLFreeEnv( keysetInfo->keysetDBMS.hEnv );
		return( CRYPT_ERROR_OPEN );
		}

	/* Get various driver and source-specific information which we may need
	   later on */
#if 0	/* Not needed since we always supply the length */
	retCode = pSQLGetInfo( keysetInfo->keysetDBMS.hDbc, SQL_NEED_LONG_DATA_LEN,
						   buffer, sizeof( buffer ), &bufLen );
	if( retCode != SQL_SUCCESS )
		keysetInfo->keysetDBMS.needLongLength = TRUE;	/* Make a paranoid guess */
	else
		keysetInfo->keysetDBMS.needLongLength = ( *buffer == 'Y' ) ? TRUE : FALSE;
#endif /* 0 */

	/* Get information on the blob data type for this database */
	status = getBlobInfo( keysetInfo );
	if( cryptStatusError( status ) )
		{
		closeDatabase( keysetInfo );
		return( status );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Database Access Routines						*
*																			*
****************************************************************************/

/* Perform an update, handling any late-binding requirements */

static int updateDatabase( KEYSET_INFO *keysetInfo, const char *command,
						  const BOOLEAN hasBoundData )
	{
	RETCODE retCode;
	int status = CRYPT_OK;

	/* If we're performing a data update, set up any required bound parameters */
	if( hasBoundData )
		{
		getDateInfo( &keysetInfo->keysetDBMS.boundDate,
					 keysetInfo->keysetDBMS.date );
		keysetInfo->keysetDBMS.cbBlobLength = \
			SQL_LEN_DATA_AT_EXEC( keysetInfo->keysetDBMS.boundKeyDataLen );
		}

	/* Execute the command/hStmt as appropriate */
	if( command == NULL )
		retCode = pSQLExecute( keysetInfo->keysetDBMS.hStmt );
	else
		retCode = pSQLExecDirect( keysetInfo->keysetDBMS.hStmt,
								  ( char * ) command, SQL_NTS );
	if( retCode == SQL_NEED_DATA )
		{
		PTR pToken;

		/* Add the key data and perform a dummy SQLParamData() call to tell 
		   the ODBC driver that we've finished with the operation */
		pSQLParamData( keysetInfo->keysetDBMS.hStmt, &pToken );
		retCode = pSQLPutData( keysetInfo->keysetDBMS.hStmt,
							   keysetInfo->keysetDBMS.boundKeyData,
							   keysetInfo->keysetDBMS.boundKeyDataLen );
		if( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO )
			retCode = pSQLParamData( keysetInfo->keysetDBMS.hStmt, &pToken );
		}
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		return( getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_ERROR_WRITE ) );

	return( status );
	}

/* Perform a transaction which updates the database without returning any
   data */

static int performUpdate( KEYSET_INFO *keysetInfo, const char *command,
						  const BOOLEAN hasBoundData )
	{
	char query[ MAX_SQL_QUERY_SIZE ];
	int status;

	convertQuery( keysetInfo, query, command );

	/* Allocate an hstmt */
	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );

	/* If we're performing a data update, bind the various parameters */
	if( hasBoundData )
		{
		/* Bind the date parameter to the hstmt.  This is unlike the
		   behaviour mentioned in the ODBC documentation, which claims that
		   SQLExecDirect() will return SQL_NEED_DATA if it finds a parameter
		   marker.  Instead, we have to bind the parameters before calling
		   SQLExecDirect() and it reads them from the bound location as
		   required.  In addition an older version of the ODBC spec required
		   that the cbColDef value never exceed SQL_MAX_MESSAGE_LENGTH,
		   however this is defined to be 512 bytes which means we can't add
		   most certs of any real complexity or with keys > 1K bits, so we
		   pass in the actual data length here instead.  This works for all
		   ODBC drivers tested */
		pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 1, SQL_PARAM_INPUT,
						   SQL_C_TIMESTAMP, SQL_TIMESTAMP, 0, 0,
						   &keysetInfo->keysetDBMS.boundDate, 0, NULL );
		if( keysetInfo->keysetDBMS.hasBinaryBlobs )
#if 1
			pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 2, SQL_PARAM_INPUT,
							   SQL_C_BINARY, keysetInfo->keysetDBMS.blobType,
							   keysetInfo->keysetDBMS.boundKeyDataLen, 0,
							   ( PTR ) 6, 0, &keysetInfo->keysetDBMS.cbBlobLength );
#else	/* Check whether this works */
			pSQLBindParameter( keysetInfo->keysetDBMS.hStmt, 2, SQL_PARAM_INPUT,
							   SQL_C_BINARY, keysetInfo->keysetDBMS.blobType,
							   keysetInfo->keysetDBMS.boundKeyDataLen, 0,
							   keysetInfo->keysetDBMS.boundKeyData, 0, NULL );
#endif
		}

	/* Perform the update */
	status = updateDatabase( keysetInfo, query, hasBoundData );
	pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	return( status );
	}

/* Perform a transaction which checks for the existence of an object.  This
   performs a dummy fetch so all we return is the status */

static int performCheck( KEYSET_INFO *keysetInfo, const char *command )
	{
	RETCODE retCode;

	/* Allocate an hstmt and set the cursor concurrency to read-only */
	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );
	pSQLSetStmtOption( keysetInfo->keysetDBMS.hStmt, SQL_CONCURRENCY,
					   SQL_CONCUR_READ_ONLY );

	/* Execute the SQL statement */
	retCode = pSQLExecDirect( keysetInfo->keysetDBMS.hStmt,
							  ( char * ) command, SQL_NTS );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		int status;

		status = getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_ERROR_READ );
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );
		return( ( status == CRYPT_ERROR_NOTFOUND ) ? \
				CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_READ );
		}
	pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	return( CRYPT_OK );
	}

/* Perform a transaction which returns information */

static RETCODE fetchData( KEYSET_INFO *keysetInfo, char *data,
						  int *dataLength, const int maxLength,
						  const DBMS_QUERY_TYPE queryType )
	{
	const SWORD dataType = ( keysetInfo->keysetDBMS.hasBinaryBlobs ) ? \
						   SQL_C_BINARY : SQL_C_CHAR;
	RETCODE retCode;
	SDWORD length;

	/* Get the results of the transaction */
	retCode = pSQLFetch( keysetInfo->keysetDBMS.hStmt );
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		return( retCode );

	/* If we're just doing a presence check, we don't bother fetching data */
	if( queryType == DBMS_QUERY_CHECK )
		return( SQL_SUCCESS );

	/* Read the data */
#if 1
	retCode = pSQLGetData( keysetInfo->keysetDBMS.hStmt, 1, dataType,
						   data, maxLength, &length );
#else
	do
		{
		retCode = pSQLGetData( keysetInfo->keysetDBMS.hStmt, 1, dataType,
							   data, maxLength, &length );
		data += length;
		}
	while( retCode != SQL_NO_DATA && retCode != SQL_ERROR );
	if( retCode == SQL_NO_DATA )
		retCode == SQL_SUCCESS;
#endif /* 0 */
	*dataLength = ( int ) length;

	return( retCode );
	}

static int performQuery( KEYSET_INFO *keysetInfo, const char *command,
						 char *data, int *dataLength, const int maxLength,
						 const DBMS_QUERY_TYPE queryType )
	{
	const BOOLEAN isQuery = ( data == NULL && maxLength != sizeof( int ) ) ? \
							TRUE : FALSE;
	RETCODE retCode;

	/* If we're cancelling a continuing query, clean up and exit */
	if( queryType == DBMS_QUERY_CANCEL )
		{
		/* Cancel any outstanding requests and free the statement handle.
		   The cancel isn't strictly necessary, but it means the
		   SQLFreeStmt() doesn't return an error code to tell is something
		   was still happening */
		pSQLCancel( keysetInfo->keysetDBMS.hStmt );
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );
		return( CRYPT_OK );
		}

	/* If we're in the middle of a continuing query, fetch the next set of
	   results */
	if( queryType == DBMS_QUERY_CONTINUE )
		{
		retCode = fetchData( keysetInfo, data, dataLength, maxLength, 
							 DBMS_QUERY_CONTINUE );
		if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
			{
			int status;

			status = getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_ERROR_READ );
			if( status == CRYPT_ERROR_NOTFOUND )
				/* We've run out of results, signal the the query has
				   completed without treating it as an error */
				return( CRYPT_ERROR_COMPLETE );
			pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );
			return( CRYPT_ERROR_READ );
			}

		return( CRYPT_OK );
		}

	/* Allocate an hstmt and set the cursor concurrency to read-only */
	pSQLAllocStmt( keysetInfo->keysetDBMS.hDbc,
				   &keysetInfo->keysetDBMS.hStmt );
	if( queryType != DBMS_QUERY_START )
		/* Only return a maximum of 2 rows in response to an non-general
		   query SELECT statement.  The only thing we're interested in when
		   we're returning rows is whether there's more than one row present,
		   so it doesn't matter if we return 2 rows or 1000 */
		pSQLSetConnectOption( keysetInfo->keysetDBMS.hStmt, SQL_MAX_ROWS, 2 );
	pSQLSetStmtOption( keysetInfo->keysetDBMS.hStmt, SQL_CONCURRENCY,
					   SQL_CONCUR_READ_ONLY );

	/* Execute the SQL statement */
	retCode = pSQLExecDirect( keysetInfo->keysetDBMS.hStmt,
							  ( char * ) command, SQL_NTS );
	if( queryType != DBMS_QUERY_START && \
		( retCode == SQL_SUCCESS || retCode == SQL_SUCCESS_WITH_INFO ) )
		retCode = fetchData( keysetInfo, data, dataLength, maxLength, 
							 queryType );

	/* Handle any errors */
	if( retCode != SQL_SUCCESS && retCode != SQL_SUCCESS_WITH_INFO )
		{
		int status;

		status = getErrorInfo( keysetInfo, SQL_ERRLVL_2, CRYPT_ERROR_READ );
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );
		return( status );
		}
	if( queryType != DBMS_QUERY_START )
		pSQLFreeStmt( keysetInfo->keysetDBMS.hStmt, SQL_DROP );

	return( CRYPT_OK );
	}

/* Set up the function pointers to the access methods */

int setAccessMethodODBC( KEYSET_INFO *keysetInfo )
	{
	/* Make sure the driver is bound in */
	if( hODBC == NULL_HINSTANCE )
		return( CRYPT_ERROR_OPEN );

	keysetInfo->keysetDBMS.openDatabase = openDatabase;
	keysetInfo->keysetDBMS.closeDatabase = closeDatabase;
	keysetInfo->keysetDBMS.performUpdate = performUpdate;
	keysetInfo->keysetDBMS.performCheck = performCheck;
	keysetInfo->keysetDBMS.performQuery = performQuery;

	return( CRYPT_OK );
	}
