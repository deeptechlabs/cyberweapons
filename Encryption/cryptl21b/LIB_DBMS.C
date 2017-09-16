/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* The DBMS interface routines use the following key ID fields:

	Usage			Name		Contents
	-----			----		--------
	X.509 certs		nameID		hash( DistinguishedName )
	S/MIME			issuerID	hash( IssuerAndSerialNumber )
	cryptlib		keyID		hash( SubjectPublicKeyInfo )

   The user retrieves a key by name or email address, cryptlib objects
   retrieve the key by keyID, certificates retrieve the key by nameID, and
   CRL's and S/MIME signatures retrieve the key by issuerID.

   The database fields are:

	Name		Usage
	----		-----
	name		Key owner name
	email		Key owner email address
	date		Expiry date
	nameID		X.509 certificate ID
	issuerID	CRL, S/MIME ID
	keyID		cryptlib ID
	key			Key data

   The name and email field will be used most frequently (to encrypt data for
   a given recipient) and are indexed.  The issuerID and keyID fields are
   used less frequently to check certs and signatures, and are also indexed
   (with the advantage that, since the values are (virtually) unique and
   randomly distributed, the indexing will work very well for both hash and
   tree-based indices) */

#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "dbms.h"
  #include "asn1keys.h"
#else
  #include "crypt.h"
  #include "misc/dbms.h"
  #include "keymgmt/asn1keys.h"
#endif /* Compiler-specific includes */

#ifdef TEST
  #include <stdio.h>
  #ifdef __WIN16__				/* QuickWin has no printf() */
	#define DEBUG( x )
  #else
	#define DEBUG( x )			x
  #endif /* __WINDOWS__ */
#else
  #define DEBUG( x )
#endif /* TEST */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Format input parameters into SQL queries suitable for submission to the
   DBMS backend.  We could use sprintf() but there are problems with
   potential buffer overruns for long args, so we use the following function
   which acts as a (very minimal) string formatter in which all '$'s in the
   input are replaced by the next input string */

static void formatSQL( const BOOLEAN escapeArgChars, 
					   char *buffer, const char *format, ... )
	{
	va_list argPtr;
	char *formatPtr = ( char * ) format;
	int bufPos = 0;

	va_start( argPtr, format );
	while( *formatPtr )
		{
		if( *formatPtr == '$' )
			{
			char *strPtr = va_arg( argPtr, char * );

			/* Copy the string to the output buffer with conversion of any
			   special characters which are used by SQL */
			while( *strPtr )
				{
				int ch = *strPtr++;

				buffer[ bufPos++ ] = ch;
				if( escapeArgChars && ch == '\'' )
					/* Add a second ' to escape the first one */
					buffer[ bufPos++ ] = '\'';

				/* Make sure we haven't overflowed the input buffer.  We
				   check for MAX_SQL_QUERY_SIZE - 3 rather than
				   MAX_SQL_QUERY_SIZE - 2 in case the next character needs
				   escaping which expands it to two chars (MAX_SQL_QUERY_SIZE
				   - 1 is used for the '\0') */
				if( bufPos > MAX_SQL_QUERY_SIZE - 3 )
					{
					bufPos = 0;
					formatPtr = "";	/* Force exit on outer loop */
					break;
					}
				}

			formatPtr++;
			}
		else
			{
			/* Just copy the char over, with a length check */
			if( bufPos > MAX_SQL_QUERY_SIZE - 1 )
				{
				bufPos = 0;
				break;
				}
			buffer[ bufPos++ ] = *formatPtr++;
			}
		}
	buffer[ bufPos++ ] = '\0';	/* Add der terminador */

	va_end( argPtr );
	DEBUG( printf( "SQL: %s\n", buffer ) );
	}

/* Format input parameters into SQL queries, replacing meta-values with
   actual column names */

static int formatQuery( char *output, const char *input,
						const KEYSET_INFO *keysetInfo )
	{
	char *inputPtr = ( char * ) input;
	int outPos = 0, status = CRYPT_OK;

	while( *inputPtr )
		{
		if( *inputPtr == '$' )
			{
			const char *fieldName = ++inputPtr;
			const char *outputFieldName;
			int length;

			/* Extract the field name and translate it into the table
			   column name */
			while( isalpha( *inputPtr ) )
				inputPtr++;
			length = ( int ) ( inputPtr - ( char * ) fieldName );
			if( length <= 0 )
				{
				status = CRYPT_BADDATA;
				break;
				}
			if( !strnicmp( fieldName, "C", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameC;
			else
			if( !strnicmp( fieldName, "SP", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameSP;
			else
			if( !strnicmp( fieldName, "L", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameL;
			else
			if( !strnicmp( fieldName, "O", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameO;
			else
			if( !strnicmp( fieldName, "OU", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameOU;
			else
			if( !strnicmp( fieldName, "CN", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameCN;
			else
			if( !strnicmp( fieldName, "email", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameEmail;
			else
			if( !strnicmp( fieldName, "date", length ) )
				outputFieldName = keysetInfo->keysetDBMS.nameDate;
			else
				{
				status = CRYPT_BADDATA;
				break;
				}
			length = strlen( outputFieldName );

			/* Copy the translated name to the output buffer */
			if( outPos + length >= MAX_SQL_QUERY_SIZE )
				{
				status = CRYPT_OVERFLOW;
				break;
				}
			strcpy( output + outPos, outputFieldName );
			outPos += length;
			}
		else
			{
			/* Just copy the char over, with a length check */
			if( outPos > MAX_SQL_QUERY_SIZE - 1 )
				{
				outPos = 0;
				break;
				}
			output[ outPos++ ] = *inputPtr++;
			}
		}
	if( cryptStatusError( status ) )
		outPos = 0;
	output[ outPos++ ] = '\0';	/* Add der terminador */

	return( status );
	}

/* Assign a name for an RDBMS field */

static void assignFieldName( char *buffer, CRYPT_OPTION_TYPE option )
	{
	char *string;

	string = getOptionString( option );
	if( strlen( string ) < CRYPT_MAX_TEXTSIZE )
		strcpy( buffer, string );
	else
		{
		/* "Versenden kann man die Dinger ja unfrei, nur annehmen nicht" */
		strncpy( buffer, string, CRYPT_MAX_TEXTSIZE - 1 );
		buffer[ CRYPT_MAX_TEXTSIZE - 1 ] = '\0';
		}

	/* Perform some minimal processing on the string to make sure it fits
	   within the constraints set by most databases.  Typically this means a
	   maximum name length of 18 characters with the name starting with a
	   letter and containing only letters, numbers and underscores */
	while( *buffer )
		{
		if( !isalnum( *buffer ) )
			*buffer = '_';
		buffer++;
		}
	}

/****************************************************************************
*																			*
*							Database Access Functions						*
*																			*
****************************************************************************/

/* Create a new key database */

int dbmsCreateDatabase( KEYSET_INFO *keysetInfo )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	int status;

	keysetInfo->keysetDBMS.isDataUpdate = FALSE;

	/* Create tables for public keys and CRL's.  We use CHAR rather than
	   VARCHAR for the ID fields since these always have a fixed length and
	   CHAR is generally faster than VARCHAR.  In addition we make them NOT
	   NULL since these fields should always be present, and because this is
	   faster for some databases.

	   If the public-keys table is deleted outside of cryptlib and the CRL's 
	   table left in place then creation will fail because the CRL's table 
	   already exists.  This is an anomalous situation (the users shouldn't
	   modify the tables outside cryptlib), but in the interests of luser-
	   friendliness we ignore a CRYPT_DATA_DUPLICATE for the CRL's table if
	   the public key table creation succeeded */
	formatSQL( FALSE, sqlBuffer, "CREATE TABLE $ ( $ CHAR(2), $ VARCHAR(64), "
			   "$ VARCHAR(64), $ VARCHAR(64), $ VARCHAR(64), $ VARCHAR(64), "
			   "$ VARCHAR(64), $ DATETIME, $ CHAR(" TEXT_KEYID_SIZE ") NOT "
			   "NULL, $ CHAR(" TEXT_KEYID_SIZE ") NOT NULL, $ CHAR("
			   TEXT_KEYID_SIZE ") NOT NULL, $ $ NOT NULL )",
			   keysetInfo->keysetDBMS.nameTable, keysetInfo->keysetDBMS.nameC,
			   keysetInfo->keysetDBMS.nameSP, keysetInfo->keysetDBMS.nameL,
			   keysetInfo->keysetDBMS.nameO, keysetInfo->keysetDBMS.nameOU,
			   keysetInfo->keysetDBMS.nameCN, keysetInfo->keysetDBMS.nameEmail,
			   keysetInfo->keysetDBMS.nameDate, keysetInfo->keysetDBMS.nameNameID,
			   keysetInfo->keysetDBMS.nameIssuerID, keysetInfo->keysetDBMS.nameKeyID,
			   keysetInfo->keysetDBMS.nameKeyData, keysetInfo->keysetDBMS.blobName );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
	if( cryptStatusError( status ) )
		return( status );
	formatSQL( FALSE, sqlBuffer, "CREATE TABLE $ ( $ CHAR(" TEXT_KEYID_SIZE
			   ") NOT NULL )", keysetInfo->keysetDBMS.nameCRLTable,
			   keysetInfo->keysetDBMS.nameIssuerID );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
	if( cryptStatusError( status ) && status != CRYPT_DATA_DUPLICATE )
		{
		/* Undo the key table creation */
		formatSQL( FALSE, sqlBuffer, "DROP TABLE $",
				   keysetInfo->keysetDBMS.nameTable );
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		return( status );
		}

	/* Create an index for the names and email addresses in the public keys
	   table */
	formatSQL( FALSE, sqlBuffer, "CREATE INDEX $In ON $ ($)",
			   keysetInfo->keysetDBMS.nameCN,
			   keysetInfo->keysetDBMS.nameTable,
			   keysetInfo->keysetDBMS.nameCN );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
	if( cryptStatusOK( status ) )
		{
		formatSQL( FALSE, sqlBuffer, "CREATE INDEX $In ON $ ($)",
				   keysetInfo->keysetDBMS.nameEmail,
				   keysetInfo->keysetDBMS.nameTable,
				   keysetInfo->keysetDBMS.nameEmail );
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		}

	/* Create an index for the name ID, issuer ID, and key ID in the public
	   keys table.  Since these are (virtually) guaranteed to be unique, we
	   can specify this for the index we're creating.

	   Because the hashed ID values are randomly distributed, this is a
	   perfect situation for indexing, whether it's done as a hash table (all
	   unique values) or some form of tree (probabalistically balanced).

	   It may be better to create fewer indices, in general the name ID will
	   be used for X.509 cert.checks and the key ID will be used for cryptlib
	   objects.  The issuer ID is only used in CRL's and S/MIME, so no index
	   is created for this since neither are used much by cryptlib */
	if( cryptStatusOK( status ) )
		{
		formatSQL( FALSE, sqlBuffer, "CREATE UNIQUE INDEX $In ON $ ($)",
				   keysetInfo->keysetDBMS.nameNameID,
				   keysetInfo->keysetDBMS.nameTable,
				   keysetInfo->keysetDBMS.nameNameID );
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		}
#if 0	/* Not used since CRL/SMIME ID's aren't used much */
	formatSQL( FALSE, sqlBuffer, "CREATE UNIQUE INDEX $In ON $ ($)",
			   keysetInfo->keysetDBMS.nameIssuerID,
			   keysetInfo->keysetDBMS.nameTable,
			   keysetInfo->keysetDBMS.nameIssuerID );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
	if( cryptStatusError( status ) )
		return( CRYPT_DATA_WRITE );
#endif /* 0 */
	if( cryptStatusOK( status ) )
		{
		formatSQL( FALSE, sqlBuffer, "CREATE UNIQUE INDEX $In ON $ ($)",
				   keysetInfo->keysetDBMS.nameKeyID,
				   keysetInfo->keysetDBMS.nameTable,
				   keysetInfo->keysetDBMS.nameKeyID );
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		}
	if( cryptStatusOK( status ) )
		{
		formatSQL( FALSE, sqlBuffer, "CREATE UNIQUE INDEX $In ON $ ($)",
				   keysetInfo->keysetDBMS.nameIssuerID,
				   keysetInfo->keysetDBMS.nameCRLTable,
				   keysetInfo->keysetDBMS.nameIssuerID );
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo the key and CRL table creation */
		formatSQL( FALSE, sqlBuffer, "DROP TABLE $",
				   keysetInfo->keysetDBMS.nameTable );
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		formatSQL( FALSE, sqlBuffer, "DROP TABLE $",
				   keysetInfo->keysetDBMS.nameCRLTable );
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		return( CRYPT_DATA_WRITE );
		}

	return( CRYPT_OK );
	}

/* Perform part of a bulk add of data to a database.  This is a specialised
   version of dbmsAddKey() which is intended for adding large amounts of
   data without the special checking (and accompanying overhead) of
   dbmsAddKey() */

static int doBulkAdd( KEYSET_INFO *keysetInfo )
	{
	int status;

	/* If we're starting a bulk update, prepare the SQL statement and submit
	   it to the database backend */
	if( keysetInfo->keysetDBMS.bulkUpdateState == BULKUPDATE_START )
		{
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		/* Prepare the SQL statement for execution */
		formatSQL( FALSE, sqlBuffer, "INSERT INTO $ VALUES ( ?, ?, ?, ?, ?, "
				   "?, ?, ?, ?, ?, ?, ? )", keysetInfo->keysetDBMS.nameTable );
		status = keysetInfo->keysetDBMS.performBulkUpdate( keysetInfo, sqlBuffer );

		/* If everything went OK, move to the update state */
		if( cryptStatusOK( status ) )
			keysetInfo->keysetDBMS.bulkUpdateState = BULKUPDATE_UPDATE;

		return( status );
		}

	/* If we're finishing a bulk update, commit the transaction */
	if( keysetInfo->keysetDBMS.bulkUpdateState == BULKUPDATE_FINISH )
		{
		status = keysetInfo->keysetDBMS.performBulkUpdate( keysetInfo, NULL );
		keysetInfo->keysetDBMS.bulkUpdateState = BULKUPDATE_NONE;
		return( status );
		}

	/* We're in the middle of a bulk update, add the data without the usual
	   checking and committing of the transaction */
	return( keysetInfo->keysetDBMS.performBulkUpdate( keysetInfo, NULL ) );
	}

/* Add a key record or CRL entry to a database.  Since RDBMS's allow existing
   records to be overwritten without providing any indication of this, we
   need to use two SELECT's to check for problems before we try and make any
   changes.  Unfortunately these checks roughly double the time required to
   perform an add, but there's no easy workaround.  Because of this we also
   provide a bulk update facility which doesn't bother with these checks,
   speeding up the process of building large key databases */

int dbmsAddKey( KEYSET_INFO *keysetInfo, const void *nameID,
				const void *issuerID, const void *keyID, const void *keyData,
				const int keyDataLen )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	int status;

	/* If we're in the middle of a query, we can't do anything else */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_INCOMPLETE );

	keysetInfo->keysetDBMS.isDataUpdate = TRUE;

	/* base64-encode the nameID, issuer ID, key ID, and key data if necessary.
	   We truncate the last character of the ID's, since this is always a
	   padding character */
	if( keyData != NULL )
		{
		base64encode( keysetInfo->keysetDBMS.boundNameID, nameID, KEYID_SIZE,
					  CRYPT_CERTTYPE_NONE, CRYPT_CERTFORMAT_NONE );
		keysetInfo->keysetDBMS.boundNameID[ MAX_ENCODED_KEYID_SIZE - 1 ] = '\0';
		base64encode( keysetInfo->keysetDBMS.boundIssuerID, issuerID,
					  KEYID_SIZE, CRYPT_CERTTYPE_NONE, CRYPT_CERTFORMAT_NONE );
		keysetInfo->keysetDBMS.boundIssuerID[ MAX_ENCODED_KEYID_SIZE - 1 ] = '\0';
		base64encode( keysetInfo->keysetDBMS.boundKeyID, keyID, KEYID_SIZE,
					  CRYPT_CERTTYPE_NONE, CRYPT_CERTFORMAT_NONE );
		keysetInfo->keysetDBMS.boundKeyID[ MAX_ENCODED_KEYID_SIZE - 1 ] = '\0';
		if( !keysetInfo->keysetDBMS.hasBinaryBlobs )
			keysetInfo->keysetDBMS.boundKeyDataLen = \
					base64encode( keysetInfo->keysetDBMS.boundKeyData,
								  keyData, keyDataLen, CRYPT_CERTTYPE_NONE,
								  CRYPT_CERTFORMAT_NONE );
		else
			{
			memcpy( keysetInfo->keysetDBMS.boundKeyData, keyData, keyDataLen );
			keysetInfo->keysetDBMS.boundKeyDataLen = keyDataLen;
			}
		}

	/* If we're being asked to perform a bulk update, handle this specially */
	if( keysetInfo->keysetDBMS.bulkUpdateState != BULKUPDATE_NONE )
		{
		/* If the database glue code supports bulk updates, handle this
		   now */
		if( keysetInfo->keysetDBMS.performBulkUpdate != NULL )
			return( doBulkAdd( keysetInfo ) );

		/* If the database glue code doesn't handle bulk updates, either
		   return or drop through to the usual code so it'll be handled as a
		   normal update */
		if( keysetInfo->keysetDBMS.bulkUpdateState != BULKUPDATE_UPDATE )
			{
			/* Skip the update start amd finish states if necessary */
			if( keysetInfo->keysetDBMS.bulkUpdateState == BULKUPDATE_START )
				keysetInfo->keysetDBMS.bulkUpdateState = BULKUPDATE_UPDATE;
			if( keysetInfo->keysetDBMS.bulkUpdateState == BULKUPDATE_FINISH )
				keysetInfo->keysetDBMS.bulkUpdateState = BULKUPDATE_NONE;

			return( CRYPT_OK );
			}
		}

	/* If we're adding a CRL entry, write it to the CRL table and exit */
	if( nameID == NULL && keyID == NULL && keyData == NULL )
		{
		char encodedIssuerID[ MAX_ENCODED_KEYID_SIZE ];

		/* If we're adding a CRL, all the data is contained in the SQL
		   command (rather than being bound in via values stored in the
		   keysetInfo) */
		keysetInfo->keysetDBMS.isDataUpdate = FALSE;

		base64encode( encodedIssuerID, issuerID, KEYID_SIZE,
					  CRYPT_CERTTYPE_NONE, CRYPT_CERTFORMAT_NONE );
		encodedIssuerID[ MAX_ENCODED_KEYID_SIZE - 1 ] = '\0';

		/* Check whether the entry is already present.  If it is, don't do
		   anything */
		formatSQL( TRUE, sqlBuffer, "SELECT COUNT(*) FROM $ WHERE $ = '$'",
				   keysetInfo->keysetDBMS.nameCRLTable,
				   keysetInfo->keysetDBMS.nameIssuerID,
				   encodedIssuerID );
		status = keysetInfo->keysetDBMS.performCheck( keysetInfo, sqlBuffer );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_DATA_READ ) ? CRYPT_DATA_WRITE : status );
		if( status > 0 )
			return( CRYPT_OK );

		/* Insert the entry */
		formatSQL( TRUE, sqlBuffer, "INSERT INTO $ VALUES ( '$' )",
				   keysetInfo->keysetDBMS.nameCRLTable, encodedIssuerID );
		return( keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer ) );
		}

	/* Check whether a row with the required name already exists */
	formatSQL( TRUE, sqlBuffer, "SELECT COUNT(*) FROM $ WHERE $ = '$'",
			   keysetInfo->keysetDBMS.nameTable,
			   keysetInfo->keysetDBMS.nameCN,
			   keysetInfo->keysetDBMS.CN );
	status = keysetInfo->keysetDBMS.performCheck( keysetInfo, sqlBuffer );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_DATA_READ ) ? CRYPT_DATA_WRITE : status );
	if( status > 0 )
		{
		/* The row already exists, now check whether there's also a key
		   already present */
		formatSQL( FALSE, sqlBuffer, "SELECT COUNT(*) FROM $ WHERE $ = '$'",
				   keysetInfo->keysetDBMS.nameTable,
				   keysetInfo->keysetDBMS.nameKeyID,
				   keysetInfo->keysetDBMS.boundKeyID );
		status = keysetInfo->keysetDBMS.performCheck( keysetInfo, sqlBuffer );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_DATA_READ ) ? CRYPT_DATA_WRITE : status );
		if( status > 0 )
			/* The key is also present, don't try to add the data */
			return( CRYPT_DATA_DUPLICATE );

		/* Add the key fields to the existing record.  Note that we don't
		   add an email address in this case, the checking for whether this
		   exists as well starts to get rather complex so we assume it's
		   present if it's required */
		if( keysetInfo->keysetDBMS.hasBinaryBlobs )
			formatSQL( TRUE, sqlBuffer, "UPDATE $ SET $ = ?, $ = '$', $ = '$', "
				"$ = '$', $ = ? WHERE $ = '$'", keysetInfo->keysetDBMS.nameTable,
				keysetInfo->keysetDBMS.nameDate, keysetInfo->keysetDBMS.nameNameID,
				keysetInfo->keysetDBMS.boundNameID, keysetInfo->keysetDBMS.nameIssuerID,
				keysetInfo->keysetDBMS.boundIssuerID, keysetInfo->keysetDBMS.nameKeyID,
				keysetInfo->keysetDBMS.boundKeyID, keysetInfo->keysetDBMS.nameKeyData,
				keysetInfo->keysetDBMS.nameCN, keysetInfo->keysetDBMS.CN );
		else
			formatSQL( TRUE, sqlBuffer, "UPDATE $ SET $ = ?, $ = '$', $ = '$', "
				"$ = '$', $ = '$' WHERE $ = '$'", keysetInfo->keysetDBMS.nameTable,
				keysetInfo->keysetDBMS.nameDate, keysetInfo->keysetDBMS.nameNameID,
				keysetInfo->keysetDBMS.boundNameID, keysetInfo->keysetDBMS.nameIssuerID,
				keysetInfo->keysetDBMS.boundIssuerID, keysetInfo->keysetDBMS.nameKeyID,
				keysetInfo->keysetDBMS.boundKeyID, keysetInfo->keysetDBMS.nameKeyData,
				keysetInfo->keysetDBMS.boundKeyData, keysetInfo->keysetDBMS.nameCN,
				keysetInfo->keysetDBMS.CN );
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* Insert a new record */
		if( keysetInfo->keysetDBMS.hasBinaryBlobs )
			formatSQL( TRUE, sqlBuffer, "INSERT INTO $ VALUES ( '$', '$', '$', "
					   "'$', '$', '$', '$', ?, '$', '$', '$', ? )",
					   keysetInfo->keysetDBMS.nameTable, keysetInfo->keysetDBMS.C,
					   keysetInfo->keysetDBMS.SP, keysetInfo->keysetDBMS.L,
					   keysetInfo->keysetDBMS.O, keysetInfo->keysetDBMS.OU,
					   keysetInfo->keysetDBMS.CN, keysetInfo->keysetDBMS.email,
					   keysetInfo->keysetDBMS.boundNameID,
					   keysetInfo->keysetDBMS.boundIssuerID,
					   keysetInfo->keysetDBMS.boundKeyID );
		else
			formatSQL( TRUE, sqlBuffer, "INSERT INTO $ VALUES ( '$', '$', '$', "
					   "'$', '$', '$', '$', ?, '$', '$', '$', '$' )",
					   keysetInfo->keysetDBMS.nameTable, keysetInfo->keysetDBMS.C,
					   keysetInfo->keysetDBMS.SP, keysetInfo->keysetDBMS.L,
					   keysetInfo->keysetDBMS.O, keysetInfo->keysetDBMS.OU, 
					   keysetInfo->keysetDBMS.CN, keysetInfo->keysetDBMS.email, 
					   keysetInfo->keysetDBMS.boundNameID, 
					   keysetInfo->keysetDBMS.boundIssuerID,
					   keysetInfo->keysetDBMS.boundKeyID,
					   keysetInfo->keysetDBMS.boundKeyData );
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Delete a key record from the database */

int dbmsDeleteKey( KEYSET_INFO *keysetInfo, const CRYPT_KEYID_TYPE keyIDtype,
				   const void *keyID )
	{
	const char *databaseKeyName, *databaseKey;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char keyIDbuffer[ MAX_ENCODED_KEYID_SIZE ];
	int status;

	/* If we're in the middle of a bulk update or query, we can't do anything
	   else */
	if( keysetInfo->keysetDBMS.bulkUpdateState != BULKUPDATE_NONE || \
		keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_INCOMPLETE );

	keysetInfo->keysetDBMS.isDataUpdate = FALSE;

	/* Set up the fields for a query to access the record */
	if( keyIDtype == CRYPT_KEYID_OBJECT )
		{
		/* base64-encode the key ID so we can use it with database queries,
		   and set up the query fields for a query by key ID */
		base64encode( keyIDbuffer, keyID, KEYID_SIZE, CRYPT_CERTTYPE_NONE,
					  CRYPT_CERTFORMAT_NONE );
		keyIDbuffer[ MAX_ENCODED_KEYID_SIZE - 1 ] = '\0';
		databaseKey = keyIDbuffer;
		databaseKeyName = keysetInfo->keysetDBMS.nameKeyID;
		}
	else
		{
		/* Set up the query fields for a query by name or email address */
		databaseKey = keyID;
		databaseKeyName = ( keyIDtype == CRYPT_KEYID_NAME ) ? \
			keysetInfo->keysetDBMS.nameCN : keysetInfo->keysetDBMS.nameEmail;
		}

	/* Check whether the key is present in the database.  We return an error
	   code if the key isn't present or if there were multiple matches for
	   the ID (the latter shouldn't happen unless some other software or
	   lusers have been messing around with the database, which may happen if
	   it's shared with other programs) */
	formatSQL( TRUE, sqlBuffer, "SELECT COUNT(*) FROM $ WHERE $ = '$'",
			   keysetInfo->keysetDBMS.nameTable, databaseKeyName, databaseKey );
	status = keysetInfo->keysetDBMS.performCheck( keysetInfo, sqlBuffer );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_DATA_READ ) ? CRYPT_DATA_WRITE : status );
	if( status == 0 )
		return( CRYPT_DATA_NOTFOUND );
	if( status > 1 )
		return( CRYPT_DATA_DUPLICATE );

	/* Delete the key from the database */
	formatSQL( TRUE, sqlBuffer, "DELETE FROM $ WHERE $ = '$'",
			   keysetInfo->keysetDBMS.nameTable, databaseKeyName, databaseKey );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR ) ? CRYPT_DATA_WRITE : status );

	return( CRYPT_OK );
	}

/* Retrieve a key record from the database */

int dbmsGetKey( KEYSET_INFO *keysetInfo, const CRYPT_KEYID_TYPE keyIDtype,
				const void *keyID, void *keyData )
	{
	const char *databaseKeyName, *databaseKey;
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char keyIDbuffer[ MAX_ENCODED_KEYID_SIZE ];
	char keyBuffer[ MAX_ENCODED_KEYDATA_SIZE ], *keyPtr = keyBuffer;
	int keyLength, status;

	/* If we're in the middle of a bulk update or query, we can't do anything
	   else */
	if( keysetInfo->keysetDBMS.bulkUpdateState != BULKUPDATE_NONE || \
		keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_INCOMPLETE );

	keysetInfo->keysetDBMS.isDataUpdate = FALSE;

	/* Set up the fields for a query to access the record */
	if( keyIDtype == CRYPT_KEYID_OBJECT )
		{
		/* base64-encode the key ID so we can use it with database queries,
		   and set up the query fields for a query by key ID */
		base64encode( keyIDbuffer, keyID, KEYID_SIZE, CRYPT_CERTTYPE_NONE,
					  CRYPT_CERTFORMAT_NONE );
		keyIDbuffer[ MAX_ENCODED_KEYID_SIZE - 1 ] = '\0';
		databaseKey = keyIDbuffer;
		databaseKeyName = keysetInfo->keysetDBMS.nameKeyID;
		}
	else
		{
		/* Set up the query fields for a query by name or email address */
		databaseKey = keyID;
		databaseKeyName = ( keyIDtype == CRYPT_KEYID_NAME ) ? \
			keysetInfo->keysetDBMS.nameCN : keysetInfo->keysetDBMS.nameEmail;
		}

	/* If we're doing a CRL query, just check for the presence of this
	   issuerID and exit */
	if( keyData == NULL )
		{
		formatSQL( TRUE, sqlBuffer, "SELECT COUNT(*) FROM $ WHERE $ = '$'",
				   keysetInfo->keysetDBMS.nameCRLTable,
				   keysetInfo->keysetDBMS.nameIssuerID, databaseKey );
		status = keysetInfo->keysetDBMS.performCheck( keysetInfo, sqlBuffer );
		if( cryptStatusError( status ) )
			return( status );

		/* If we get a positive count then there's a revocation present,
		   indicate that the cert we're querying should be regarded as
		   invalid */
		return( status > 0 ) ? CRYPT_INVALID : CRYPT_OK;
		}

	/* If we have binary blob support, fetch the data directly into the
	   getkey buffer */
	if( keysetInfo->keysetDBMS.hasBinaryBlobs )
		keyPtr = keyData;

	/* Retrieve the record */
	formatSQL( TRUE, sqlBuffer, "SELECT $ FROM $ WHERE $ = '$'",
			   keysetInfo->keysetDBMS.nameKeyData,
			   keysetInfo->keysetDBMS.nameTable, databaseKeyName, databaseKey );
	status = keysetInfo->keysetDBMS.performQuery( keysetInfo, sqlBuffer,
												  keyPtr, &keyLength,
												  MAX_ENCODED_KEYDATA_SIZE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR ) ? CRYPT_DATA_READ : status );

	/* base64-decode the binary key data if necessary */
	if( !keysetInfo->keysetDBMS.hasBinaryBlobs && \
		!base64decode( keyData, keyBuffer, keyLength, CRYPT_CERTFORMAT_NONE ) )
		return( CRYPT_BADDATA );

	return( CRYPT_OK );
	}

/* Send a general query to the database and retrieve keys based on it */

int dbmsQuery( KEYSET_INFO *keysetInfo, const char *query, void *keyData )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char keyBuffer[ MAX_ENCODED_KEYDATA_SIZE ], *keyPtr = keyBuffer;
	int keyLength, status;

	/* If we're in the middle of a bulk update, we can't do anything else */
	if( keysetInfo->keysetDBMS.bulkUpdateState != BULKUPDATE_NONE )
		return( CRYPT_INCOMPLETE );

	keysetInfo->keysetDBMS.isDataUpdate = FALSE;

	/* If we have binary blob support, fetch the data directly into the
	   getkey buffer */
	if( keysetInfo->keysetDBMS.hasBinaryBlobs )
		keyPtr = keyData;

	/* Retrieve the record.  The first time around we send the query.  After
	   that, we retrieve results from the query */
	if( query != NULL )
		{
		/* Send the query to the database */
		if( !stricmp( query, "cancel" ) )
			{
			/* We're cancelling an existing query, pass it on down */
			status = keysetInfo->keysetDBMS.performQuery( keysetInfo, "cancel",
														  NULL, NULL, 0 );
			keysetInfo->keysetDBMS.queryState = QUERY_NONE;
			}
		else
			{
			char expandedQuery[ MAX_SQL_QUERY_SIZE ];

			/* If we're in the middle of an existing query the user needs to
			   cancel it before starting another one */
			if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
				return( CRYPT_INCOMPLETE );

			/* Rewrite the user-supplied portion of the query using the
			   actual column names and turn it into a SELECT statement */
			formatQuery( expandedQuery, query, keysetInfo );
			formatSQL( FALSE, sqlBuffer, "SELECT $ FROM $ WHERE $",
					   keysetInfo->keysetDBMS.nameKeyData,
					   keysetInfo->keysetDBMS.nameTable, expandedQuery );
			status = keysetInfo->keysetDBMS.performQuery( keysetInfo,
												sqlBuffer, NULL, NULL, 0 );
			if( cryptStatusOK( status ) )
				keysetInfo->keysetDBMS.queryState = QUERY_INPROGRESS;
			}
		}
	else
		/* There's a query already in progress, fetch the next record */
		status = keysetInfo->keysetDBMS.performQuery( keysetInfo, NULL,
							keyPtr, &keyLength, MAX_ENCODED_KEYDATA_SIZE );
	if( cryptStatusError( status ) )
		{
		/* If there are no more results available, wrap up the processing */
		if( status == CRYPT_COMPLETE )
			{
			keysetInfo->keysetDBMS.performQuery( keysetInfo, "cancel", NULL,
												 NULL, 0 );
			keysetInfo->keysetDBMS.queryState = QUERY_NONE;
			}
		return( ( status == CRYPT_ERROR ) ? CRYPT_DATA_READ : status );
		}

	/* If we're fetching results, base64-decode the binary key data if
	   necessary */
	if( query == NULL && !keysetInfo->keysetDBMS.hasBinaryBlobs && \
		!base64decode( keyData, keyBuffer, keyLength, CRYPT_CERTFORMAT_NONE ) )
		return( CRYPT_BADDATA );

	return( CRYPT_OK );
	}

/* Open a connection to a database */

int dbmsOpenDatabase( KEYSET_INFO *keysetInfo, const char *name,
					  const char *server, const char *user,
					  const char *password )
	{
	int status;

	/* Set up the names of the database tables and columns */
	assignFieldName( keysetInfo->keysetDBMS.nameTable, CRYPT_OPTION_KEYS_DBMS_NAMETABLE );
	assignFieldName( keysetInfo->keysetDBMS.nameCRLTable, CRYPT_OPTION_KEYS_DBMS_NAMECRLTABLE );
	assignFieldName( keysetInfo->keysetDBMS.nameC, CRYPT_OPTION_KEYS_DBMS_NAME_C );
	assignFieldName( keysetInfo->keysetDBMS.nameSP, CRYPT_OPTION_KEYS_DBMS_NAME_SP );
	assignFieldName( keysetInfo->keysetDBMS.nameL, CRYPT_OPTION_KEYS_DBMS_NAME_L );
	assignFieldName( keysetInfo->keysetDBMS.nameO, CRYPT_OPTION_KEYS_DBMS_NAME_O );
	assignFieldName( keysetInfo->keysetDBMS.nameOU, CRYPT_OPTION_KEYS_DBMS_NAME_OU );
	assignFieldName( keysetInfo->keysetDBMS.nameCN, CRYPT_OPTION_KEYS_DBMS_NAME_CN );
	assignFieldName( keysetInfo->keysetDBMS.nameEmail, CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL );
	assignFieldName( keysetInfo->keysetDBMS.nameDate, CRYPT_OPTION_KEYS_DBMS_NAMEDATE );
	assignFieldName( keysetInfo->keysetDBMS.nameNameID, CRYPT_OPTION_KEYS_DBMS_NAMENAMEID );
	assignFieldName( keysetInfo->keysetDBMS.nameIssuerID, CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID );
	assignFieldName( keysetInfo->keysetDBMS.nameKeyID, CRYPT_OPTION_KEYS_DBMS_NAMEKEYID );
	assignFieldName( keysetInfo->keysetDBMS.nameKeyData, CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA );

	/* Perform a database back-end specific open */
	status = keysetInfo->keysetDBMS.openDatabase( keysetInfo,
					( name == ( char * ) CRYPT_UNUSED ) ? NULL : name,
					( server == ( char * ) CRYPT_UNUSED ) ? NULL : server,
					( user == ( char * ) CRYPT_UNUSED ) ? NULL : user,
					( password == ( char * ) CRYPT_UNUSED ) ? NULL : password );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure the field names are of an appropriate length.  We also make
	   sure that the names of fields which have indices are at least one
	   character shorter than the allowed maximum since we need to be able to
	   add two more characters to create the index name */
	if( !keysetInfo->keysetDBMS.maxTableNameLen || \
		keysetInfo->keysetDBMS.maxTableNameLen > CRYPT_MAX_TEXTSIZE )
		keysetInfo->keysetDBMS.maxTableNameLen = CRYPT_MAX_TEXTSIZE;
	if( !keysetInfo->keysetDBMS.maxColumnNameLen || \
		keysetInfo->keysetDBMS.maxColumnNameLen > CRYPT_MAX_TEXTSIZE )
		keysetInfo->keysetDBMS.maxColumnNameLen = CRYPT_MAX_TEXTSIZE;
	keysetInfo->keysetDBMS.nameTable[ keysetInfo->keysetDBMS.maxTableNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameCRLTable[ keysetInfo->keysetDBMS.maxTableNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameC[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameSP[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameL[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameO[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameOU[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameCN[ keysetInfo->keysetDBMS.maxColumnNameLen - 2 ] = '\0';
	keysetInfo->keysetDBMS.nameEmail[ keysetInfo->keysetDBMS.maxColumnNameLen - 2 ] = '\0';
	keysetInfo->keysetDBMS.nameDate[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';
	keysetInfo->keysetDBMS.nameNameID[ keysetInfo->keysetDBMS.maxColumnNameLen - 2 ] = '\0';
	keysetInfo->keysetDBMS.nameIssuerID[ keysetInfo->keysetDBMS.maxColumnNameLen - 2 ] = '\0';
	keysetInfo->keysetDBMS.nameKeyID[ keysetInfo->keysetDBMS.maxColumnNameLen - 2 ] = '\0';
	keysetInfo->keysetDBMS.nameKeyData[ keysetInfo->keysetDBMS.maxColumnNameLen ] = '\0';

	return( CRYPT_OK );
	}

/***************************************************************************/
/********************************* End *************************************/
/***************************************************************************/

#ifdef TEST

#include <string.h>

/* Dummy routine for when we're not linked with cryptlib */

void shaHashBuffer( void ) {}
void ripemd160HashBuffer( void ) {}
void md5HashBuffer( void ) {}
void md2HashBuffer( void ) {}
int getOptionNumeric( const int dummy ) { return 0; }

char *getOptionString( const CRYPT_OPTION_TYPE option )
	{
	switch( option )
		{
		case CRYPT_OPTION_KEYS_DBMS_NAMETABLE:
			return( "PublicKeys" );
		case CRYPT_OPTION_KEYS_DBMS_NAMECRLTABLE:
			return( "CRLs" );
		case CRYPT_OPTION_KEYS_DBMS_NAME_C:
			return( "PK_C" );
		case CRYPT_OPTION_KEYS_DBMS_NAME_SP:
			return( "PK_SP" );
		case CRYPT_OPTION_KEYS_DBMS_NAME_L:
			return( "PK_L" );
		case CRYPT_OPTION_KEYS_DBMS_NAME_O:
			return( "PK_O" );
		case CRYPT_OPTION_KEYS_DBMS_NAME_OU:
			return( "PK_OU" );
		case CRYPT_OPTION_KEYS_DBMS_NAME_CN:
			return( "Name" );
		case CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL:
			return( "Email" );
		case CRYPT_OPTION_KEYS_DBMS_NAMEDATE:
			return( "PK_Date" );
		case CRYPT_OPTION_KEYS_DBMS_NAMENAMEID:
			return( "PK_NameID" );
		case CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID:
			return( "PK_IssuerID" );
		case CRYPT_OPTION_KEYS_DBMS_NAMEKEYID:
			return( "PK_KeyID" );
		case CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA:
			return( "PK_KeyData" );
		}

	return( "Bang" );
	}

/* Map an error code to an error string */

char *mapError( const int error )
	{
	return( ( error == CRYPT_DATA_OPEN ) ? "Cannot open data object" :
			( error == CRYPT_DATA_READ ) ? "Cannot read from data object" :
			( error == CRYPT_DATA_WRITE ) ? "Cannot write to data object" :
			( error == CRYPT_DATA_NOTFOUND ) ? "Item not found in data object" :
			( error == CRYPT_DATA_DUPLICATE ) ? "Item already present in data object" :
			( error == CRYPT_OK ) ? "OK" : "Non-data error" );
	}

/* Database connection information */

#if defined( DBX_ORACLE )
 #define DB_SERVER		( char * ) CRYPT_UNUSED
 #define DB_NAME		( char * ) CRYPT_UNUSED
 #define DB_USER		"system"
 #define DB_PASSWORD	"admin"
#elif defined DBX_MSQL
 #define DB_SERVER		( char * ) CRYPT_UNUSED
 #define DB_NAME		"test"
 #define DB_USER		( char * ) CRYPT_UNUSED
 #define DB_PASSWORD	( char * ) CRYPT_UNUSED
#elif defined DBX_POSTGRES
 #define DB_SERVER		"localhost"
 #define DB_NAME		"test"
 #define DB_USER		( char * ) CRYPT_UNUSED
 #define DB_PASSWORD	( char * ) CRYPT_UNUSED
#elif defined( __WIN32__ )
 #define DB_SERVER		( char * ) CRYPT_UNUSED
/* #define DB_NAME		"dbase_keys" /**/
/* #define DB_NAME		"keys" /**/
 #define DB_NAME		"sql_keys" /**/
 #define DB_USER		""
 #define DB_PASSWORD	""
#else
 #define DB_SERVER		( char * ) CRYPT_UNUSED
/* #define DB_NAME		"keys" /**/
 #define DB_NAME		"foxkeys"
 #define DB_USER		""
 #define DB_PASSWORD	""
#endif /* Database access info */

/* The main program */

int dbxInitODBC( void );
int dbxEndODBC( void );

void main( void )
	{
	KEYSET_INFO keysetInfo, *keysetInfoPtr;
	BYTE keyBuffer[ 256 ];
	int status, i;

	/* Set up things as cryptOpenKeyset() would have */
	memset( &keysetInfo, 0, sizeof( KEYSET_INFO ) );
	keysetInfoPtr = &keysetInfo;
#ifdef __WINDOWS__
	setAccessMethodODBC( keysetInfoPtr );
//	setAccessMethodMSQL( keysetInfoPtr );
#endif /* __WINDOWS__ */
#ifdef __UNIX__
  #ifdef DBX_ORACLE
	setAccessMethodOracle( keysetInfoPtr );
  #endif /* DBX_ORACLE */
  #ifdef DBX_POSTGRES
	setAccessMethodPostgres( keysetInfoPtr );
  #endif /* DBX_POSTGRES */
#endif /* __UNIX__ */
#if ( defined( __WINDOWS__ ) || defined( __UNIX__ ) ) && defined( DBX_LDAP )
	setAccessMethodLDAP( keysetInfoPtr );
#endif /* ( __WINDOWS__ || __UNIX__ ) && DBX_LDAP */

#if defined( __WINDOWS__ ) && defined( USE_ODBC )
	/* Load the ODBC libraries */
	status = dbxInitODBC();
	if( cryptStatusError( status ) )
		{
		puts( "Bang" );
		return;
		}
#endif /* __WINDOWS__ && USE_ODBC */

	/* Try and establish a connection to the database */
	status = dbmsOpenDatabase( keysetInfoPtr, DB_NAME, DB_SERVER, DB_USER,
							   DB_PASSWORD );
	DEBUG( printf( "dbmsOpenDatabase status = %s\n", mapError( status ) ) );
	if( cryptStatusError( status ) )
		{
		puts( "Bang" );
#if defined( __WINDOWS__ ) && defined( USE_ODBC )
		dbxEndODBC();
#endif /* __WINDOWS__ && USE_ODBC */
		return;
		}

#if 0
	/* Test database create */
	status = dbmsCreateDatabase( keysetInfoPtr );
	DEBUG( printf( "dbmsCreateDatabase status = %s\n", mapError( status ) ) );
#endif

#if 0
	/* Test key add */
	strcpy( keysetInfoPtr->C, "US" );
	strcpy( keysetInfoPtr->SP, "Florida" );
	strcpy( keysetInfoPtr->L, "Dumpwater" );
	strcpy( keysetInfoPtr->O, "" );
	strcpy( keysetInfoPtr->OU, "" );
	strcpy( keysetInfoPtr->CN, "J.Random Luser" );
	strcpy( keysetInfoPtr->email, "jrandom@blem.com" );
	time( &keysetInfoPtr->date );
	status = dbmsAddKey( keysetInfoPtr, "01234567890123456789012345678901234",
						 "12345678901234567890123456789012345",
						 "23456789012345678901234567890123456",
						 "qwertyuiopasdfghjklzxcvbnm123456789", 36 );
	DEBUG( printf( "dbmsAddKey #1 status = %s\n", mapError( status ) ) );
	strcpy( keysetInfoPtr->C, "US" );
	strcpy( keysetInfoPtr->SP, "New Mexico" );
	strcpy( keysetInfoPtr->L, "Burnt Scrotum" );
	strcpy( keysetInfoPtr->O, "" );
	strcpy( keysetInfoPtr->OU, "" );
	strcpy( keysetInfoPtr->CN, "Noki S.Crow" );
	strcpy( keysetInfoPtr->email, "noki@blort.com" );
	keysetInfoPtr->date -= 86400;
	status = dbmsAddKey( keysetInfoPtr, "34567890123456789012345678901234567",
						 "45678901234567890123456789012345678",
						 "56789012345678901234567890123456789",
						 "abcdefghijklmnopqrstuvwxyz987654321", 36 );
	DEBUG( printf( "dbmsAddKey #2 status = %s\n", mapError( status ) ) );
	strcpy( keysetInfoPtr->C, "US" );
	strcpy( keysetInfoPtr->SP, "Illinois" );
	strcpy( keysetInfoPtr->L, "Goose Fart" );
	strcpy( keysetInfoPtr->O, "" );
	strcpy( keysetInfoPtr->OU, "" );
	strcpy( keysetInfoPtr->CN, "Big Al" );
	strcpy( keysetInfoPtr->email, "bigal@gruswald.org" );
	time( &keysetInfoPtr->date );
	status = dbmsAddKey( keysetInfoPtr, "23456789012345678901234567890123456",
						 "34567890123456789012345678901234567",
						 "45678901234567890123456789012345678",
						 "qwertyuiopasdfghjklzxcvbnm987654321", 36 );
	DEBUG( printf( "dbmsAddKey #1 status = %s\n", mapError( status ) ) );
	strcpy( keysetInfoPtr->C, "NZ" );
	strcpy( keysetInfoPtr->SP, "" );
	strcpy( keysetInfoPtr->L, "Auckland" );
	strcpy( keysetInfoPtr->O, "Orion Systems" );
	strcpy( keysetInfoPtr->OU, "" );
	strcpy( keysetInfoPtr->CN, "Paul Petard" );
	strcpy( keysetInfoPtr->email, "paul@orion.co.nz" );
	keysetInfoPtr->date -= 86400;
	status = dbmsAddKey( keysetInfoPtr, "67890123456789012345678901234567890",
						 "78901234567890123456789012345678901",
						 "89012345678901234567890123456789012",
						 "qazwsxedcrfvtgbyhnujmikolp741852963", 36 );
	DEBUG( printf( "dbmsAddKey #3 status = %s\n", mapError( status ) ) );
	strcpy( keysetInfoPtr->C, "NZ" );
	strcpy( keysetInfoPtr->SP, "" );
	strcpy( keysetInfoPtr->L, "Auckland" );
	strcpy( keysetInfoPtr->O, "Orion Systems" );
	strcpy( keysetInfoPtr->OU, "" );
	strcpy( keysetInfoPtr->CN, "Paul Petard" );
	strcpy( keysetInfoPtr->email, "paul@orion.co.nz" );
	keysetInfoPtr->date -= 86400;
	status = dbmsAddKey( keysetInfoPtr, "01234567890123456789012345678901234",
						 "12345678901234567890123456789012345",
						 "23456789012345678901234567890123456",
						 "qazwsxedcrfvtgbyhnujmikolp741852963", 36 );
	DEBUG( printf( "dbmsAddKey duplicate key status = %s\n",
					mapError( status ) ) );
	strcpy( keysetInfoPtr->C, "US" );
	strcpy( keysetInfoPtr->SP, "California" );
	strcpy( keysetInfoPtr->L, "" );
	strcpy( keysetInfoPtr->O, "" );
	strcpy( keysetInfoPtr->OU, "" );
	strcpy( keysetInfoPtr->CN, "J.Gruswald Finklebottom" );
	strcpy( keysetInfoPtr->email, "gruswald@wibble.org" );
	keysetInfoPtr->date -= 86400;
	status = dbmsAddKey( keysetInfoPtr, "01234567890123456789012345678901234",
						 "12345678901234567890123456789012345",
						 "23456789012345678901234567890123456",
						 "qazwsxedcrfvtgbyhnujmikolp741852963", 36 );
	DEBUG( printf( "dbmsAddKey duplicate keyID/nameID status = %s\n",
					mapError( status ) ) );
#endif

#if 0
	/* Test key get */
	status = dbmsGetKey( keysetInfoPtr, CRYPT_KEYID_NAME, "J.Random Luser",
						 keyBuffer );
	DEBUG( printf( "dbmsGetKey status = %s, key = %s\n", mapError( status ),
					keyBuffer ) );
	status = dbmsGetKey( keysetInfoPtr, CRYPT_KEYID_NAME,
						 "Mr.Not Appearing in this Database", keyBuffer );
	DEBUG( printf( "dbmsGetKey status for non-present key = %s\n",
					mapError( status ) ) );

	/* Test key delete */
	status = dbmsDeleteKey( keysetInfoPtr, CRYPT_KEYID_NAME, "Paul Petard" );
	DEBUG( printf( "dbmsDeleteKey status = %s\n", mapError( status ) ) );
	status = dbmsDeleteKey( keysetInfoPtr, CRYPT_KEYID_NAME,
							"Mr.Not Appearing in this Database" );
	DEBUG( printf( "dbmsDeleteKey status for non-present key = %s\n",
					mapError( status ) ) );
#endif

#if 1
	/* Test general key query */
	status = dbmsQuery( keysetInfoPtr, "PK_C = 'US'", NULL );
	DEBUG( printf( "dbmsQuery status = %s\n", mapError( status ) ) );
	while( cryptStatusOK( status ) )
		{
		status = dbmsQuery( keysetInfoPtr, NULL, keyBuffer );
		DEBUG( printf( "dbmsGetKey status = %s, key = %s\n",
						mapError( status ), keyBuffer ) );
		}
#endif

#if 1
	/* Test bulk key add */
	keysetInfoPtr->bulkUpdateState = BULKUPDATE_START;
	status = dbmsAddKey( keysetInfoPtr, NULL, NULL, NULL, NULL, 0 );
	DEBUG( printf( "dbmsBulkAddKey start status = %s\n", mapError( status ) ) );
	for( i = 0; i < 20; i++ )
		{
		strcpy( keysetInfoPtr->C, "DE" );
		strcpy( keysetInfoPtr->SP, "Munich" );
		strcpy( keysetInfoPtr->L, "Unterfoehring" );
		strcpy( keysetInfoPtr->O, "" );
		strcpy( keysetInfoPtr->OU, "" );
		sprintf( keysetInfoPtr->CN, "Bulk Luser #%d", i );
		sprintf( keysetInfoPtr->email, "luser%d@blem.de", i );
		keysetInfoPtr->date -= 86400;
		status = dbmsAddKey( keysetInfoPtr, "01234567890123456789012345678901234",
						 "12345678901234567890123456789012345",
						 "23456789012345678901234567890123456",
							 "qwertyuiopasdfghjklzxcvbnm123456789", 36 );
		DEBUG( printf( "dbmsBulkAddKey #%d status = %s\n", i,
						mapError( status ) ) );
		}
	keysetInfoPtr->bulkUpdateState = BULKUPDATE_FINISH;
	status = dbmsAddKey( keysetInfoPtr, NULL, NULL, NULL, NULL, 0 );
	DEBUG( printf( "dbmsBulkAddKey end status = %s\n", mapError( status ) ) );
#endif

	/* Close the database connection if necessary */
	if( keysetInfoPtr->databaseOpen )
		keysetInfoPtr->closeDatabase( keysetInfoPtr );

#if defined( __WINDOWS__ ) && defined( USE_ODBC )
	/* Unload the ODBC libraries */
	dbxEndODBC();
#endif /* __WINDOWS__ && USE_ODBC */
	}
#endif /* TEST */
