/****************************************************************************
*																			*
*							cryptlib DBMS Interface							*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "asn1.h"
  #include "crypt.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
  #include "misc/keyset.h"
#endif /* Compiler-specific includes */

/* Prototypes for low-level DBMS interface functions */

int setAccessMethodODBC( KEYSET_INFO *keysetInfo );
int setAccessMethodMSQL( KEYSET_INFO *keysetInfo );
int setAccessMethodMySQL( KEYSET_INFO *keysetInfo );
int setAccessMethodOracle( KEYSET_INFO *keysetInfo );
int setAccessMethodPostgres( KEYSET_INFO *keysetInfo );

/* Some database types aren't supported on some platforms, so we replace a
   call to the mapping function with an error code */

#ifndef DBX_ODBC
  #define setAccessMethodODBC( x )		CRYPT_ARGERROR_NUM1
#endif /* !DBX_ODBC */
#ifndef DBX_MSQL
  #define setAccessMethodMSQL( x )		CRYPT_ARGERROR_NUM1
#endif /* !DBX_MSQL */
#ifndef DBX_MYSQL
  #define setAccessMethodMySQL( x )		CRYPT_ARGERROR_NUM1
#endif /* !DBX_MYSQL */
#ifndef DBX_ORACLE
  #define setAccessMethodOracle( x )	CRYPT_ARGERROR_NUM1
#endif /* !DBX_ORACLE */
#ifndef DBX_POSTGRES
  #define setAccessMethodPostgres( x )	CRYPT_ARGERROR_NUM1
#endif /* !DBX_POSTGRES */

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

#ifdef __WINDOWS__
				/* Bypass a Microsoft ODBC "enhancement" in which the driver
				   will execute anything delimited by '|'s as an expression
				   (an example being '|shell("cmd /c echo " & chr(124) & 
				   " format c:")|').  Because of this we strip gazinta's if
				   we're running under Windoze */
				if( ch != '|' )
#endif /* __WINDOWS__ */
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
	}

/* Format input parameters into SQL queries, replacing meta-values with
   actual column names */

static int formatQuery( char *output, const char *input, const int inputLength,
						const KEYSET_INFO *keysetInfo )
	{
	int inPos = 0, outPos = 0, status = CRYPT_OK;

	while( inPos < inputLength )
		{
		if( input[ inPos ] == '$' )
			{
			const char *fieldName = &input[ inPos + 1 ];
			const char *outputFieldName;
			const int fieldPos = inPos + 1;
			int length;

			inPos++;	/* Skip '$' */

			/* Extract the field name and translate it into the table
			   column name */
			while( isalpha( input[ inPos ] ) )
				inPos++;
			length = inPos - fieldPos;
			if( length <= 0 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			if( !strnicmp( fieldName, "C", length ) )
				outputFieldName = "C";
			else
			if( !strnicmp( fieldName, "SP", length ) )
				outputFieldName = "SP";
			else
			if( !strnicmp( fieldName, "L", length ) )
				outputFieldName = "L";
			else
			if( !strnicmp( fieldName, "O", length ) )
				outputFieldName = "O";
			else
			if( !strnicmp( fieldName, "OU", length ) )
				outputFieldName = "OU";
			else
			if( !strnicmp( fieldName, "CN", length ) )
				outputFieldName = "CN";
			else
			if( !strnicmp( fieldName, "email", length ) )
				outputFieldName = "email";
			else
			if( !strnicmp( fieldName, "date", length ) )
				outputFieldName = "validTo";
			else
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			length = strlen( outputFieldName );

			/* Copy the translated name to the output buffer */
			if( outPos + length >= MAX_SQL_QUERY_SIZE )
				{
				status = CRYPT_ERROR_OVERFLOW;
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
			output[ outPos++ ] = input[ inPos++ ];
			}
		}
	if( cryptStatusError( status ) )
		outPos = 0;
	output[ outPos++ ] = '\0';	/* Add der terminador */

	return( status );
	}

/* Set up key ID information for a query */

static void setKeyID( BYTE *keyIDbuffer, const CRYPT_KEYID_TYPE keyIDtype, 
					  const void *keyID, const int keyIDlength )
	{
	const int idLength = min( keyIDlength, ( CRYPT_MAX_TEXTSIZE * 2 ) - 1 );

	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_EMAIL || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID || \
			keyIDtype == CRYPT_KEYID_NONE );

	if( keyIDtype == CRYPT_IKEYID_KEYID || \
		keyIDtype == CRYPT_IKEYID_ISSUERID || \
		keyIDtype == CRYPT_KEYID_NONE )
		{
		assert( keyIDlength == KEYID_SIZE );

		/* base64-encode the key ID so we can use it with database queries,
		   and set up the query fields for a query by key ID */
		base64encode( keyIDbuffer, keyID, DBXKEYID_SIZE, CRYPT_CERTTYPE_NONE );
		keyIDbuffer[ MAX_ENCODED_DBXKEYID_SIZE ] = '\0';
		return;
		}

	/* Zero-terminate the keyID so we can use it with database queries, and 
	   set up the query fields for a query by name or email address */
	memcpy( keyIDbuffer, keyID, idLength );
	keyIDbuffer[ idLength ] = '\0';
	}

static int generateKeyID( BYTE *keyIDbuffer, const CRYPT_HANDLE cryptHandle, 
						  const CRYPT_ATTRIBUTE_TYPE keyIDtype )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ 1024 ], *bufPtr = buffer;
	int status;

	/* Get the attribute from the cert, hash it to get an ID, and use that 
	   for the keyID */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, keyIDtype );
	if( cryptStatusError( status ) )
		return( status );
	if( msgData.length > MAX_ENCODED_CERT_SIZE && \
		( bufPtr = malloc( msgData.length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	msgData.data = bufPtr;
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, keyIDtype );
	if( cryptStatusOK( status ) )
		{
		HASHFUNCTION hashFunction;
		BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ];
		int hashSize;

		/* Get the hash algorithm information and hash the attribute to get
		   the ID */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
		hashFunction( NULL, hashBuffer, bufPtr, msgData.length, HASH_ALL );
		setKeyID( keyIDbuffer, CRYPT_KEYID_NONE, hashBuffer, KEYID_SIZE );
		}
	if( bufPtr != buffer )
		free( bufPtr );
	return( status );
	}

static char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype )
	{
	switch( keyIDtype )
		{
		case CRYPT_KEYID_NAME:
			return( "CN" );

		case CRYPT_KEYID_EMAIL:
			return( "email" );

		case CRYPT_IKEYID_KEYID:
			return( "keyID" );

		case CRYPT_IKEYID_ISSUERID:
			return( "issuerID" );
		}

	assert( NOTREACHED );
	return( NULL );			/* Get rid of compiler warning */
	}

/* Create a new key database */

static int createDatabase( KEYSET_INFO *keysetInfo )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	int status;

	/* Create tables for public keys, CRL's, revoked certs, and cert requests.  
	   We use CHAR rather than VARCHAR for the ID fields since these always 
	   have a fixed length and CHAR is faster than VARCHAR.  In addition we 
	   make as many columns as possible NOT NULL since these fields should 
	   always be present, and because this is faster for most databases.

	   If the one of the tables is deleted outside of cryptlib and others
	   left in place then creation will fail because one or more tables
	   already exist.  This is an anomalous situation (the users shouldn't
	   modify the tables outside cryptlib), but in the interests of luser-
	   friendliness we ignore a CRYPT_ERROR_DUPLICATE for the other tables if
	   the basic cert table creation succeeded */
	formatSQL( FALSE, sqlBuffer, 
					"CREATE TABLE certificates ( "
						"C CHAR(2), "
						"SP VARCHAR(64), "
						"L VARCHAR(64), "
						"O VARCHAR(64), "
						"OU VARCHAR(64), "
						"CN VARCHAR(64), "
						"email VARCHAR(64), "
						"validTo DATETIME NOT NULL, "
						"nameID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
						"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
						"keyID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
						"oobCertID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL, "
						"keyData $ NOT NULL )",
			   keysetInfo->keysetDBMS.blobName );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer, 
												   FALSE );
	if( cryptStatusError( status ) )
		return( status );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"CREATE TABLE CRLs ("
						"nameID CHAR(" TEXT_DBXKEYID_SIZE ") PRIMARY KEY NOT NULL, "
						"issuerID CHAR(" TEXT_DBXKEYID_SIZE ") NOT NULL,"
						"revDate DATETIME NOT NULL, "
						"revReason SMALLINT NOT NULL )", FALSE );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_DUPLICATE )
		{
		/* Undo the certificate table creation */
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"DROP TABLE certificates", FALSE );
		return( status );
		}
	formatSQL( FALSE, sqlBuffer, 
					"CREATE TABLE certRequests ("
						"C CHAR(2), "
						"SP VARCHAR(64), "
						"L VARCHAR(64), "
						"O VARCHAR(64), "
						"OU VARCHAR(64), "
						"CN VARCHAR(64), "
						"email VARCHAR(64), "
						"keyData $ NOT NULL )",
			   keysetInfo->keysetDBMS.blobName );
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer, 
												   FALSE );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_DUPLICATE )
		{
		/* Undo the certificate and CRL table creation */
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"DROP TABLE certificates", FALSE );
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"DROP TABLE CRLs", FALSE );
		return( status );
		}


	/* Create an index for the email addresses in the certificate table */
	status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"CREATE INDEX emailIdx ON certificates(email)", 
					FALSE );

	/* Create an index for the nameID, issuerID, keyID, and oobCertID in 
	   the certificates table and the issuerID in the CRLs table (the CRL
	   nameID isn't indexed since we only use it for linear scans, however 
	   it's designated the primary key to ensure rows are clustered around 
	   it).  Since most of the fields are supposed to be unique, we can 
	   specify this for the index we're creating, however we can't do it for 
	   the nameID since there could be multiple certs present which differ 
	   only in key usage.  We don't index the revoked cert or cert request 
	   table since indexes consume space and we don't expect to access 
	   either of these much */
	if( cryptStatusOK( status ) )
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"CREATE INDEX nameIDIdx ON certificates(nameID)",
					FALSE );
	if( cryptStatusOK( status ) )
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"CREATE UNIQUE INDEX issuerIDIdx ON certificates(issuerID)",
					FALSE );
	if( cryptStatusOK( status ) )
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"CREATE UNIQUE INDEX keyIDIdx ON certificates(keyID)",
					FALSE );
	if( cryptStatusOK( status ) )
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"CREATE UNIQUE INDEX oobCertIDIdx ON certificates(oobCertID)",
					FALSE );
	if( cryptStatusOK( status ) )
		status = keysetInfo->keysetDBMS.performUpdate( keysetInfo,
					"CREATE UNIQUE INDEX issuerIDIdx ON CRLs (issuerID)",
					FALSE );
	if( cryptStatusError( status ) )
		{
		/* Undo the creation of the various tables */
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"DROP TABLE certificates", FALSE );
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"DROP TABLE CRLs", FALSE );
		keysetInfo->keysetDBMS.performUpdate( keysetInfo, 
					"DROP TABLE certRequests", FALSE );
		return( CRYPT_ERROR_WRITE );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Database Access Functions						*
*																			*
****************************************************************************/

/* Check an encoded cert for a matching key usage.  The semantics of key 
   usage flags are vague in the sense that the query "Is this key valid for
   X" is easily resolved, but the query "Which key is appropriate for X" is
   NP-hard due to the potential existence of unbounded numbers of 
   certificates with usage semantics expressed in an arbitrary number of 
   ways.  For now we distinguish between signing and encryption keys (this,
   at least, is feasible) by doing a quick check for keyUsage if we get
   multiple certs with the same DN and choosing the one with the appropriate
   key usage.

   Rather than performing a relatively expensive cert import for each cert,
   we find the keyUsage by doing an optimised search through the cert data
   for its encoded form.  The pattern we look for is:

	OID				06 03 55 1D 0F
	BOOLEAN			(optional)
	OCTET STRING {	04 (4 or 5)
		BIT STRING	03 (2 or 3) nn (value) */

static BOOLEAN checkCertUsage( const BYTE *certificate, const int length )
	{
	int i;

	/* Scan the payload portion of the cert for the keyUsage extension */
	for( i = 64; i < length - 64; i++ )
		{
		/* Look for the OID.  This potentially skips two bytes at a 
		   time, but this is safe since the preceding bytes can never
		   contain either of these two values (they're 0x30 + 11...15) */
		if( certificate[ i++ ] != BER_OBJECT_IDENTIFIER || \
			certificate[ i++ ] != 3 )
			continue;
		if( memcmp( certificate + i, "\x55\x1D\x0F", 3 ) )
			continue;
		i += 3;

		/* We've found the OID (with 1.1e-12 error probability), skip
		   the critical flag if necessary */
		if( certificate[ i ] == BER_BOOLEAN )
			i += 3;

		/* Check for the OCTET STRING wrapper and BIT STRING */
		if( certificate[ i++ ] != BER_OCTETSTRING || \
			( certificate[ i ] != 4 && certificate[ i ] != 5 ) || \
			certificate[ ++i ] != BER_BITSTRING )
			continue;
		i += 4;		/* Skip OCTET STRING and BIT STRING header + bit count */

		/* We've got to the BIT STRING payload, check whether the requested
		   usage is allowed */
		}

	/* No key usage found, assume any usage is OK */
	return( TRUE );
	}

/* Fetch a sequence of certs from a data source.  This is called indirectly
   by the certificate code to fetch the next cert in a chain, if the key ID
   is nonzero we fetch the first cert and set the state info, if the key ID
   is zero we fetch the next cert based on the previously stored state info */

static int getNextCertFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo,
								const CRYPT_KEYID_TYPE keyIDtype,
								const void *keyID, const int keyIDlength,
								const CERTIMPORT_TYPE options )
	{
	CREATEOBJECT_INFO createInfo;
	BYTE certificate[ MAX_CERT_SIZE ];
	char keyBuffer[ MAX_ENCODED_CERT_SIZE ], *keyPtr = keyBuffer;
	char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	const char *keyName;
	int keyLength, keyLengthMax = MAX_ENCODED_CERT_SIZE, status;

	/* If we're continuing from a previous fetch, set the key ID to the nameID
	   of the previous certs issuer */
	if( keyIDtype == CRYPT_KEYID_NONE )
		{
		status = generateKeyID( keyIDbuffer, *stateInfo, 
								CRYPT_IATTRIBUTE_ISSUER );
		if( cryptStatusError( status ) )
			return( status );
		keyName = "nameID";
		}
	else
		{
		/* Set up the fields for a query to access the record */
		setKeyID( keyIDbuffer, keyIDtype, keyID, keyIDlength );
		keyName = getKeyName( keyIDtype );
		}

	/* If we have binary blob support, fetch the data directly into the
	   certificate buffer.  We have to change the maximum length indicator
	   as well as the buffer because some sources will helpfully zero-pad
	   the data to the maximum indicated size, which is smaller for the
	   non-ASCII-encoded buffer */
	if( keysetInfo->keysetDBMS.hasBinaryBlobs )
		{
		keyPtr = certificate;
		keyLengthMax = MAX_CERT_SIZE;
		}

	/* Retrieve the record */
	formatSQL( TRUE, sqlBuffer, 
					"SELECT keyData FROM certificates WHERE $ = '$'",
			   keyName, keyIDbuffer );
	status = keysetInfo->keysetDBMS.performQuery( keysetInfo, sqlBuffer,
					keyPtr, &keyLength, keyLengthMax, DBMS_QUERY_NORMAL );
	if( cryptStatusError( status ) )
		return( status );

	/* base64-decode the binary key data if necessary */
	if( !keysetInfo->keysetDBMS.hasBinaryBlobs )
		{
		keyLength = base64decode( certificate, keyBuffer, keyLength, 
								  CRYPT_CERTFORMAT_NONE );
		if( !keyLength )
			return( CRYPT_ERROR_BADDATA );
		}

	/* If more than one cert is present, try and match the requested key 
	   usage with the one indicated in the cert */
	checkCertUsage( certificate, keyLength );

	/* Create a certificate object from the encoded cert */
	setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
	createInfo.createIndirect = TRUE;
	createInfo.strArg1 = certificate;
	createInfo.strArgLen1 = keyLength;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	*iCertificate = createInfo.cryptHandle;

	/* Remember where we got to so we can fetch the next cert in the chain */
	*stateInfo = *iCertificate;
	return( CRYPT_OK );
	}

/* Retrieve a key record from the database */

static int getItemFunction( KEYSET_INFO *keysetInfo, 
							CRYPT_HANDLE *iCryptHandle, 
							const CRYPT_KEYID_TYPE keyIDtype, 
							const void *keyID,  const int keyIDlength, 
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	int status;

	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* If we're in the middle of a query, fetch the next result */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		{
		CREATEOBJECT_INFO createInfo;
		BYTE certificate[ MAX_CERT_SIZE ];
		char keyBuffer[ MAX_ENCODED_CERT_SIZE ], *keyPtr = keyBuffer;
		int keyLength, keyLengthMax = MAX_ENCODED_CERT_SIZE;

		/* Make sure the parameters are correct for a query */
		if( keyIDtype != CRYPT_KEYID_NONE || keyID != NULL )
			return( CRYPT_ERROR_INCOMPLETE );

		/* Fetch the next record.  This is just a cut-down version of the code
		   below */
		if( keysetInfo->keysetDBMS.hasBinaryBlobs )
			{
			keyPtr = certificate;
			keyLengthMax = MAX_CERT_SIZE;
			}
		status = keysetInfo->keysetDBMS.performQuery( keysetInfo, NULL,
					keyPtr, &keyLength, keyLengthMax, DBMS_QUERY_CONTINUE );
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_COMPLETE )
				{
				/* There are no more results available, wrap up the 
				   processing */
				keysetInfo->keysetDBMS.performQuery( keysetInfo, NULL, 
										NULL, NULL, 0, DBMS_QUERY_CANCEL );
				keysetInfo->keysetDBMS.queryState = QUERY_NONE;
				}
			return( status );
			}
		if( !keysetInfo->keysetDBMS.hasBinaryBlobs )
			{
			keyLength = base64decode( certificate, keyBuffer, keyLength, 
									  CRYPT_CERTFORMAT_NONE );
			if( !keyLength )
				return( CRYPT_ERROR_BADDATA );
			}

		/* Create a certificate object from the encoded cert */
		setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
		createInfo.createIndirect = TRUE;
		createInfo.strArg1 = certificate;
		createInfo.strArgLen1 = keyLength;
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			*iCryptHandle = createInfo.cryptHandle;
		return( status );
		}

	/* If we're doing a check only, just check whether the item is present.
	   Since this is only used for CRL checks, we query the CRL table rather
	   than the main one */
	if( keyIDtype == CRYPT_IKEYID_ISSUERID && \
		( flags & KEYMGMT_FLAG_CHECK_ONLY ) )
		{
		char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
		char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

		assert( keyIDlength == KEYID_SIZE );

		/* Check whether this item is present in the CRL table.  We don't 
		   care about the result, all we want to know is whether it's there
		   or not, so we use a null result buffer to tell the DBMS glue code
		   not to bother fetching the results */
		setKeyID( keyIDbuffer, CRYPT_KEYID_NONE, keyID, KEYID_SIZE );
		formatSQL( TRUE, sqlBuffer, 
					"SELECT revReason FROM CRLs WHERE issuerID = '$'",
				   keyIDbuffer );
		return( keysetInfo->keysetDBMS.performQuery( keysetInfo, sqlBuffer,
										NULL, NULL, 0, DBMS_QUERY_CHECK ) );
		}

	/* Import the cert by doing an indirect read, which fetches either a 
	   single cert or an entire chain if it's present */
	status = iCryptImportCertIndirect( iCryptHandle, keysetInfo->objectHandle, 
									   keyIDtype, keyID, keyIDlength, 
									   CERTIMPORT_NORMAL );
	return( status );
	}

/* Add a certificate object to a database.  Normally RDBMS's would allow 
   existing rows to be overwritten, but the UNIQUE constraint on the index
   will catch this */

static int addCert( KEYSET_INFO *keysetInfo, const CRYPT_HANDLE iCryptHandle )
	{
	RESOURCE_DATA msgData;
	BYTE keyData[ MAX_CERT_SIZE ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char nameID[ MAX_ENCODED_DBXKEYID_SIZE ];
	char issuerID[ MAX_ENCODED_DBXKEYID_SIZE ];
	char keyID[ MAX_ENCODED_DBXKEYID_SIZE ];
	char oobCertID[ MAX_ENCODED_DBXKEYID_SIZE ];
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ],
		email[ CRYPT_MAX_TEXTSIZE + 1 ];
	int keyDataLength, status;

	*C = *SP = *L = *O = *OU = *CN = *email = '\0';

	/* Extract the DN and altName components.  This changes the currently
	   selected DN components, but this is OK since we've got the cert
	   locked and the prior state will be restored when we unlock it */
	krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_SUBJECTNAME );
	setResourceData( &msgData, C, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_COUNTRYNAME );
	if( cryptStatusOK( status ) )
		C[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setResourceData( &msgData, SP, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_STATEORPROVINCENAME );
		}
	if( cryptStatusOK( status ) )
		SP[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setResourceData( &msgData, L, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_LOCALITYNAME );
		}
	if( cryptStatusOK( status ) )
		L[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setResourceData( &msgData, O, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_ORGANIZATIONNAME );
		}
	if( cryptStatusOK( status ) )
		O[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setResourceData( &msgData, OU, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
		}
	if( cryptStatusOK( status ) )
		OU[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setResourceData( &msgData, CN, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_COMMONNAME );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* Some certs don't have CN components, so we use the OU instead.
			   If that also fails, we use the O.  This gets a bit messy, but
			   duplicating the OU/O into the CN seems to be the best way to
			   handle this */
			strcpy( CN, *OU ? OU : O );
			msgData.length = strlen( CN );
			status = CRYPT_OK;
			}
		}
	if( cryptStatusOK( status ) )
		{
		CN[ msgData.length ] = '\0';

		setResourceData( &msgData, email, CRYPT_MAX_TEXTSIZE );
		krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_UNUSED, CRYPT_CERTINFO_SUBJECTALTNAME );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							CRYPT_CERTINFO_RFC822NAME );
		}
	if( cryptStatusOK( status ) )
		email[ msgData.length ] = '\0';
	if( cryptStatusOK( status ) || status == CRYPT_ERROR_NOTFOUND )
		{
		setResourceData( &msgData, &keysetInfo->keysetDBMS.date, 
						 sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
							&msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   which makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* Get the ID information and cert data for the cert */
	status = generateKeyID( nameID, iCryptHandle, 
							CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusOK( status ) )
		status = generateKeyID( issuerID, iCryptHandle, 
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		status = generateKeyID( keyID, iCryptHandle, 
								CRYPT_IATTRIBUTE_SPKI );
	if( cryptStatusOK( status ) )
		status = generateKeyID( oobCertID, iCryptHandle, 
								CRYPT_CERTINFO_FINGERPRINT_SHA );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, keyData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
		keyDataLength = msgData.length;
		}
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   which makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* Set up the various ID's and the cert.object data to write */
	if( !keysetInfo->keysetDBMS.hasBinaryBlobs )
		keysetInfo->keysetDBMS.boundKeyDataLen = \
					base64encode( keysetInfo->keysetDBMS.boundKeyData,
								  keyData, keyDataLength, 
								  CRYPT_CERTTYPE_NONE );
	else
		{
		memcpy( keysetInfo->keysetDBMS.boundKeyData, keyData, keyDataLength );
		keysetInfo->keysetDBMS.boundKeyDataLen = keyDataLength;
		}

	/* Insert the cert object information */
	if( keysetInfo->keysetDBMS.hasBinaryBlobs )
		formatSQL( TRUE, sqlBuffer, 
					"INSERT INTO certificates VALUES ( "
						"'$', '$', '$', '$', '$', '$', '$', ?, '$', '$', '$', '$', ? )",
				   C, SP, L, O, OU, CN, email, nameID, issuerID, keyID, oobCertID );
	else
		formatSQL( TRUE, sqlBuffer, 
					"INSERT INTO certificates VALUES ( "
						"'$', '$', '$', '$', '$', '$', '$', ?, '$', '$', '$', '$', '$' )",
				   C, SP, L, O, OU, CN, email, nameID, issuerID, keyID, oobCertID, 
				   keysetInfo->keysetDBMS.boundKeyData );
	return( keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer, TRUE ) );
	}

static int addCRL( KEYSET_INFO *keysetInfo, const CRYPT_HANDLE iCryptHandle )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ], reasonBuffer[ 8 ];
	char nameID[ MAX_ENCODED_DBXKEYID_SIZE ];
	char issuerID[ MAX_ENCODED_DBXKEYID_SIZE ];
	int status;

	/* Get the ID information for the current CRL entry */
	status = generateKeyID( nameID, iCryptHandle, CRYPT_IATTRIBUTE_ISSUER );
	if( cryptStatusOK( status ) )
		status = generateKeyID( issuerID, iCryptHandle, 
								CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, &keysetInfo->keysetDBMS.date, 
						 sizeof( time_t ) );
		status = krnlSendMessage( iCryptHandle, 
						RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
						&msgData, CRYPT_CERTINFO_REVOCATIONDATE );
		}
	if( cryptStatusOK( status ) )
		{
		int revocationReason;

		status = krnlSendMessage( iCryptHandle, 
						RESOURCE_IMESSAGE_GETATTRIBUTE, 
						&revocationReason, CRYPT_CERTINFO_CRLREASON );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			revocationReason = CRYPT_CRLREASON_UNSPECIFIED;
			status = CRYPT_OK;
			}
		sprintf( reasonBuffer, "%4d", revocationReason );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Insert the entry */
	formatSQL( TRUE, sqlBuffer, 
					"INSERT INTO CRLs VALUES ( '$', '$', ?, '$' )",
			   nameID, issuerID, reasonBuffer );
	return( keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer, TRUE ) );
	}

static int setItemFunction( KEYSET_INFO *keysetInfo, 
							const CRYPT_HANDLE iCryptHandle,
							const char *password, const int passwordLength )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int type, status;

	assert( password == NULL ); assert( passwordLength == 0 );

	/* If we're in the middle of a query, we can't do anything else */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_ERROR_INCOMPLETE );

	/* Make sure we've been given a cert, cert chain, or CRL */
	status = krnlSendMessage( iCryptHandle, RESOURCE_MESSAGE_GETATTRIBUTE,
							  &type, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( type != CRYPT_CERTTYPE_CERTIFICATE && \
		type != CRYPT_CERTTYPE_CERTCHAIN && \
		type != CRYPT_CERTTYPE_CRL )
		return( CRYPT_ARGERROR_NUM1 );

	/* Lock the cert or CRL for our exclusive use and select the first 
	   sub-item (cert in a cert chain, entry in a CRL), update the keyset 
	   with the cert(s)/CRL entries, and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );
	do
		{
		/* Add the certificate or CRL */
		if( type == CRYPT_CERTTYPE_CRL )
			status = addCRL( keysetInfo, iCryptHandle );
		else
			status = addCert( keysetInfo, iCryptHandle );

		/* An item being added may already be present, however we can't fail
		   immediately because what's being added may be a chain containing 
		   further certs, so we keep track of whether we've successfully 
		   added at least one cert and clear data duplicate errors */
		if( status == CRYPT_OK )
			seenNonDuplicate = TRUE;
		else
			if( status == CRYPT_ERROR_DUPLICATE )
				status = CRYPT_OK;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_UNLOCK );
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* We reached the end of the chain/CRL without finding anything we 
		   could add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;

	return( status );
	}

/* Delete a record from the database */

static int deleteItemFunction( KEYSET_INFO *keysetInfo, 
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	char keyIDbuffer[ CRYPT_MAX_TEXTSIZE * 2 ];
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];

	/* If we're in the middle of a query, we can't do anything else */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_ERROR_INCOMPLETE );

	/* Delete the key from the database */
	setKeyID( keyIDbuffer, keyIDtype, keyID, keyIDlength );
	formatSQL( TRUE, sqlBuffer, 
					"DELETE FROM certificates WHERE $ = '$'",
			   getKeyName( keyIDtype ), keyIDbuffer );
	return( keysetInfo->keysetDBMS.performUpdate( keysetInfo, sqlBuffer, 
												  FALSE ) );
	}

/* Send a query to the database */

static int queryFunction( KEYSET_INFO *keysetInfo, const char *query,
						  const int queryLength )
	{
	char sqlBuffer[ MAX_SQL_QUERY_SIZE ];
	char expandedQuery[ MAX_SQL_QUERY_SIZE ];
	int status;

	if( queryLength > MAX_SQL_QUERY_SIZE - 20 )
		return( CRYPT_ARGERROR_STR1 );
	keysetInfo->keysetDBMS.queryState = QUERY_START;

	/* If we're cancelling an existing query, pass it on down */
	if( !strnicmp( query, "cancel", queryLength ) )
		{
		status = keysetInfo->keysetDBMS.performQuery( keysetInfo, NULL,
									NULL, NULL, 0, DBMS_QUERY_CANCEL );
		keysetInfo->keysetDBMS.queryState = QUERY_NONE;
		return( status );
		}

	/* If we're in the middle of an existing query the user needs to cancel 
	   it before starting another one */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_ERROR_INCOMPLETE );

	/* Rewrite the user-supplied portion of the query using the actual 
	   column names and turn it into a SELECT statement */
	formatQuery( expandedQuery, query, queryLength, keysetInfo );
	formatSQL( FALSE, sqlBuffer, 
				   "SELECT keyData FROM certificates WHERE $",
			   expandedQuery );
	status = keysetInfo->keysetDBMS.performQuery( keysetInfo, sqlBuffer, 
									NULL, NULL, 0, DBMS_QUERY_START );
	if( cryptStatusOK( status ) )
		keysetInfo->keysetDBMS.queryState = QUERY_INPROGRESS;

	/* If there are no more results available, wrap up the processing */
	if( status == CRYPT_ERROR_COMPLETE )
		{
		keysetInfo->keysetDBMS.performQuery( keysetInfo, NULL, 
									NULL, NULL, 0, DBMS_QUERY_CANCEL );
		keysetInfo->keysetDBMS.queryState = QUERY_NONE;
		}

	return( status );
	}

/* Open a connection to a database */

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *name,
							   const char *server, const char *user,
							   const char *password,
							   const CRYPT_KEYOPT_TYPE options )
	{
	int status;

	/* Perform a database back-end specific open */
	status = keysetInfo->keysetDBMS.openDatabase( keysetInfo,
					( name == ( char * ) CRYPT_UNUSED ) ? NULL : name,
					( server == ( char * ) CRYPT_UNUSED ) ? NULL : server,
					( user == ( char * ) CRYPT_UNUSED ) ? NULL : user,
					( password == ( char * ) CRYPT_UNUSED ) ? NULL : password );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's nothing else to do, we're done */
	if( options != CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* We need to create a new database before we can continue */
	status = createDatabase( keysetInfo );
	if( cryptStatusError( status ) )
		keysetInfo->keysetDBMS.closeDatabase( keysetInfo );
	return( status );
	}

/* Close the connection to a database */

static void shutdownKeysetFunction( KEYSET_INFO *keysetInfo )
	{
	/* If there was a problem opening the connection, there's nothing to do */
	if( !keysetInfo->isOpen )
		return;

	/* If we're in the middle of a query, complete the operation */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		queryFunction( keysetInfo, "cancel", 6 );

	keysetInfo->keysetDBMS.closeDatabase( keysetInfo );
	}

/* Set up the function pointers to the keyset methods */

int setAccessMethodDBMS( KEYSET_INFO *keysetInfo,
						 const CRYPT_KEYSET_TYPE type )
	{
	int status = CRYPT_ERROR;

	/* Set up the lower-level interface functions */
	switch( type )
		{
		case CRYPT_KEYSET_MSQL:
			status = setAccessMethodMSQL( keysetInfo );
			break;
		case CRYPT_KEYSET_MYSQL:
			status = setAccessMethodMySQL( keysetInfo );
			break;
		case CRYPT_KEYSET_ODBC:
			status = setAccessMethodODBC( keysetInfo );
			break;
		case CRYPT_KEYSET_ORACLE:
			status = setAccessMethodOracle( keysetInfo );
			break;
		case CRYPT_KEYSET_POSTGRES:
			status = setAccessMethodPostgres( keysetInfo );
			break;
		default:
			assert( NOTREACHED );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->shutdownKeysetFunction = shutdownKeysetFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;
	keysetInfo->getNextCertFunction = getNextCertFunction;
	keysetInfo->queryFunction = queryFunction;

	return( CRYPT_OK );
	}
