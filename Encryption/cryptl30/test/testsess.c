/****************************************************************************
*																			*
*					  cryptlib Secure Session Test Routines					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
  #include "../capi.h"
  #include "../test/test.h"
#else
  #include "capi.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

/****************************************************************************
*																			*
*								SSH Routines Test							*
*																			*
****************************************************************************/

/* Establish an SSH session */

int testSessionSSH( void )
	{
	CRYPT_SESSION cryptSession;
	BYTE buffer[ 1024 ];
	int cryptAlgo, keySize, bytesCopied, status;

	puts( "Testing SSH session..." );

	/* Create the client and server sessions */
	status = cryptCreateSession( &cryptSession, CRYPT_FORMAT_SSH );
	if( status == CRYPT_BADPARM2 )	/* SSH session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the server and user information and activate the session */
#if 1
	status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_SERVER, 
									  SSH_SERVER_NAME, 
									  strlen( SSH_SERVER_NAME ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_USERNAME, 
										  SSH_USER_NAME, 
										  strlen( SSH_USER_NAME ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_PASSWORD, 
										  SSH_PASSWORD, strlen( SSH_PASSWORD ) );
#else
KLUDGE_WARN( "SSH server + user name + password" );
#include "d:/tmp/sshhack.c"
#endif /* 0 */
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttributeString() failed with error code "
				"%d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to connect to SSH server failed with error code "
				"%d, line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Report the session security info details */
	status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO, 
								&cryptAlgo );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_KEYSIZE, 
									&keySize );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't query encryption algorithm and keysize used for "
				"session, status %d, line %d.\n", status, __LINE__ );
		return( status );
		}
	printf( "Session is protected using algorithm %d with %d bit key.\n",
			cryptAlgo, keySize * 8 );

	/* Print the first lot of output from the server */
	status = cryptPopData( cryptSession, buffer, 1024, &bytesCopied );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't read data from server, status %d, line %d.\n", 
				status, __LINE__ );
		return( status );
		}
	buffer[ bytesCopied ] = '\0';
	puts( "---- Server returned ----" );
	puts( buffer );
	puts( "---- End of output ----" );

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "SSH session succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								SSL/TLS Routines Test						*
*																			*
****************************************************************************/

/* Establish an SSL/TLS session */

static int connectSSLTLS( const CRYPT_FORMAT_TYPE sessionType,
						  const char *sessionText )
	{
	CRYPT_SESSION cryptSession;
	const char *serverName = ( sessionType == CRYPT_FORMAT_SSL ) ? \
							 SSL_SERVER_NAME : TLS_SERVER_NAME;
	int cryptAlgo, keySize, status;

	printf( "Testing %s session...\n", sessionText );

	/* Create the SSL session */
	status = cryptCreateSession( &cryptSession, sessionType );
	if( status == CRYPT_BADPARM2 )	/* SSL/TLS session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the server information and activate the session */
#if 1
	status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_SERVER, 
									  serverName, strlen( serverName ) );
#else
KLUDGE_WARN( "SSL/TLS server name + port" );
#include "d:/tmp/sslhack.c"
#endif /* 0 */
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttributeString() failed with error code "
				"%d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		printf( "Attempt to connect to %s server failed with error code "
				"%d, line %d\n", sessionText, status, __LINE__ );
		return( FALSE );
		}

	/* Report the session security info details */
	status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO, 
								&cryptAlgo );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_KEYSIZE, 
									&keySize );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't query encryption algorithm and keysize used for "
				"session, status %d, line %d.\n", status, __LINE__ );
		return( status );
		}
	printf( "Session is protected using algorithm %d with %d bit key.\n",
			cryptAlgo, keySize * 8 );

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "%s session succeeded.\n\n", sessionText );
	return( TRUE );
	}

int testSessionSSL( void )
	{
	return( connectSSLTLS( CRYPT_FORMAT_SSL, "SSL" ) );
	}

int testSessionTLS( void )
	{
	return( connectSSLTLS( CRYPT_FORMAT_TLS, "TLS" ) );
	}
