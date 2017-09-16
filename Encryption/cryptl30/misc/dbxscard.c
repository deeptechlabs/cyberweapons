/****************************************************************************
*																			*
*				  cryptlib Smart Card Keyset Glue Routines					*
*					  Copyright Peter Gutmann 1997-1999						*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
#elif  defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "misc/keyset.h"
#endif /* Compiler-specific includes */

/* Reading data from memory cards is a bit tricky since we can't tell in
   advance how much the card can hold, the best we can do is use a buffer
   big enough to hold the contents of the largest I2C card made (64Kb = 8K), 
   just to be safe we use one twice this size */

#define MAX_SCARDDATA_SIZE	16384

/* Open a connection to the card and read the data on it for later use, and
   shut down the connection to the reader */

static void shutdownKeysetFunction( KEYSET_INFO *keysetInfo )
	{
	/* Close down the session with the card if necessary */
	if( keysetInfo->keysetScard.readerHandle > 0 )
		keysetInfo->keysetScard.shutdownReader( &keysetInfo->keysetScard );
	if( keysetInfo->keyData != NULL )
		{
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		free( keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		}
	}

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *name,
							   const char *arg1, const char *arg2,
							   const char *arg3, const CRYPT_KEYOPT_TYPE options )
	{
	COMM_PARAMS commParams;
	int status;

	/* Set up the pointers to the error information in the encapsulating 
	   object */
	keysetInfo->keysetScard.errorCode = &keysetInfo->errorCode;
	keysetInfo->keysetScard.errorMessage = keysetInfo->errorMessage;

	/* Allocate room for the data from the card */
	if( ( keysetInfo->keyData = malloc( MAX_SCARDDATA_SIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( keysetInfo->keyData, 0, MAX_SCARDDATA_SIZE );
	keysetInfo->keyDataSize = MAX_SCARDDATA_SIZE;

	/* Set up the comms params if they're present */
	if( !getCommParams( &commParams, arg3, FALSE ) )
		/* Fall back to defaults, these should always work if the specialised
		   ones don't */
		getCommParams( &commParams, NULL, FALSE );

	/* Open a session to the reader and card.  If an error occurs we map the 
	   initReader()-relative status codes to a more generic keyset open code */
	status = keysetInfo->keysetScard.initReader( &keysetInfo->keysetScard,
												 arg1, arg2, &commParams );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_STR1 || \
				  status == CRYPT_ARGERROR_STR2 ) ? \
				CRYPT_ERROR_OPEN : status );

	/* If we're opening the keyset in create mode, wipe the old keyset.  
	   Memory cards don't explicitly support the ability to delete records 
	   so we write a null record which tells the lower-level routines to 
	   overwrite whatever's on the card */
	if( options == CRYPT_KEYOPT_CREATE )
		return( keysetInfo->keysetScard.writeData( &keysetInfo->keysetScard,
												   NULL, 0 ) );

	/* Try and read the key data from the card */
	status = keysetInfo->keysetScard.readData( \
							&keysetInfo->keysetScard, keysetInfo->keyData );
	if( cryptStatusError( status ) )
		{
		shutdownKeysetFunction( keysetInfo );
		return( status );
		}

	return( CRYPT_OK );
	}

int setAccessMethodScard( KEYSET_INFO *keysetInfo, const char *name )
	{
	int status;

	/* Set up the lower-level interface functions */
	if( !stricmp( name, "ASE" ) )
		status = setAccessMethodASE( &keysetInfo->keysetScard );
	else if( !stricmp( name, "Gemplus" ) )
		status = setAccessMethodGemplus( &keysetInfo->keysetScard );
	else if( !stricmp( name, "Towitoko" ) )
		status = setAccessMethodTowitoko( &keysetInfo->keysetScard );
	else
		status = CRYPT_ARGERROR_STR1;
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->shutdownKeysetFunction = shutdownKeysetFunction;

	return( CRYPT_OK );
	}
