/****************************************************************************
*																			*
*							Stream I/O Functions							*
*						Copyright Peter Gutmann 1993-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "stream.h"
#else
  #include "keymgmt/stream.h"
#endif /* Compiler-specific includes */
#if defined( __UNIX__ )
  #include <errno.h>
  #include <fcntl.h>
  #include <sys/types.h>
  #include <sys/file.h>
  #include <sys/stat.h>
  #if !( ( defined( sun ) && OSVERSION == 4 ) || defined( linux ) || \
		   defined( __bsdi__ ) || defined( __FreeBSD__ ) || \
		   defined( __hpux ) || defined( _M_XENIX ) )
	#include <sys/mode.h>
  #endif /* SunOS || Linux || BSDI */
  #include <unistd.h>
  #if defined( sun ) || defined( _M_XENIX ) || defined( linux ) || \
	  defined( __osf__ ) || defined( __bsdi__ ) || defined( _AIX )
	#include <utime.h>			/* It's a SYSV thing... */
  #endif /* SYSV Unixen */

  #if ( defined( sun ) && ( OSVERSION >= 5 ) ) || \
	  defined( _M_XENIX ) || defined( __hpux ) || defined( _AIX )
	#define flock( a, b )		/* Slowaris, SCO, Aches, and PHUX don't support flock() */
    /* Actually Slowaris does have flock(), but there are lots of warnings
	   in the manpage about using it only on BSD platforms, and the result
	   won't work with any of the system libraries.  SunOS did support it
	   without any problems, it's only Slowaris which breaks it */
  #endif /* Slowaris || SCO || PHUX || Aches */
  #if ( defined( _M_XENIX ) && ( OSVERSION == 3 ) )
	#define ftruncate( a, b )	chsize( a, b )
  #endif /* SCO */
#elif defined( __AMIGA__ )
  #include <proto/dos.h>
#elif defined( __MSDOS16__ ) || defined( __WIN16__ )
  #include <io.h>
#elif defined( __OS2__ )
  #define INCL_DOSFILEMGR	/* DosQueryPathInfo(),DosSetFileSize(),DosSetPathInfo */
  #include <os2.h>			/* FILESTATUS */
  #include <io.h>
#elif defined( __WIN32__ )
  /* The size of the buffer for Win32 ACLs */
  #define ACL_BUFFER_SIZE		1024
#elif defined( __IBM4758__ )
  #include <scc_err.h>
  #include <scc_int.h>
#elif defined( __TANDEM__ )
  #include <errno.h>
#elif defined( __MAC__ )
  #include <Script.h>
#endif /* OS-specific includes and defines */

/* Some environments place severe restrictions on what can be done with file
   I/O, either having no filesystem at all or having one with characteristics
   which don't fit the stdio model.  For these systems we used our own in-
   memory buffer and make them look like memory streams until they're
   flushed, at which point they're written to backing store (flash RAM/
   EEPROM/DASD/whatever non-FS storage is being used) in one go.

   For streams with the sensitive bit set we don't expand the buffer size
   (because the original was probably in protected memory) for non-sensitive
   streams we do expand the size if necessary.  This means we have to choose
   a suitably large buffer for sensitive streams (private keys), but one
   which isn't too big, 16K is about right (typical private key files with
   cert chains are 2K) */

#if defined( __VMCMS__ ) || defined( __IBM4758__ )
  #define NO_STDIO
  #define STREAM_BUFSIZE	16384
#endif /* Nonstandard file I/O systems */

/****************************************************************************
*																			*
*							Generic Stream I/O Functions					*
*																			*
****************************************************************************/

/* In environments where we're provinding emulated I/O, we need to expand the
   write buffer on demand when it fills up.  The following routine does a
   safe realloc() which wipes the original buffer */

#ifdef NO_STDIO

static int expandBuffer( STREAM *stream, const int length )
	{
	void *newBuffer;
	int newSize = stream->bufSize + STREAM_BUFSIZE;

	/* Determine how much to expand the buffer by.  If it's a small buffer
	   allocated when we initially read a file and it doesn't look like we'll
	   be overflowing a standard-size buffer, we first expand it up to
	   STREAM_BUFSIZE before increasing it in STREAM_BUFSIZE steps */
	if( stream->bufSize < STREAM_BUFSIZE && \
		stream->bufPos + length < STREAM_BUFSIZE - 1024 )
		newSize = STREAM_BUFSIZE;

	/* Allocate the buffer and copy the new data across.  If the malloc
	   fails we return CRYPT_ERROR_OVERFLOW rather than CRYPT_ERROR_MEMORY
	   since the former is more appropriate for the emulated-I/O environment */
	if( ( newBuffer = malloc( stream->bufSize + STREAM_BUFSIZE ) ) == NULL )
		{
		stream->status = CRYPT_ERROR_OVERFLOW;
		return( CRYPT_ERROR_OVERFLOW );
		}
	memcpy( newBuffer, stream->buffer, stream->bufSize );
	zeroise( stream->buffer, stream->bufSize );
	free( stream->buffer );
	stream->buffer = newBuffer;
	stream->bufSize = newSize;

	return( CRYPT_OK );
	}
#endif /* NO_STDIO */

/* OS-specific support routines */

#ifdef __MAC__

static void CStringToPString( const char *cstring, StringPtr pstring )
	{
	short len = min( strlen( cstring ), 255 );

	memmove( pstring+1, cstring, len );
	*pstring = len;
	}
#endif /* __MAC__ */

/* Read a byte from a stream */

int sgetc( STREAM *stream )
	{
#if defined( __WIN32__ )
	DWORD bytesRead;
	BYTE ch;
#elif defined( __MAC__ )
	long bytesRead = 1;
	BYTE ch;
#else
	int ch;
#endif /* OS-specific variable declarations */

	assert( stream != NULL && !stream->isNull );

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != CRYPT_OK )
		return( stream->status );

	/* If we ungot a char, return this */
	if( stream->ungetChar )
		{
		ch = stream->lastChar;
		stream->ungetChar = FALSE;
		return( ch );
		}

	/* If it's a memory stream, read the data from the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos >= stream->bufEnd )
			{
			stream->status = CRYPT_ERROR_UNDERFLOW;
			return( CRYPT_ERROR_UNDERFLOW );
			}
		stream->lastChar = stream->buffer[ stream->bufPos++ ];

		return( stream->lastChar );
		}

#ifndef NO_STDIO
	/* It's a file stream, read the data from the file */
#if defined( __WIN32__ )
	if( !ReadFile( stream->hFile, &ch, 1, &bytesRead, NULL ) || !bytesRead )
#elif defined( __MAC__ )
	if( !FSRead( stream->refNum, &bytesRead, &ch) || !bytesRead )
#else
	if( ( ch = getc( stream->filePtr ) ) == EOF )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_ERROR_UNDERFLOW;
		return( CRYPT_ERROR_UNDERFLOW );
		}
#else
	assert( NOTREACHED );
#endif /* NO_STDIO */

	return( stream->lastChar = ch );
	}

/* Write a byte to a stream */

int sputc( STREAM *stream, int data )
	{
#if defined( __WIN32__ )
	DWORD bytesWritten;
	int regData = data;
#elif defined( __MAC__ )
	long bytesWritten = 1;
	BYTE regData = data;
#else
	register int regData = data;
#endif /* __WIN32__ */

	assert( stream != NULL );

	/* With any luck localData is now in a register, so we can try to destroy
	   the copy of the data on the stack.  We do this by assigning a live
	   value to it and using it a little later on.  A really good optimizing
	   compiler should detect that this is a nop, but with any luck most
	   compilers won't */
	data = stream->status;

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( data != CRYPT_OK )
		return( data );		/* Equal to stream->status, force reuse of data */

	/* If it's a null stream, just record the write and return */
	if( stream->isNull )
		{
		stream->bufPos++;
		return( CRYPT_OK );
		}

	/* If we ungot a char, move back one entry in the buffer */
	if( stream->ungetChar && stream->bufPos )
		{
		stream->bufPos--;
		stream->ungetChar = FALSE;
		}

	/* If it's a memory stream, deposit the data in the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos >= stream->bufSize )
			{
#ifdef NO_STDIO
			/* If it's a non-sensitive pseudo-I/O stream, expand the buffer */
			if( stream->isIOStream && !stream->isSensitive )
				{
				const int status = expandBuffer( stream, 1 );
				if( cryptStatusError( status ) )
					return( status );
				}
			else
#endif /* NO_STDIO */
				{
				stream->status = CRYPT_ERROR_OVERFLOW;
				return( CRYPT_ERROR_OVERFLOW );
				}
			}
		stream->buffer[ stream->bufPos++ ] = regData;
		if( stream->bufEnd < stream->bufPos )
			/* Move up the end-of-data pointer if necessary */
			stream->bufEnd = stream->bufPos;
		stream->isDirty = TRUE;

		return( CRYPT_OK );
		}

#ifndef NO_STDIO
	/* It's a file stream, write the data to the file */
#if defined( __WIN32__ )
	if( !WriteFile( stream->hFile, &regData, 1, &bytesWritten, NULL ) || !bytesWritten )
#elif defined( __MAC__ )
	if( !FSWrite( stream->refNum, &bytesWritten, &regData ) || !bytesWritten )
#else
	if( putc( regData, stream->filePtr ) == EOF )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_ERROR_WRITE;
		return( CRYPT_ERROR_WRITE );
		}
	stream->isDirty = TRUE;
#else
	assert( NOTREACHED );
#endif /* NO_STDIO */

	return( CRYPT_OK );
	}

/* Unget a byte from a stream */

int sungetc( STREAM *stream )
	{
	assert( stream != NULL );

	/* If the stream is empty, calling this function resets the stream
	   status to nonempty (since we can't read past EOF, ungetting even one
	   char will reset the stream status).  If the stream isn't empty, we
	   set a flag to indicate that we should return the last character read
	   in the next read call */
	if( stream->status == CRYPT_ERROR_UNDERFLOW )
		stream->status = CRYPT_OK;
	else
		stream->ungetChar = TRUE;

	return( CRYPT_OK );
	}

/* Read a block of data from a stream.  If not enough data is available it
   will fail with CRYPT_ERROR_UNDERFLOW rather than trying to read as much 
   as it can, which mirrors the behaviour of most read()/fread() 
   implementations */

int sread( STREAM *stream, void *buffer, int length )
	{
#if defined( __WIN32__ )
	DWORD bytesRead;
#elif defined( __MAC__ )
	long bytesRead = length;
#endif /* __WIN32__ */
	BYTE *bufPtr = buffer;

	assert( stream != NULL && !stream->isNull );
	assert( buffer != NULL );
	assert( length > 0 );

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != CRYPT_OK )
		return( stream->status );

	/* If we ungot a char, return this first */
	if( stream->ungetChar )
		{
		*bufPtr++ = stream->lastChar;
		stream->ungetChar = FALSE;
		if( !--length )
			return( CRYPT_OK );
		}

	/* If it's a memory stream, read the data from the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufEnd )
			{
			memset( bufPtr, 0, length );	/* Clear the output buffer */
			stream->status = CRYPT_ERROR_UNDERFLOW;
			return( CRYPT_ERROR_UNDERFLOW );
			}
		memcpy( bufPtr, stream->buffer + stream->bufPos, length );
		stream->bufPos += length;

		return( CRYPT_OK );
		}

#ifndef NO_STDIO
	/* It's a file stream, read the data from the file */
#ifdef __WIN32__
	if( !ReadFile( stream->hFile, bufPtr, length, &bytesRead, NULL ) || \
		( int ) bytesRead != length )
#elif defined( __MAC__ )
	if( !FSRead( stream->refNum, &bytesRead, bufPtr ) || \
		( int ) bytesRead != length )
#else
	if( fread( bufPtr, 1, length, stream->filePtr ) != ( size_t ) length )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_ERROR_READ;
		return( CRYPT_ERROR_READ );
		}
#else
	assert( NOTREACHED );
#endif /* NO_STDIO */

	return( CRYPT_OK );
	}

/* Write a block of data from a stream.  If not enough data is available it
   will fail with CRYPT_ERROR_OVERFLOW rather than trying to write as much 
   as it can, which mirrors the behaviour of most write()/fwrite()
   implementations */

int swrite( STREAM *stream, const void *buffer, const int length )
	{
#ifdef __WIN32__
	DWORD bytesWritten;
#elif defined( __MAC__ )
	long bytesWritten = length;
#endif /* __WIN32__ */

	assert( stream != NULL );
	assert( buffer != NULL );
	assert( length > 0 );

	/* If there's a problem with the stream, don't try to do anything until
	   the error is cleared */
	if( stream->status != CRYPT_OK )
		return( stream->status );

	/* If it's a null stream, just record the write and return */
	if( stream->isNull )
		{
		stream->bufPos += length;
		return( CRYPT_OK );
		}

	/* If it's a memory stream, deposit the data in the buffer */
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + length > stream->bufSize )
			{
#ifdef NO_STDIO
			/* If it's a non-sensitive pseudo-I/O stream, expand the buffer */
			if( stream->isIOStream && !stream->isSensitive )
				{
				const int status = expandBuffer( stream, length );
				if( cryptStatusError( status ) )
					return( status );
				}
			else
#endif /* NO_STDIO */
				{
				stream->status = CRYPT_ERROR_OVERFLOW;
				return( CRYPT_ERROR_OVERFLOW );
				}
			}
		memcpy( stream->buffer + stream->bufPos, buffer, length );
		stream->bufPos += length;
		if( stream->bufEnd < stream->bufPos )
			/* Move up the end-of-data pointer if necessary */
			stream->bufEnd = stream->bufPos;
		stream->isDirty = TRUE;

		return( CRYPT_OK );
		}

#ifndef NO_STDIO
	/* It's a file stream, write the data to the file */
#if defined( __WIN32__ )
	if( !WriteFile( stream->hFile, buffer, length, &bytesWritten, NULL ) || \
		( int ) bytesWritten != length )
#elif defined( __MAC__ )
	if( !FSWrite( stream->refNum, &bytesWritten, buffer ) || \
		( int ) bytesWritten != length )
#else
	if( fwrite( buffer, 1, length, stream->filePtr ) != ( size_t ) length )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_ERROR_WRITE;
		return( CRYPT_ERROR_WRITE );
		}
	stream->isDirty = TRUE;
#else
	assert( NOTREACHED );
#endif /* NO_STDIO */

	return( CRYPT_OK );
	}

/* Commit data in a stream to backing storage */

int sflush( STREAM *stream )
	{
#if defined( __MAC__ )
	FileParam paramBlock;
#endif /* __MAC__ */

	assert( stream != NULL && !stream->isNull );

	/* If there's no backing storage or the data is unchanged, there's 
	   nothing to do */
#ifdef NO_STDIO
	if( !stream->isDirty || \
		( sIsMemoryStream( stream ) && !stream->isIOStream ) )
#else
	if( !stream->isDirty || sIsMemoryStream( stream ) )
#endif /* NO_STDIO */
		return( CRYPT_OK );

	/* Commit the data as required by the system */
#if defined( __WIN32__ )
	FlushFileBuffers( stream->hFile );
#elif defined( __MAC__ )
	paramBlock.ioCompletion = NULL;
	paramBlock.ioFRefNum = stream->refNum;
	PBFlushFileSync( &paramBlock );
#elif defined( NO_STDIO )
  #if defined( __IBM4758__ )
	/* Write the data to flash or BB memory as appropriate */
	if( sccSavePPD( stream->name, stream->buffer, stream->bufEnd,
			( ( stream->isSensitive ) ? PPD_BBRAM : PPD_FLASH ) | PPD_TRIPLE ) != PPDGood )
		return( CRYPT_ERROR_WRITE );
  #elif defined( __VMCMS__ )
	/* Under CMS, MVS, TSO, etc the only consistent way to handle writes is
	   to write a fixed-length single-record file containing all the data in
	   one record, so we can't really do anything until the data is flushed */
	{
	FILE *filePtr;
	char formatBuffer[ 32 ];
	int count;

	sprintf( formatBuffer, "wb, recfm=F, lrecl=%d, noseek", stream->bufPos );
	filePtr = fopen( stream->name, formatBuffer );
	if( filePtr == NULL )
		return( CRYPT_ERROR_WRITE );
	count = fwrite( stream->buffer, stream->bufEnd, 1, filePtr );
	fclose( filePtr );
	if( count != 1 )
		return( CRYPT_ERROR_WRITE );
	}
  #else
	#error Need to add mechanism to save data to backing store
  #endif /* Nonstandard I/O enviroments */
#else
	fflush( stream->filePtr );
#endif /* OS-specific data commit */
	stream->isDirty = FALSE;

	return( CRYPT_OK );
	}

/* Move to an absolute position in a stream */

int sseek( STREAM *stream, const long position )
	{
	assert( stream != NULL );
	assert( position >= 0 );

	/* If it's a memory or null stream, move to the position in the buffer */
	if( stream->isNull )
		{
		stream->bufPos = ( int ) position;
		return( CRYPT_OK );
		}
	if( sIsMemoryStream( stream ) )
		{
		stream->ungetChar = FALSE;
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			( int ) position > stream->bufSize )
			{
			stream->bufPos = stream->bufSize;
			stream->status = CRYPT_ERROR_UNDERFLOW;
			return( CRYPT_ERROR_UNDERFLOW );
			}

		/* Set the new R/W position */
		stream->bufPos = ( int ) position;
		if( stream->bufPos > stream->bufEnd )
			/* If we've moved past the end of the valid data in the buffer,
			   move the end of data pointer to match the current position.
			   This mimics the behaviour of fseek(), which allows a seek past
			   the end of the file */
			stream->bufEnd = stream->bufPos;

		return( CRYPT_OK );
		}

#ifndef NO_STDIO
	/* It's a file stream, seek to the position in the file */
#if defined( __WIN32__ )
	if( SetFilePointer( stream->hFile, position, NULL, 
						FILE_BEGIN ) == 0xFFFFFFFF )
#elif defined( __MAC__ )
	if( SetFPos( stream->refNum, fsFromStart, position) )
#else
	if( fseek( stream->filePtr, position, SEEK_SET ) )
#endif /* __WIN32__ */
		return( CRYPT_ERROR_WRITE );
#else
	assert( NOTREACHED );
#endif /* NO_STDIO */

	return( CRYPT_OK );
	}

/* Determine the position in a stream */

long stell( STREAM *stream )
	{
	long position;

	assert( stream != NULL );

	/* If it's a memory or null stream, return the position in the buffer */
	if( sIsMemoryStream( stream ) || stream->isNull )
		return( ( stream )->bufPos - ( stream )->ungetChar );

#ifndef NO_STDIO
	/* It's a file stream, find the position in the file */
#if defined( __WIN32__ )
	if( ( position = SetFilePointer( stream->hFile, 0, NULL, 
									 FILE_CURRENT ) ) == 0xFFFFFFFF )
#elif defined( __MAC__ )
	if( GetFPos( stream->refNum, &position ) )
#else
	if( ( position = ftell( stream->filePtr ) ) == -1L )
#endif /* __WIN32__ */
		return( CRYPT_ERROR_READ );
#else
	assert( NOTREACHED );
#endif /* NO_STDIO */

	return( position );
	}

/* Skip a number of bytes in a stream */

int sSkip( STREAM *stream, const long length )
	{
	long skipLength = length;

	assert( stream != NULL );
	assert( length > 0 );

	/* If there's a problem with the stream, don't try to do anything */
	if( stream->status != CRYPT_OK )
		return( stream->status );

	/* If we were ready to unget a char, skip it */
	if( stream->ungetChar )
		{
		stream->ungetChar = FALSE;
		stream->lastChar = 0;
		skipLength--;
		if( skipLength == 0 )
			return( CRYPT_OK );
		}

	/* If it's a memory or null stream, move ahead in the buffer */
	if( stream->isNull )
		{
		stream->bufPos += ( int ) skipLength;
		return( CRYPT_OK );
		}
	if( sIsMemoryStream( stream ) )
		{
		if( stream->bufSize != STREAMSIZE_UNKNOWN && \
			stream->bufPos + skipLength > stream->bufSize )
			{
			stream->bufPos = stream->bufSize;
			stream->status = CRYPT_ERROR_UNDERFLOW;
			return( CRYPT_ERROR_UNDERFLOW );
			}
		stream->bufPos += ( int ) skipLength;
		if( stream->bufPos > stream->bufEnd )
			/* If we've moved past the end of the valid data in the buffer,
			   move the end of data pointer to match the current position.
			   This mimics the behaviour of fseek(), which allows a seek past
			   the end of the file */
			stream->bufEnd = stream->bufPos;

		return( CRYPT_OK );
		}

#ifndef NO_STDIO
	/* It's a file stream, skip the data in the file */
#if defined( __WIN32__ )
	if( SetFilePointer( stream->hFile, skipLength, NULL, 
						FILE_CURRENT ) == 0xFFFFFFFF )
#elif defined( __MAC__ )
	if( SetFPos( stream->refNum, fsFromMark, skipLength) )
#else
	if( fseek( stream->filePtr, skipLength, SEEK_CUR ) )
#endif /* __WIN32__ */
		{
		stream->status = CRYPT_ERROR_READ;
		return( CRYPT_ERROR_READ );
		}
#endif /* NO_STDIO */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Memory Stream Functions							*
*																			*
****************************************************************************/

/* Open a memory stream.  If the buffer parameter is NULL and the length is
   zero, this creates a null stream which serves as a data sink - this is 
   useful for implementing sizeof() functions by writing data to null 
   streams */

int sMemOpen( STREAM *stream, void *buffer, const int length )
	{
	assert( stream != NULL );
	assert( ( buffer == NULL && length == 0 ) || \
			( buffer != NULL && \
			  ( length > 1 || length == STREAMSIZE_UNKNOWN ) ) );

	memset( stream, 0, sizeof( STREAM ) );
	if( buffer == NULL )
		{
		/* Make it a null stream */
		stream->isNull = TRUE;
		return( CRYPT_OK );
		}

	/* Initialise the stream structure */
	stream->buffer = buffer;
	stream->bufSize = length;
	if( stream->bufSize != STREAMSIZE_UNKNOWN )
		memset( stream->buffer, 0, stream->bufSize );

	return( CRYPT_OK );
	}

/* Close a memory stream */

int sMemClose( STREAM *stream )
	{
	assert( stream != NULL );

	/* Clear the stream structure */
	if( stream->buffer != NULL )
		if( stream->bufSize != STREAMSIZE_UNKNOWN )
			zeroise( stream->buffer, stream->bufSize );
		else
			/* If it's of an unknown size we can still zap as much as was
			   written to/read from it */
			if( stream->bufEnd > 0 )
				zeroise( stream->buffer, stream->bufEnd );
	zeroise( stream, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/* Connect a memory stream without destroying the buffer contents */

int sMemConnect( STREAM *stream, const void *buffer, const int length )
	{
	assert( stream != NULL );
	assert( buffer != NULL );
	assert( length >= 1 || length == STREAMSIZE_UNKNOWN );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	stream->buffer = ( void * ) buffer;
	stream->bufSize = stream->bufEnd = length;

	return( CRYPT_OK );
	}

/* Disconnect a memory stream without destroying the buffer contents */

int sMemDisconnect( STREAM *stream )
	{
	assert( stream != NULL );

	/* Clear the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							File Stream Functions							*
*																			*
****************************************************************************/

/* Usually we'd use the C stdio routines for file I/O, but under Win32 we can
   get enhanced control over things like file security and buffering by using
   the Win32 file routines (in fact this is almost essential to work with
   things like ACL's for sensitive files and forcing disk writes for files we
   want to erase.  Without the forced disk write the data in the cache
   doesn't get flushed before the file delete request arrives, after which
   it's discarded rather than being written, so the file never gets
   overwritten).  In addition some embedded environments don't support stdio
   so we have to supply our own alternatives */

/* Open a file stream */

#if defined( __WIN32__ )

/* Get information on the current user.  This works in an extraordinarily
   ugly manner because although the TOKEN_USER struct is only 8 bytes long,
   Windoze allocates an extra 24 bytes after the end of the struct into which
   it stuffs data which the SID in the TOKEN_USER struct points to.  This
   means we can't return the SID pointer from the function because it would
   point to freed memory, so we need to return the pointer to the entire
   TOKEN_USER struct to ensure that what the SID pointer points to remains
   around for the caller to use */

TOKEN_USER *getUserInfo( void )
	{
	TOKEN_USER *pUserInfo = NULL;
	HANDLE hToken = INVALID_HANDLE_VALUE;	/* See comment below */
	DWORD cbTokenUser;

	/* Get the security token for this thread.  We initialise the hToken even
	   though it shouldn't be necessary because Windows tries to read its
	   contents, which indicates there might be problems if it happens to
	   have the wrong value */
	if( !OpenThreadToken( GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) )
		if( GetLastError() == ERROR_NO_TOKEN )
			{
			/* If the thread doesn't have a security token, try the token
			   associated with the process */
			if( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY,
								   &hToken ) )
				return( NULL );
			}
		else
			return( NULL );

	/* Query the size of the user information associated with the token,
	   allocate a buffer for it, and fetch the information into the buffer */
	GetTokenInformation( hToken, TokenUser, NULL, 0, &cbTokenUser );
	if( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
		{
		pUserInfo = ( TOKEN_USER * ) malloc( cbTokenUser );
		if( !GetTokenInformation( hToken, TokenUser, pUserInfo, cbTokenUser,
								 &cbTokenUser ) )
			{
			free( pUserInfo );
			pUserInfo = NULL;
			}
		}

	/* Clean up */
	CloseHandle( hToken );
	return( pUserInfo );
	}

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	SECURITY_ATTRIBUTES sa;
	LPSECURITY_ATTRIBUTES lpsa = NULL;
	SECURITY_DESCRIPTOR sdPermissions;
	TOKEN_USER *pUserInfo = NULL;
	BYTE aclBuffer[ ACL_BUFFER_SIZE ];
	PACL paclKey = ( PACL ) aclBuffer;
	int status = CRYPT_ERROR_OPEN;

	assert( stream != NULL );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	/* If we're creating the file and we don't want others to get to it, set
	   up the security attributes to reflect this provided the OS supports
	   security */
	if( !isWin95 && ( mode & FILE_WRITE ) && ( mode & FILE_PRIVATE ) )
		{
		/* Get the SID for the current user */
		if( ( pUserInfo = getUserInfo() ) == NULL )
			goto exit;

		/* Set the current user to own this security descriptor */
		if( !InitializeSecurityDescriptor( &sdPermissions,
										   SECURITY_DESCRIPTOR_REVISION1 ) || \
			!SetSecurityDescriptorOwner( &sdPermissions, pUserInfo->User.Sid, 0 ) )
			goto exit;

		/* Set up the discretionary access control list (DACL) with one
		   access control entry (ACE) for the current user which allows full
		   access.  We give the user a somewhat odd set of access rights 
		   rather than the more restricted set which would make sense because 
		   this set is detected as "Full control" access instead of the 
		   peculiar collection of rights we'd get from the more sensible 
		   GENERIC_READ | GENERIC_WRITE | STANDARD_RIGHTS_ALL.  The OS can 
		   check the full-access ACL much quicker than the one with the more 
		   restricted access permissions */
		if( !InitializeAcl( paclKey, ACL_BUFFER_SIZE, ACL_REVISION2 ) || \
			!AddAccessAllowedAce( paclKey, ACL_REVISION2,
								  GENERIC_ALL | STANDARD_RIGHTS_ALL,
								  pUserInfo->User.Sid ) )
			goto exit;

		/* Bind the DACL to the security descriptor */
		if( !SetSecurityDescriptorDacl( &sdPermissions, TRUE, paclKey, FALSE ) )
			goto exit;

		/* Finally, set up the security attributes structure */
		sa.nLength = sizeof( SECURITY_ATTRIBUTES );
		sa.bInheritHandle = FALSE;
		sa.lpSecurityDescriptor = &sdPermissions;
		lpsa = &sa;
		}

	/* Try and open the file */
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		stream->hFile = CreateFile( fileName, GENERIC_READ | GENERIC_WRITE, 0, lpsa,
									CREATE_ALWAYS,
									FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
									NULL );
	else
		{
		int openMode = ( ( mode & FILE_RW_MASK ) == FILE_READ ) ? \
					   GENERIC_READ : GENERIC_READ | GENERIC_WRITE;

		stream->hFile = CreateFile( fileName, openMode, FILE_SHARE_READ,
									NULL, OPEN_EXISTING,
									FILE_FLAG_SEQUENTIAL_SCAN, NULL );
		}
	if( stream->hFile == INVALID_HANDLE_VALUE )
		{
		DWORD errorCode = GetLastError();

		/* Translate the Win32 error code into an equivalent cryptlib error
		   code */
		if( errorCode == ERROR_FILE_NOT_FOUND || \
			errorCode == ERROR_PATH_NOT_FOUND )
			status = CRYPT_ERROR_NOTFOUND;
		else
			if( errorCode == ERROR_ACCESS_DENIED )
				status = CRYPT_ERROR_PERMISSION;
			else
				status = CRYPT_ERROR_OPEN;
		}
	else
		status = CRYPT_OK;

	/* Clean up */
exit:
	if( pUserInfo != NULL )
		free( pUserInfo );
	return( status );
	}

#elif defined( __MAC__ )

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	Str255 pFileName;
	OSErr err;
	
	assert( stream != NULL );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

	CStringToPString( fileName, &pFileName );
	
	err = FSMakeFSSpec(0, 0, &pFileName, &stream->fsspec );
	if( err == dirNFErr || err == nsvErr )	
		/* Volume or parent directory not found */
		return CRYPT_ERROR_NOTFOUND;
	if( err != noErr && err != fnfErr )
		/* fnfErr is OK since the fsspec is still valid */
		return CRYPT_ERROR_OPEN;
	
	if( mode & FILE_WRITE )
		{
		/* Try and create the file, specifying its type and creator */
		err = FSpCreate( &stream->fsspec, '????', 'CLib', smSystemScript );
		if ( err == wPrErr || err == vLckdErr || err == afpAccessDenied )
			return CRYPT_ERROR_PERMISSION;
		if ( err != noErr && err != dupFNErr && err != afpObjectTypeErr )
			return CRYPT_ERROR_OPEN;
		}
	
	err = FSpOpenDF( &stream->fsspec, mode & FILE_RW_MASK, &stream->refNum );
	if( err == nsvErr || err == dirNFErr || err == fnfErr )
		return CRYPT_ERROR_NOTFOUND;
	if( err == opWrErr || err == permErr || err == afpAccessDenied )
		return CRYPT_ERROR_PERMISSION;
	if( err != noErr )
		return CRYPT_ERROR_OPEN;

	return( CRYPT_OK );
	}

#elif defined( NO_STDIO )

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	const BOOLEAN useBBRAM = ( mode & FILE_SENSITIVE ) ? TRUE : FALSE;
	long length, status;

	assert( stream != NULL );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );

#if defined( __IBM4758__ )
	/* Make sure the filename matches the 4758's data item naming conventions
	   and remember the filename.  The best error code to return if there's
	   a problem is a file open error, since this is buried so many levels
	   down that a parameter error won't be meaningful to the caller */
	if( strlen( fileName ) > 8 )
		return( CRYPT_ERROR_OPEN );
	strcpy( stream->name, fileName );

	/* If we're doing a read, fetch the data into memory and convert the
	   stream to a memory stream (which is done implicitly by allocating a
	   memory buffer for it) */
	if( mode & FILE_READ )
		{
		/* Find out how big the data item is and allocate a buffer for
		   it */
		status = sccGetPPDLen( ( char * ) fileName, &length );
		if( status != PPDGood )
			return( ( status == PPD_NOT_FOUND ) ? CRYPT_ERROR_NOTFOUND : \
					( status == PPD_NOT_AUTHORIZED ) ? CRYPT_ERROR_PERMISSION : \
					CRYPT_ERROR_OPEN );
		if( ( stream->buffer = malloc( length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		stream->bufSize = stream->bufEnd = length;
		stream->isIOStream = TRUE;

		/* Fetch the data into the buffer so it can be read as a memory
		   stream */
		status = sccGetPPD( ( char * ) fileName, stream->buffer, length );
		return( ( status != PPDGood ) ? CRYPT_ERROR_READ : CRYPT_OK );
		}

	/* We're doing a write, make sure there's enough room available (this
	   doesn't guarantee that there'll be enough when the data is committed,
	   but it makes sense to at least check when the "file" is opened) */
	status = sccQueryPPDSpace( &length, ( useBBRAM ) ? PPD_BBRAM : PPD_FLASH );
	if( status != PPDGood || length < STREAM_BUFSIZE )
		return( CRYPT_ERROR_OPEN );
#elif defined( __VMCMS__ )
	/* If we're going to be doing a write either now or later, we can't open 
	   the file until we have all the data to write to it available since the 
	   open arg has to include the file format information so all we can do at 
	   this point is remember the name for later use */
	strcpy( stream->name, fileName );

	/* If we're doing a read, fetch the data into memory and convert the
	   stream to a memory stream (which is done implicitly by allocating a
	   memory buffer for it) */
	if( mode & FILE_READ )
		{
		FILE *filePtr;
		fldata_t fileData;
		char fileBuffer[ MAX_PATH_LENGTH ], formatBuffer[ 32 ];
		int count;

		/* Open the file and determine how large it is */
		filePtr = fopen( fileName, "rb" );
		if( filePtr == NULL )
			return( CRYPT_ERROR_OPEN );
		status = fldata( filePtr, fileBuffer, &fileData );
		if( status )
			{
			fclose( filePtr );
			return( CRYPT_ERROR_OPEN );
			}
		length = fileData.__maxreclen;

		/* Fetch the data into the buffer so it can be read as a memory
		   stream */
		if( ( stream->buffer = malloc( length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		stream->bufSize = stream->bufEnd = length;
		stream->isIOStream = TRUE;
		status = fread( stream->buffer, length, 1, filePtr );
		fclose( filePtr );
		return( ( status != 1 ) ? CRYPT_ERROR_READ : CRYPT_OK );
		}
#else
	#error Need to add mechanism to read data from backing store
#endif /* Nonstandard I/O enviroments */

	/* Allocate the initial I/O buffer for the data */
	if( ( stream->buffer = malloc( STREAM_BUFSIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	stream->bufSize = STREAM_BUFSIZE;
	stream->isSensitive = useBBRAM;
	stream->isIOStream = TRUE;

	return( CRYPT_OK );
	}

#else

int sFileOpen( STREAM *stream, const char *fileName, const int mode )
	{
	static const char *modes[] = { "x", "rb", "wb", "rb+" };
	const char *openMode;

	assert( stream != NULL );
	assert( fileName != NULL );
	assert( mode != 0 );

	/* Initialise the stream structure */
	memset( stream, 0, sizeof( STREAM ) );
	openMode = modes[ mode & FILE_RW_MASK ];

	/* If we're trying to write to the file, check whether we've got
	   permission to do so */
	if( ( mode & FILE_WRITE ) && fileReadonly( fileName ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Under Unix we try to defend against writing through links, but this is
	   somewhat difficult since the there's no atomic way to do this, and
	   without resorting to low-level I/O it can't be done at all.  What we
	   do is lstat() the file, open it as appropriate, and if it's an
	   existing file ftstat() it and compare various important fields to make
	   sure the file wasn't changed between the lstat() and the open().  If
	   everything is OK, we then use the lstat() information to make sure it
	   isn't a symlink (or at least that it's a normal file) and that the
	   link count is 1.  These checks also catch other weird things like
	   STREAMS stuff fattach()'d over files.

	   If these checks pass and the file already exists we truncate it to
	   mimic the effect of an open with create.  Finally, we use fdopen() to
	   convert the file handle for stdio use */
#ifdef __UNIX__
	if( ( mode & FILE_RW_MASK ) == FILE_WRITE )
		{
		struct stat lstatInfo;
		char *mode = "rb+";
		int fd;

		/* lstat() the file.  If it doesn't exist, create it with O_EXCL.  If
		   it does exist, open it for read/write and perform the fstat()
		   check */
		if( lstat( fileName, &lstatInfo ) == -1 )
			{
			/* If the lstat() failed for reasons other than the file not
			   existing, return a file open error */
			if( errno != ENOENT )
				return( CRYPT_ERROR_OPEN );

			/* The file doesn't exist, create it with O_EXCL to make sure an
			   attacker can't slip in a file between the lstat() and open() */
			if( ( fd = open( fileName, O_CREAT | O_EXCL | O_RDWR, 0600 ) ) == -1 )
				return( CRYPT_ERROR_OPEN );
			mode = "wb";
			}
		else
			{
			struct stat fstatInfo;

			/* Open an existing file */
			if( ( fd = open( fileName, O_RDWR ) ) == -1 )
				return( CRYPT_ERROR_OPEN );

			/* fstat() the opened file and check that the file mode bits and
			   inode and device match */
			if( fstat( fd, &fstatInfo ) == -1 || \
				lstatInfo.st_mode != fstatInfo.st_mode || \
				lstatInfo.st_ino != fstatInfo.st_ino || \
				lstatInfo.st_dev != fstatInfo.st_dev )
				{
				close( fd );
				return( CRYPT_ERROR_OPEN );
				}

			/* If the above check was passed, we know that the lstat() and
			   fstat() were done to the same file.  Now check that there's
			   only one link, and that it's a normal file (this isn't
			   strictly necessary because the fstat() vs lstat() st_mode
			   check would also find this) */
			if( fstatInfo.st_nlink > 1 || !S_ISREG( lstatInfo.st_mode ) )
				{
				close( fd );
				return( CRYPT_ERROR_OPEN );
				}

			/* Turn the file into an empty file */
			ftruncate( fd, 0 );
			}

		/* Open a stdio file over the low-level one */
		stream->filePtr = fdopen( fd, mode );
		if( stream->filePtr == NULL )
			{
			close( fd );
			unlink( fileName );
			return( CRYPT_ERROR_OPEN );
			}
		}
	else
#endif /* __UNIX__ */
#if defined( __UNIX__ ) || defined( __MSDOS16__ ) || defined( __WIN16__ ) || \
	defined( __OS2__ )
	/* Try and open the file */
	stream->filePtr = fopen( fileName, openMode );
	if( stream->filePtr == NULL )
		/* The open failed, determine whether it was because the file doesn't
		   exist or because we can't use that access mode */
		return( ( access( fileName, 0 ) == -1 ) ? \
				CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_OPEN );
#elif defined( __TANDEM__ )
	stream->filePtr = fopen( fileName, openMode );
	if( stream->filePtr == NULL )
		return( ( errno == ENOENT ) ? \
				CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_OPEN );
#else
  #error Need to add file accessibility call
#endif /* OS-specific file accessibility check */

	/* Set the file access permissions so only the owner can access it if
	   necessary */
#if defined( __UNIX__ )
	if( mode & FILE_PRIVATE )
		chmod( fileName, 0600 );
#endif /* __UNIX__ */

	/* Lock the file if necessary to make sure noone else tries to do things
	   to it.  We don't do anything fancy with timeouts and whatnot because
	   no process should ever lock the file for more than a fraction of a
	   second */
#ifdef __UNIX__
	/* Place a simple advisory lock on the file.  We don't use the more
	   complex lockf() because it's probably overkill for something this
	   simple, and because there are all sorts of weird variations (mainly in
	   the use of header files) of this floating around */
	flock( fileno( stream->filePtr ), LOCK_SH );
#endif /* __UNIX__ */

	return( CRYPT_OK );
	}
#endif /* __WIN32__ */

/* Close a file stream */

int sFileClose( STREAM *stream )
	{
	int status;

#ifdef NO_STDIO
	assert( stream != NULL && !stream->isNull );
#else
	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );
#endif /* NO_STDIO */

	/* Commit the data before we close the stream */
	status = sflush( stream );

	/* Close the file and clear the stream structure */
#if defined( __WIN32__ )
	CloseHandle( stream->hFile );
#elif defined( __MAC__ )
	FSClose( stream->refNum );
#elif defined( NO_STDIO )
	zeroise( stream->buffer, stream->bufSize );
	free( stream->buffer );
#else
	/* Unlock the file if necessary */
  #ifdef __UNIX__
	flock( fileno( stream->filePtr ), LOCK_UN );
  #endif /* __UNIX__ */
	fclose( stream->filePtr );
#endif /* __WIN32__ */
	zeroise( stream, sizeof( STREAM ) );

	return( status );
	}

/****************************************************************************
*																			*
*							Misc Oddball File Routines 						*
*																			*
****************************************************************************/

/* BC++ 3.1 is rather anal-retentive about not allowing extensions when in
   ANSI mode */

#if defined( __STDC__ ) && ( __BORLANDC__ == 0x410 )
  #define fileno( filePtr )		( ( filePtr )->fd )
#endif /* BC++ 3.1 in ANSI mode */

/* When checking whether a file is readonly we also have to check (via errno)
   to make sure the file actually exists since the access check will return a
   false positive for a nonexistant file */

#if defined( __MSDOS16__ ) || defined( __OS2__ ) || defined( __WIN16__ )
  #include <errno.h>
#endif /* __MSDOS16__ || __OS2__ || __WIN16__ */

/* Some OS's don't define W_OK for the access check */

#ifndef W_OK
  #define W_OK	2
#endif /* W_OK */

/* Check whether a file is writeable */

BOOLEAN fileReadonly( const char *fileName )
	{
#if defined( __UNIX__ ) || defined( __MSDOS16__ ) || defined( __WIN16__ ) || \
	defined( __OS2__ )
	if( access( fileName, W_OK ) == -1 && errno != ENOENT )
		return( TRUE );
#elif defined( __WIN32__ )
	HANDLE hFile;

	assert( fileName != NULL );

	/* The only way to tell whether a file is writeable is to try to open it
	   for writing */
	hFile = CreateFile( fileName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, NULL );
	if( hFile == INVALID_HANDLE_VALUE )
		{
		DWORD errorCode = GetLastError();

		/* Translate the Win32 error code into an equivalent cryptlib error
		   code */
		if( errorCode == ERROR_ACCESS_DENIED )
			return( TRUE );
		return( FALSE );
		}
	CloseHandle( hFile );
#elif defined( __TANDEM )
	FILE *filePtr;

	if( ( filePtr = fopen( fileName, "rb+" ) ) == NULL )
		{
		if( errno == EACCES )
			return( TRUE );
		}
	else
		fclose( filePtr );
#elif defined( __MAC__ )
	Str255 pFileName;
	FSSpec fsspec;
	OSErr err;
	short refnum;

	assert( fileName != NULL );

	CStringToPString( fileName, &pFileName );

	err = FSMakeFSSpec(0, 0, &pFileName, &fsspec );
	if ( !err )
		err = FSpOpenDF( &fsspec, fsRdWrPerm, &refnum );
	if ( !err )
		FSClose( refnum );

	if ( err == opWrErr || err == permErr || err == afpAccessDenied )
		return( TRUE );
#elif defined( NO_STDIO )
	/* Since there's no filesystem, there's no concept of a read-only
	   file - all data items are always accessible */
	return( FALSE );
#else
  #error Need to add file accessibility call
#endif /* OS-specific file accessibility check */

	return( FALSE );
	}

/* File deletion functions: Unlink a file, wipe a file from the current 
   position to EOF, and wipe and delete a file (although it's not terribly 
   rigorous).  Vestigia nulla retrorsum */

void fileUnlink( const char *fileName )
	{
#if defined( __MAC__ )
	FSSpec fsspec;
	Str255 pFileName;
#endif /* __MAC__ */

	assert( fileName != NULL );

#if defined( __WIN32__ )
	DeleteFile( fileName );
#elif defined( __MAC__ )
	CStringToPString( fileName, pFileName );
	if( !FSMakeFSSpec( 0, 0, pFileName, &fsspec ) )
		FSpDelete( &fsspec );
#elif defined( NO_STDIO )
  #if defined( __IBM4758__ )
	sccDeletePPD( ( char * ) fileName );
  #elif defined( __VMCMS__ )
	remove( fileName );
  #else
	#error Need to add file unlink call
  #endif /* Nonstandard I/O enviroments */
#else
	remove( fileName );
#endif /* OS-specific file unlink calls */
	}

#if defined( __WIN32__ )

void fileClearToEOF( const STREAM *stream )
	{
	BYTE buffer[ BUFSIZ * 2 ];
	long position, length;

	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );

	/* Wipe everything past the current position in the file */
	if( ( position = SetFilePointer( stream->hFile, 0, NULL, 
									 FILE_CURRENT ) ) == 0xFFFFFFFF )
		return;
	length = GetFileSize( stream->hFile, NULL ) - position;
	if( !length )
		return;		/* Nothing to do, exit */
	while( length > 0 )
		{
		DWORD bytesWritten;
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesToWrite );
		WriteFile( stream->hFile, buffer, bytesToWrite, &bytesWritten, NULL );
		length -= bytesToWrite;
		}

	/* Truncate the file at the last write position */
	SetFilePointer( stream->hFile, position, NULL, FILE_BEGIN );
	SetEndOfFile( stream->hFile );
	}

#elif defined( __MAC__ )

void fileClearToEOF( const STREAM *stream )
	{
	char buffer[ BUFSIZ * 2 ];
	long position, eof, length;

	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );
	
	if( GetFPos( stream->refNum, &position ) || GetEOF( stream->refNum, &eof ) )
		return;
	
	if( !( length = eof - position ) )
		return;	/* Position already at EOF */
	
	while( length > 0 )
		{
		long bytesWritten = min( length, BUFSIZ * 2 );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesWritten );
		if( FSWrite( stream->refNum, &bytesWritten, buffer ) )
			return; /* An error occurred while writing */
		length -= bytesWritten;
		}
	}

#elif defined( NO_STDIO )

void fileClearToEOF( const STREAM *stream )
	{
#if defined( __IBM4758__ ) || defined( __VMCMS__ )
	/* Data updates on these systems are atomic so there's no remaining data
	   left to clear */
	UNUSED( stream );
#else
  #error Need to add file clear-to-EOF call
#endif /* Nonstandard I/O enviroments */
	}

#else

void fileClearToEOF( const STREAM *stream )
	{
	BYTE buffer[ BUFSIZ * 2 ];
	const int fileHandle = fileno( stream->filePtr );
	long position, length;

	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );

	/* Figure out how big the file is */
	position = ftell( stream->filePtr );
	fseek( stream->filePtr, 0, SEEK_END );
	length = ftell( stream->filePtr ) - position;
	fseek( stream->filePtr, position, SEEK_SET );

	/* Wipe everything past the current position in the file */
	while( length > 0 )
		{
		int bytesToWrite = min( length, BUFSIZ * 2 );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesToWrite );
		fwrite( buffer, 1, bytesToWrite, stream->filePtr );
		length -= bytesToWrite;
		}
	fflush( stream->filePtr );
#ifdef __UNIX__
	fsync( fileHandle );
#endif /* __UNIX__ */

	/* Truncate the file at the last write position */
#if defined( __UNIX__ )
	ftruncate( fileHandle, position );
#elif defined( __AMIGA__ )
	SetFileSize( fileHandle, OFFSET_BEGINNING, position );
#elif defined( __MSDOS16__ ) || defined( __MSDOS32__ )	/* djgpp libc.a */
	chsize( fileHandle, position );
#elif defined( __OS2__ )
	DosSetFileSize( fileHandle, position );
#elif defined( __WIN16__ )
	_chsize( fileHandle, position );
#endif /* OS-specific size mangling */
	}
#endif /* OS-specific file wiping */

#if defined( __WIN32__ )

void fileErase( STREAM *stream, const char *fileName )
	{
	BYTE buffer[ BUFSIZ ];
	int length;

	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );
	assert( fileName != NULL );

	/* Wipe the file */
	SetFilePointer( stream->hFile, 0, NULL, FILE_BEGIN );
	length = GetFileSize( stream->hFile, NULL );
	while( length )
		{
		DWORD bytesWritten;
		int bytesToWrite = min( length, BUFSIZ );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesToWrite );
		WriteFile( stream->hFile, buffer, bytesToWrite, &bytesWritten, NULL );
		length -= bytesToWrite;
		}

	/* Truncate the file to 0 bytes, reset the timestamps, and delete the
	   file.  The delete just marks the file as deleted rather than actually
	   deleting it, but there's not much information which can be recovered
	   without a magnetic force microscope.  The call to FlushFileBuffers()
	   ensures that the changed data gets committed before the delete call
	   comes along, if we didn't do this then the OS would drop all changes
	   once DeleteFile() was called, leaving the original more or less intact
	   on disk */
	SetFilePointer( stream->hFile, 0, NULL, FILE_BEGIN );
	SetEndOfFile( stream->hFile );
	SetFileTime( stream->hFile, 0, 0, 0 );
	FlushFileBuffers( stream->hFile );
	CloseHandle( stream->hFile );
	DeleteFile( fileName );
	}

#elif defined( __MAC__ )

void fileErase( STREAM *stream, const char *fileName )
	{
	BYTE buffer[ BUFSIZ ];
	long length;

	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );

	/* Wipe the file */
	SetFPos( stream->refNum, fsFromStart, 0 );
	GetEOF( stream->refNum, &length );
	while( length )
		{
		long bytesWritten = min( length, BUFSIZ );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesWritten );
		if( FSWrite( stream->refNum, &bytesWritten, buffer ) )
			length = 0; /* an error has occurred while writing */
		else
			length -= bytesWritten;
		}

	/* Truncate the file to 0 bytes, and delete the file. */
	SetFPos( stream->refNum, fsFromStart, 0 );
	SetEOF( stream->refNum, 0 );
	FSClose( stream->refNum );
	FSpDelete( &stream->fsspec );
	}

#elif defined( NO_STDIO )

void fileErase( STREAM *stream, const char *fileName )
	{
#if defined( __IBM4758__ )
	fileUnlink( fileName );
#elif defined( __VMCMS__ )
	FILE *filePtr;
	int length = CRYPT_ERROR;

	assert( stream != NULL && !stream->isNull );
	assert( fileName != NULL );

	/* Determine how large the file is */
	filePtr = fopen( fileName, "rb+" );
	if( filePtr != NULL )
		{
		fldata_t fileData;
		char fileBuffer[ MAX_PATH_LENGTH ];
		int status;

		status = fldata( filePtr, fileBuffer, &fileData );
		fclose( filePtr );
		if( status == 0 )
			length = fileData.__maxreclen;
		}

	/* If we got a length, overwrite the data.  Since the file contains a
	   single record we can't do the write-until-done overwrite used on
	   other OS's, however since we're only going to be deleting short
	   private key files using the default stream buffer is OK for this */
	if( length != CRYPT_ERROR )
		{
		BYTE buffer[ STREAM_BUFSIZE ];

		length = max( length, STREAM_BUFSIZE );
		getNonce( buffer, length );
		fwrite( buffer, 1, length, filePtr );
		}
	if( filePtr != NULL )
		fclose( filePtr );

	fileUnlink( fileName );
#else
  #error Need to add file erase call
#endif /* Nonstandard I/O enviroments */
	}

#else

void fileErase( STREAM *stream, const char *fileName )
	{
#if defined( __UNIX__ )
	struct utimbuf timeStamp;
#elif defined( __AMIGA__ )
	struct DateStamp dateStamp;
#elif defined( __MSDOS16__ ) || defined( __MSDOS32__ )
	struct ftime fileTime;
#elif defined( __OS2__ )
	FILESTATUS info;
#elif defined( __WIN16__ )
	HFILE hFile;
#endif /* OS-specific file access structures */
	BYTE buffer[ BUFSIZ ];
	const int fileHandle = fileno( stream->filePtr );
	int length;

	assert( stream != NULL && !stream->isNull && !sIsMemoryStream( stream ) );
	assert( fileName != NULL );

	/* Figure out how big the file is */
	fseek( stream->filePtr, 0, SEEK_END );
	length = ( int ) ftell( stream->filePtr );
	fseek( stream->filePtr, 0, SEEK_SET );

	/* Wipe the file.  This is a fairly crude function which performs a
	   single pass of overwriting the data with random data, it's not
	   possible to do much better than this without getting terribly OS-
	   specific.  Under Win95 and NT it wouldn't have much effect at all
	   since the file buffering is such that the file delete appears before
	   the OS buffers has been flushed, so the OS never bothers writing the
	   data.  For this reason we use different code for Win32 which uses a
	   low-level function which forces a disk buffer flush.

	   You'll NEVER get rid of me, Toddy */
	while( length )
		{
		int bytesToWrite = min( length, BUFSIZ );

		/* We need to make sure we fill the buffer with random data for each
		   write, otherwise compressing filesystems will just compress it to
		   nothing */
		getNonce( buffer, bytesToWrite );
		fwrite( buffer, 1, bytesToWrite, stream->filePtr );
		length -= bytesToWrite;
		}
	fflush( stream->filePtr );
#ifdef __UNIX__
	fsync( fileHandle );
#endif /* __UNIX__ */

	/* Truncate the file to 0 bytes, reset the time stamps, and delete it */
#if defined( __UNIX__ )
	ftruncate( fileHandle, 0 );
#elif defined( __AMIGA__ )
	SetFileSize( fileHandle, OFFSET_BEGINNING, 0 );
#elif defined( __MSDOS16__ ) || defined( __MSDOS32__ )	/* djgpp libc.a */
	chsize( fileHandle, 0 );
	memset( &fileTime, 0, sizeof( struct ftime ) );
	setftime( fileHandle, &fileTime );
#elif defined( __OS2__ )
	DosSetFileSize( fileHandle, 0 );
#endif /* OS-specific size and date-mangling */
	sFileClose( stream );
#if defined( __UNIX__ )
	timeStamp.actime = timeStamp.modtime = 0;
	utime( fileName, &timeStamp );
#elif defined( __AMIGA__ )
	memset( dateStamp, 0, sizeof( struct DateStamp ) );
	SetFileDate( fileName, &dateStamp );
#elif defined( __OS2__ )
	DosQueryPathInfo( ( PSZ ) fileName, FIL_STANDARD, &info, sizeof( info ) );
	memset( &info.fdateLastWrite, 0, sizeof( info.fdateLastWrite ) );
	memset( &info.ftimeLastWrite, 0, sizeof( info.ftimeLastWrite ) );
	memset( &info.fdateLastAccess, 0, sizeof( info.fdateLastAccess ) );
	memset( &info.ftimeLastAccess, 0, sizeof( info.ftimeLastAccess ) );
	memset( &info.fdateCreation, 0, sizeof( info.fdateCreation ) );
	memset( &info.ftimeCreation, 0, sizeof( info.ftimeCreation ) );
	DosSetPathInfo( ( PSZ ) fileName, FIL_STANDARD, &info, sizeof( info ), 0 );
#elif defined( __WIN16__ )
	/* Under Win16 we can't really do anything without resorting to MSDOS int
	   21h calls, the best we can do is truncate the file using _lcreat() */
	hFile = _lcreat( fileName, 0 );
	if( hFile != HFILE_ERROR )
		_lclose( hFile );
#endif /* OS-specific size and date-mangling */

	/* Finally, delete the file */
	remove( fileName );
	}
#endif /* OS-specific file wiping */
