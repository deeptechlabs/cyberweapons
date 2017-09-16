/****************************************************************************
*																			*
*						STREAM Class Constants and Structures				*
*						  Copyright Peter Gutmann 1993-1996					*
*																			*
****************************************************************************/

#ifndef _STREAM_DEFINED

#define _STREAM_DEFINED

#if defined( INC_ALL )
  #include "crypt.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */
#ifdef __MAC__		/* Must be after the crypt.h include */
  #include <Files.h>
#else
  #include <stdio.h>
#endif /* __MAC__ */

/****************************************************************************
*																			*
*								STREAM Constants							*
*																			*
****************************************************************************/

/* Occasionally we want to connect a memory stream to a fixed-length buffer
   whose size is "big enough for the data it needs to hold", but of an
   unknown length.  Using the following as the length will avoid various
   checks on the input length */

#define STREAMSIZE_UNKNOWN		-1

/* Access/option flags for the file stream open call.  The difference between
   the private and sensitive flags is that some data may be private for a
   given user but not sensitive (eg config info) while other data may be
   private and sensitive (eg private keys).  The sensitive flag only has an
   effect on special systems where data can be committed to secure storage,
   since there's usually a very limited amount of this available we only use
   it for sensitive data but not generic private data */

#define FILE_READ		1			/* Open file for read access */
#define FILE_WRITE		2			/* Open file for write access */
#define FILE_PRIVATE	4			/* Set ACL's to allow owner access only */
#define FILE_SENSITIVE	8			/* File contains sensitive data */
#define FILE_RW_MASK	3			/* Mask for R/W bits */

/****************************************************************************
*																			*
*							STREAM Class Structures							*
*																			*
****************************************************************************/

/* The STREAM data type */

typedef struct {
	/* Information for memory I/O */
	BYTE *buffer;				/* Buffer to R/W to */
	int bufSize;				/* Total size of buffer */
	int bufPos;					/* Current position in buffer */
	int bufEnd;					/* Last buffer position with valid data */

	/* Information for file I/O */
#if defined( __WIN32__ )
	HANDLE hFile;				/* The file associated with this stream */
#elif defined( __IBM4758__ ) || defined( __VMCMS__ )
	char name[ FILENAME_MAX ];	/* Data item associated with stream */
	BOOLEAN isIOStream;			/* Whether stream is an emulated I/O stream */
	BOOLEAN isSensitive;		/* Whether stream contains sensitive data */
#elif defined( __MAC__ )
	short refNum;				/* The file stream reference number */
	FSSpec fsspec;				/* The file system specification */
#else
	FILE *filePtr;				/* The file associated with this stream */
#endif /* __WIN32__ */

	/* General information for the stream */
	BOOLEAN isNull;				/* Whether this is a null stream */
	BOOLEAN isDirty;			/* Whether stream data has changed */
	int status;					/* Current stream status (clib error code) */
	int lastChar;				/* Last char read, for ungetc() function */
	int ungetChar;				/* Whether we need to return lastChar next */
	} STREAM;

/****************************************************************************
*																			*
*							STREAM Class Function Prototypes				*
*																			*
****************************************************************************/

/* Functions corresponding to traditional/stdio-type I/O */

int sputc( STREAM *stream, int data );
int sgetc( STREAM *stream );
int sungetc( STREAM *stream );
int sread( STREAM *stream, void *buffer, int length );
int swrite( STREAM *stream, const void *buffer, const int length );
int sflush( STREAM *stream );
int sseek( STREAM *stream, const long position );
long stell( STREAM *stream );

/* Skip a number of bytes in a stream */

int sSkip( STREAM *stream, const long length );

/* Inquire as to the health of a stream */

#define sGetStatus( stream )		( stream )->status

/* Set/clear user-defined error state for the stream.  The reason for the
   slightly convoluted code in sSetError() is because a conventional if
   statement would cause problems with dangling elses */

#define sSetError( stream, error )	( stream )->status = \
										( ( stream )->status == CRYPT_OK ) ? \
										( error ) : ( stream )->status
#define sClearError( stream )		( stream )->status = CRYPT_OK

/* Stream query functions to determine whether a stream is a memory stream
   (if it has a nonzero associated memory buffer, it's a memory stream), a
   null stream, or out of data */

#define sIsMemoryStream( stream )	( stream )->bufSize
#define sIsNullStream( stream )		( stream )->isNull
#define sIsEmpty( stream )			( stream )->status == CRYPT_ERROR_UNDERFLOW

/* Determine the total size of a memory stream and return a pointer to the
   current position in a streams internal memory buffer.  The latter is used
   by some routines which need to process data in a stream buffer after it's
   been written to the wire format */

#define sMemBufSize( stream )	( ( stream )->bufSize )
#define sMemBufPtr( stream )	( ( stream )->isNull ? NULL : \
								  ( stream )->buffer + ( stream )->bufPos - \
									( stream )->ungetChar )

/* Functions to work with memory streams */

int sMemOpen( STREAM *stream, void *buffer, const int length );
int sMemClose( STREAM *stream );
int sMemConnect( STREAM *stream, const void *buffer, const int length );
int sMemDisconnect( STREAM *stream );

/* Functions to work with file streams */

int sFileOpen( STREAM *stream, const char *fileName, const int mode );
int sFileClose( STREAM *stream );

/* Special-case file I/O calls */

BOOLEAN fileReadonly( const char *fileName );
void fileClearToEOF( const STREAM *stream );
void fileUnlink( const char *fileName );

#endif /* _STREAM_DEFINED */
