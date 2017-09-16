/****************************************************************************
*																			*
*					cryptlib Randomness Management Header File				*
*						 Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

#ifndef _RANDOM_DEFINED

#define _RANDOM_DEFINED

/* For systems which don't support background randomness gathering the
   routine to wait for the completion of the polling does nothing */

#if !defined( __WIN32__ ) && !defined( __UNIX__ )
  #define waitforRandomCompletion()
#endif /* !( __WIN32__ || __UNIX__ ) */

/* For systems which don't require special-case initialisation for threading
   support, the routine to initialise and clean up special objects does 
   nothing */

#if !defined( __WIN32__ ) && !defined( __UNIX__ )
  #define initRandomPolling()
  #define endRandomPolling()
#endif /* !( __WIN32__ || __UNIX__ ) */

/* The size of the randomness pool */

#define RANDOMPOOL_SIZE			256

/* The allocated size if the randomness pool, which allows for the overflow
   created by the fact that the hash function blocksize isn't any useful 
   multiple of a power of 2 */

#define RANDOMPOOL_ALLOCSIZE	( ( ( RANDOMPOOL_SIZE + 20 - 1 ) / 20 ) * 20 )

/* The number of samples of previous output we keep for the FIPS 140 
   continuous tests, and the number of retries we perform if we detect a
   repeat of a previous output */

#define RANDOMPOOL_SAMPLES		16
#define RANDOMPOOL_RETRIES		5

/* In order to avoid the pool startup problem (where initial pool data may
   consist of minimally-mixed entropy samples) we require that the pool be
   mixed at least the following number of times before we can draw data from
   it.  This usually happens automatically because a slow poll adds enough
   data to cause many mixing iterations, however if this doesn't happen we
   manually mix it the appropriate number of times to get it up to the
   correct level */

#define RANDOMPOOL_MIXES		10

/* Random pool information, pagelocked in memory to ensure it never gets 
   swapped to disk.  We keep track of the write position in the pool, which 
   tracks where new data is added.  Whenever we add new data the write
   position is updated, once we reach the end of the pool we mix the pool 
   and start again at the beginning.  In addition we track the pool status
   by recording the quality of the pool contents (1-100) and the number of
   times the pool has been mixed, we can't draw data from the pool unless
   both of these values have reached an acceptable level.
   
   In addition to the pool state information we keep track of the previous
   RANDOMPOOL_SAMPLES output samples to check for stuck-at faults or (short)
   cyles */

typedef struct {
	/* Pool state information */
	BYTE randomPool[ RANDOMPOOL_ALLOCSIZE ];	/* Random byte pool */
	int randomPoolPos;		/* Current write position in the pool */

	/* Pool status information */
	int randomQuality;		/* Whether there's any randomness in the pool */
	int randomPoolMixes;	/* Number of times pool has been mixed */

	/* Information for FIPS 140 continuous tests */
	LONG prevOutput[ RANDOMPOOL_SAMPLES ];
	int prevOutputIndex;
	} RANDOM_INFO;

/* In order to make it easier to add lots of arbitrary-sized values, we make 
   the following functions available to the polling code to implement a 
   clustered-write mechanism for small data quantities.  These add an integer 
   or string to a buffer and send it through to the randomness device when 
   the buffer is full.  A call with a string of (NULL, 0) flushes any 
   remaining data through.  The method of use is:

	BYTE buffer[ RANDOM_BUFSIZE ];
	int bufIndex = 0;

	addRandom( buffer, &bufIndex, ... );
	addRandomString( buffer, &bufIndex, ... );
	[...]
	addRandomString( buffer, &bufIndex, NULL, 0 );
	
   Using the intermediate buffer ensures we don't have to send a message to 
   the device for every bit of data added */

#define RANDOM_BUFSIZE	512

#define addRandom( buffer, bufIndex, value ) \
		addRandomLong( buffer, bufIndex, ( long ) value );
void addRandomLong( BYTE *buffer, int *bufIndex, const long value );
void addRandomString( BYTE *buffer, int *bufIndex, const void *value, 
					  const int valueLength );

/* Prototypes for functions in the OS-specific randomness polling routines */

void slowPoll( void );
void fastPoll( void );
#if defined( __WIN32__ ) || defined( __UNIX__ )
  void waitforRandomCompletion( void );
#endif /* __WIN32__ || __UNIX__ */
#if defined( __WIN32__ )
  void initRandomPolling( void );
  void endRandomPolling( void );
#endif /* __WIN32__ */
#if defined( __OS2__ )
  ULONG DosGetThreadID( void );
#endif  /* __OS2__ */
#endif /* _RANDOM_DEFINED */
