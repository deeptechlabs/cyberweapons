/****************************************************************************
*																			*
*					  cryptlib Internal General Header File 				*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _CRYPT_DEFINED

#define _CRYPT_DEFINED

/* Various compilers handle includes in subdirectories differently.  Most
   will work with paths from a root directory.  Macintoshes don't recognise
   '/'s as path delimiters, but work around it by scanning all subdirectories
   and treating the files as if they were in the same directory (INC_ALL).
   Microsoft C, in a braindamaged exception to all other compilers, treats
   the subdirectory as the root (INC_CHILD).  The Tandem NSK doesn't have
   subdirectories, and the C compiler zaps '.'s, truncates filenames to 7
   characters, and appends a 'h' to the name (so that asn1misc.h becomes
   asn1mish).  This unfortunately requires a bit of renaming for header
   files.

   There are also a few systems which have somewhat special requirements,
   these get their own OS-specific include defines */

#if ( defined( __MWERKS__ ) || defined( SYMANTEC_C ) || defined( __BEOS__ ) ) && \
	!defined( INC_ALL )
  #error You need to predefine INC_ALL in your project file
#elif defined( _MSC_VER ) && !defined( INC_CHILD )
  #error You need to predefine INC_CHILD in your project/make file
#elif defined( __TANDEM ) && !defined( INC_ALL )
  #error You need to predefine INC_NSK in your project/make file
#endif /* Checks for various compiler/OS-dependant include paths */

/* If we're on a new enough version of VC++, set a flag to only include
   header files once */

#if defined( _MSC_VER ) && ( _MSC_VER >= 1000 )
  #pragma once
#endif /* VC++ 5.0 or higher */

/* If the global crypt API header hasn't been included yet, include it now */

#ifndef _CAPI_DEFINED
  #include "capi.h"
#endif /* _CAPI_DEFINED */

/* It's possible to disable certain of the less-useful and patented
   algorithms to reduce the size of the code and/or eliminate problems due to
   patents.  Defining any of the following will eliminate the corresponding
   algorithm from the code (at the moment we just allow the entire block to
   be disabled with the CRYPTLIB_LITE define).  We also automatically define
   CRYPTLIB_LITE under 16-bit DOS to conserve memory, since this saves about
   60K.

   Although it would be nice to remove IDEA as well, it's needed for PGP 2.x
   private keyring reads so we leave it in place - if you remove IDEA, the
   ability to read PGP 2.x private keyrings will go as well.  CAST is
   excluded from the lite version not because of any problems but because of
   the huge S-boxes */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define CRYPTLIB_LITE
#endif /* __MSDOS__ && !__MSDOS32__ */

#ifdef CRYPTLIB_LITE
  #define NO_CAST
  #define NO_ELGAMAL
  #define NO_HMAC_MD5
  #define NO_HMAC_RIPEMD160
  #define NO_IDEA
  #define NO_MD4
  #define NO_MDC2
  #define NO_RC2
  #define NO_RC4
  #define NO_RC5
  #define NO_SAFER
  #define NO_SKIPJACK
#endif /* CRYPTLIB_LITE */

/****************************************************************************
*																			*
*								OS-Specific Defines							*
*																			*
****************************************************************************/

/* To build the static .LIB under Win32, uncomment the following define (this
   it not recommended since the init/shutdown is no longer thread-safe).  In
   theory it should be possible to detect the build of a DLL vs a LIB with
   the _DLL define which is set when the /MD (multithreaded DLL) option is 
   used, however fscking VC++ only defines _DLL when /MD is used *and* it's
   linked with the MT DLL runtime.  If it's linked with the statically
   linked runtime, _DLL isn't defined, which would result in the unsafe
   LIB version being built as a DLL */

/* #define STATIC_LIB */

/* Try and figure out if we're running under Windows and/or Win32.  We have
   to jump through all sorts of hoops later on, not helped by the fact that
   the method of detecting Windows at compile time changes with different
   versions of Visual C (it's different for each of VC 2.0, 2.1, 4.0, and
   4.1.  It actually remains the same from 4.1 to 4.2) */

#if !defined( __WINDOWS__ ) && ( defined( _Windows ) || defined( _WINDOWS ) )
  #define __WINDOWS__
#endif /* !__WINDOWS__ && ( _Windows || _WINDOWS ) */
#if !defined( __WIN32__ ) && ( defined( WIN32 ) || defined( _WIN32 ) )
  #ifndef __WINDOWS__
	#define __WINDOWS__
  #endif /* __WINDOWS__ */
  #define __WIN32__
#endif /* !__WIN32__ && ( WIN32 || _WIN32 ) */
#if defined( __WINDOWS__ ) && !defined( __WIN32__ )
  #define __WIN16__
#endif /* __WINDOWS__ && !__WIN32__ */

/* Fix up a type clash with a Windows predefined type - for some reason BYTE
   and WORD are unsigned, but LONG is signed (actually DWORD is the Windows
   unsigned type, the counterpoint CHAR, SHORT and LONG types are all signed,
   but DWORD is a Windows-ism which all the Unix types will LART me for if I
   start using it).  Some OS/2 compilers can do this as well */

#if defined( __WINDOWS__ ) || defined( __OS2__ )
  #undef LONG
#endif /* __WINDOWS__ || __OS2__ */

/* If we're compiling under VC++ with the maximum level of warning, turn off
   some of the more irritating warnings */

#if defined( _MSC_VER )
  #pragma warning( disable: 4057 )	/* Conv from char * to char[] or BYTE * */
  #pragma warning( disable: 4127 )	/* Conditional is constant: while( TRUE ) */
  #pragma warning( disable: 4201 )	/* Nameless union in Windows header file */
  #pragma warning( disable: 4244 )	/* Conv from int to BYTE */
#endif /* _MSC_VER */

/* If we're using a DOS compiler and it's not a 32-bit one, record this.
   __MSDOS__ is predefined by a number of compilers, so we use __MSDOS16__
   for stuff which is 16-bit DOS specific, and __MSDOS32__ for stuff which
   is 32-bit DOS specific */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* __MSDOS__ && !__MSDOS32__ */

/* Make the Tandem NSK define look a bit more like the usual ANSI defines
   used to identify the other OS types */

#ifdef __TANDEM
  #define __TANDEM__
#endif /* __TANDEM */

/* Some encryption algorithms which rely on longints having 32 bits won't
   work on 64- or 128-bit machines due to problems with sign extension and
   whatnot.  The following define can be used to enable special handling for
   processors with a > 32 bit word size */

#include <limits.h>
#if ULONG_MAX > 0xFFFFFFFFUL
  #define _BIG_WORDS
#endif /* LONG > 32 bits */

/* Some useful types.  We have to jump through all sorts of hoops for
   Windoze */

#ifdef __WIN32__
  #define BOOLEAN			int
#else
  typedef int				BOOLEAN;
#endif /* __WIN32__ */
typedef unsigned char		BYTE;
#if !defined( __WINDOWS__ ) || defined( __WIN32__ )
  typedef unsigned short	WORD;
#endif /* !__WINDOWS__ || __WIN32__ */
#ifdef __WIN32__
  #ifndef __BORLANDC__
	#pragma warning( disable : 4142 )
	typedef unsigned long	LONG;
	#pragma warning( default : 4142 )
  #endif /* __BORLANDC__ */
  #if defined( _WIN32 ) || defined( __BORLANDC__ )
	/* Visual C 2.1+ doesn't seem to like LONG being typedef'd to unsigned
	   no matter what you do, so we rely on the preprocessor to get rid of
	   the problem.  Visual C 2.1+ defined _WIN32 whereas 2.0 defined WIN32,
	   so we can use this to tell the two apart */
	#define LONG	unsigned long
  #endif /* _WIN32 || __BORLANDC__ */
#else
  typedef unsigned long		LONG;
#endif  /* __WIN32__ */

/* If we're building the Win32 kernel driver version, include the DDK
   headers */

#if defined( __WIN32__ ) && defined( NT_DRIVER )
  #include <ntddk.h>
#endif /* __WIN32__  && NT_DRIVER */

/* In 16-bit environments the BSS data is large enough that it overflows the
   (64K) BSS segment.  Because of this we move as much of it as possible into
   its own segment with the following define */

#if defined( __WIN16__ )
  #define FAR_BSS	far
#else
  #define FAR_BSS
#endif /* 16-bit systems */

/* Some newer Unix versions support threads.  The following define enables
   the creation of the multithreaded version of cryptlib unless it's
   specifically disabled with NO_THREADS */

#if defined( __UNIX__ ) && !defined( NO_THREADS )
  #if( ( defined( sun ) && ( OSVERSION > 4 ) ) || defined( __osf__ ) || \
	   defined( __Mach__ ) )
	#define USE_THREADS
  #endif /* Slowaris || OSF1/DEC Unix || Mach */
#endif /* __UNIX__ && !NO_THREADS */

/* Win32 consists of Win95 and WinNT, Win95 doesn't have a number of the
   functions and services which exist in NT so we need to adapt the code
   based on the Win32 variant.  The following flag records which OS variant
   we're crawling under */

#ifdef __WIN32__
  extern BOOLEAN isWin95;
#endif /* __WIN32__ */

/* Boolean constants */

#ifndef TRUE
  #define FALSE			0
  #define TRUE			!FALSE
#endif /* TRUE */

/* If the endianness is not defined and the compiler can tell us what
   endianness we've got, use this in preference to all other methods.  This
   is only really necessary on non-Unix systems since the makefile kludge
   will tell us the endianness under Unix */

#if !defined( DATA_LITTLEENDIAN ) && !defined( DATA_BIGENDIAN )
  #if defined( _M_I86 ) || defined( _M_IX86 ) || defined( __TURBOC__ ) || \
	  defined( __OS2__ )
	#define DATA_LITTLEENDIAN	/* Intel architecture always little-endian */
  #elif defined( AMIGA ) || defined( __MWERKS__ ) || defined( SYMANTEC_C ) || \
		defined( THINK_C ) || defined( applec )
	#define DATA_BIGENDIAN		/* Motorola architecture always big-endian */
  #elif defined( VMS ) || defined( __VMS )
	#define DATA_LITTLEENDIAN	/* VAX architecture always little-endian */
  #elif defined( __TANDEM )
	#define DATA_BIGENDIAN		/* Tandem architecture always big-endian */
  #elif defined __GNUC__
	#ifdef BYTES_BIG_ENDIAN
	  #define DATA_BIGENDIAN	/* Big-endian byte order */
	#else
	  #define DATA_LITTLEENDIAN	/* Undefined = little-endian byte order */
	#endif /* __GNUC__ */
  #endif /* Compiler-specific endianness checks */
#endif /* !( DATA_LITTLEENDIAN || DATA_BIGENDIAN ) */

/* The last-resort method.  Thanks to Shawn Clifford
   <sysop@robot.nuceng.ufl.edu> for this trick.

   NB: A number of compilers aren't tough enough for this test */

#if !defined( DATA_LITTLEENDIAN ) && !defined( DATA_BIGENDIAN )
  #if ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'B' )
	#define DATA_LITTLEENDIAN
  #elif ( ( ( unsigned short ) ( 'AB' ) >> 8 ) == 'A' )
	#define DATA_BIGENDIAN
  #else
	#error Cannot determine processor endianness - edit crypt.h and recompile
  #endif /* Endianness test */
#endif /* !( DATA_LITTLEENDIAN || DATA_BIGENDIAN ) */

/* Some systems define both BIG_ENDIAN and LITTLE_ENDIAN, then define
   BYTE_ORDER to the appropriate one, so we check this and define the
   appropriate value */

#if defined( BIG_ENDIAN ) && defined( LITTLE_ENDIAN ) && defined( BYTE_ORDER )
  #if ( BYTE_ORDER == BIG_ENDIAN ) && !defined( DATA_BIGENDIAN )
	#define DATA_BIGENDIAN
  #else
	#if !defined( DATA_LITTLEENDIAN )
	  #define DATA_LITTLEENDIAN
	#endif /* !DATA_LITTLEENDIAN */
  #endif /* BYTE_ORDER-specific define */
#endif /* LITTLE_ENDIAN && BIG_ENDIAN && BYTE_ORDER */

/* SunOS 4 doesn't have memmove(), but SunOS 5 (Slowaris) does, so we define
   memmove() to bcopy() under 4.  In addition SunOS doesn't define the
   fseek position indicators so we define those as well */

#if defined( __UNIX__ ) && defined( sun ) && ( OSVERSION == 4 )
  #define memmove	bcopy

  #define SEEK_SET	0
  #define SEEK_CUR	1
  #define SEEK_END	2
#endif /* SunOS 4 */

/****************************************************************************
*																			*
*								OS-Specific Macros							*
*																			*
****************************************************************************/

/* cryptlib provides support for a number of extended OS-specific services
   such as multithreading, resource locking, bounds checking, and so on.
   The macros for the OS-specific services are defined in their own include
   file, the following section sets up any which aren't defined to generic
   do-nothing equivalents */

#include "cryptos.h"

/* Check the validity of a pointer passed to a cryptlib function.  Since the
   check can be somewhat slow, we restrict its use to cases where the
   overhead is insignificant and/or where it'll really make a difference, and
   use a quick check for NULL as an alternative */

#define checkBadPtrQ( ptr )			( ptr == NULL )
#ifndef checkBadPtrRead
  #define checkBadPtrRead( ptr, size )	( ptr == NULL )
  #define checkBadPtrWrite( ptr, size )	( ptr == NULL )
#endif /* Pointer check macros */

/* In multithreaded environments we need to protect the information inside
   cryptlib data structures from access by other threads while we use it.
   The following macros handle this resource protection when we enter and
   exit cryptlib functions */

#ifndef DECLARE_RESOURCE_LOCKING_VARS
  #define DECLARE_RESOURCE_LOCKING_VARS
  #define initResourceLock( resource )
  #define deleteResourceLock( resource )
  #define lockResource( resource )
  #define unlockResource( resource )
  #define unlockResourceExit( resource, retCode )				return( retCode )
  #define unlockResourceExit2( resource1, resource2, retCode )	return( retCode )

  #define DECLARE_LOCKING_VARS( name )
  #define DEFINE_LOCKING_VARS( name )
  #define initGlobalResourceLock( name )
  #define deleteGlobalResourceLock( name )
  #define lockGlobalResource( name )
  #define unlockGlobalResource( name )
#endif /* Resource locking macros */

#ifndef DECLARE_OWNERSHIP_VARS
  #define DECLARE_OWNERSHIP_VARS
  #define getCurrentIdentity()					CRYPT_UNUSED
  #define checkResourceOwnership( resource )	TRUE
  #define checkResourceOwned( resource )		FALSE
  #define getResourceOwnership( resource )		CRYPT_UNUSED
  #define setResourceOwnership( resource, owner )

  #define THREAD_HANDLE						int
  #define SEMAPHORE_HANDLE					int
#endif /* Resource ownership macros */

/* Since we typically unlock a resource when we've finished using it, we
   combine the unlock and function exit in one macro.  We also provide a
   macro for unlocking two resources for those functions which manipulate
   two resources at once (eg the export/import functions) */

#ifndef unlockResourceExit				/* May be defined to empty macros */
  #define unlockResourceExit( resource, retCode )	\
		{ \
		unlockResource( resource ); \
		return( retCode ); \
		}
  #define unlockResourceExit2( resource1, resource2, retCode ) \
		{ \
		unlockResource( resource1 ); \
		unlockResource( resource2 ); \
		return( retCode ); \
		}
#endif /* !unlockResourceExit */

/* The following macros process resource ownership information using the
   previously-defined primitives */

#ifndef checkResourceOwnership
  #define checkResourceOwnership( resource ) \
		( ( resource## ).resourceOwner == CRYPT_UNUSED || \
		  ( resource## ).resourceOwner == getCurrentIdentity() )
  #define checkResourceOwned( resource ) \
		( ( resource## ).resourceOwner != CRYPT_UNUSED )
  #define getResourceOwnership( resource ) \
		( resource## )->resourceOwner
  #define setResourceOwnership( resource, owner ) \
		( resource## )->resourceOwner = ( owner )
#endif /* checkResourceOwnership */

/****************************************************************************
*																			*
*								Portability Defines							*
*																			*
****************************************************************************/

/* If we're running on a 64-bit CPU we often need to mask values off to 32
   bits.  The following define enables this if the CPU word size is
   > 64 bits */

#ifdef _BIG_WORDS
  #define MASK32( x )	( ( x ) & 0xFFFFFFFFUL )
#else
  #define MASK32( x )	x
#endif /* _BIG_WORDS */

/* The odd algorithm needs masking to 16 bits */

#if UINT_MAX > 0xFFFFUL
  #define MASK16( x )	( ( x ) & 0xFFFFUL )
#else
  #define MASK16( x )	x
#endif /* > 16-bit ints */

/* If we're running on a machine with > 32 bit wordsize we need to jump
   through all sorts of hoops to convert data from arrays of bytes to arrays
   of longints.  The following macros pull bytes out of memory and assemble
   them into a longword, and deposit a longword into memory as a series of
   bytes.  This code really blows on any processors which need to use it */

#ifdef DATA_BIGENDIAN
	#define mgetLong(memPtr) \
		( ( ( LONG ) memPtr[ 0 ] << 24 ) | ( ( LONG ) memPtr[ 1 ] << 16 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 8 ) | ( ( LONG ) memPtr[ 3 ] ) ); \
		memPtr += 4

	#define mputLong(memPtr,data) \
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4
#else
	#define mgetLong(memPtr) \
		( ( ( LONG ) memPtr[ 0 ] ) | ( ( LONG ) memPtr[ 1 ] << 8 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 16 ) | ( ( LONG ) memPtr[ 3 ] << 24 ) ); \
		memPtr += 4

	#define mputLong(memPtr,data) \
		memPtr[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr += 4
#endif /* DATA_BIGENDIAN */

/* Copy an array of bytes to an array of 32-bit words.  We need to take
   special precautions when the machine word size is > 32 bits because we
   can't just assume BYTE[] == LONG[] */

#ifdef _BIG_WORDS
  #define copyToLong(dest,src,count)	\
					{ \
					LONG *destPtr = ( LONG * ) dest; \
					BYTE *srcPtr = src; \
					int i; \
					for( i = 0; i < count / 4; i++ ) \
						{ \
						destPtr[ i ] = mgetLong( srcPtr ); \
						} \
					}
#else
  #define copyToLong(dest,src,count) \
					memcpy( dest, src, count )
#endif /* _BIG_WORDS */

/* Versions of the above which are guaranteed to always be big or
   little-endian (these are needed for some algorithms where the external
   data format is always little-endian, eg anything designed by Ron
   Rivest) */

#define mgetBWord(memPtr)		\
		( ( WORD ) memPtr[ 0 ] << 8 ) | ( ( WORD ) memPtr[ 1 ] ); \
		memPtr += 2

#define mputBWord(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 2

#define mgetBLong(memPtr)		\
		( ( ( LONG ) memPtr[ 0 ] << 24 ) | ( ( LONG ) memPtr[ 1 ] << 16 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 8 ) | ( LONG ) memPtr[ 3 ] ); \
		memPtr += 4

#define mputBLong(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr += 4

#define mgetLWord(memPtr)		\
		( ( WORD ) memPtr[ 0 ] ) | ( ( WORD ) memPtr[ 1 ] << 8 ); \
		memPtr += 2

#define mputLWord(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr += 2

#define mgetLLong(memPtr)		\
		( ( ( LONG ) memPtr[ 0 ] ) | ( ( LONG ) memPtr[ 1 ] << 8 ) | \
		  ( ( LONG ) memPtr[ 2 ] << 16 ) | ( ( LONG ) memPtr[ 3 ] << 24 ) ); \
		memPtr += 4

#define mputLLong(memPtr,data)	\
		memPtr[ 0 ] = ( BYTE ) ( ( data ) & 0xFF ); \
		memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
		memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
		memPtr[ 3 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
		memPtr += 4

#ifdef _BIG_WORDS
  #define copyToLLong(dest,src,count)	\
					{ \
					LONG *destPtr = ( LONG * ) dest; \
					BYTE *srcPtr = src; \
					int i; \
					for( i = 0; i < count / 4; i++ ) \
						{ \
						destPtr[ i ] = mgetLLong( srcPtr ); \
						} \
					}

  #define copyToBLong(dest,src,count)	\
					{ \
					LONG *destPtr = ( LONG * ) dest; \
					BYTE *srcPtr = src; \
					int i; \
					for( i = 0; i < count / 4; i++ ) \
						{ \
						destPtr[ i ] = mgetBLong( srcPtr ); \
						} \
					}
#endif /* _BIG_WORDS */

/* Functions to convert the endianness from the canonical form to the
   internal form.  bigToLittle() converts from big-endian in-memory to
   little-endian in-CPU, littleToBig() converts from little-endian in-memory
   to big-endian in-CPU */

void longReverse( LONG *buffer, int count );
void wordReverse( WORD *buffer, int count );

#ifdef DATA_LITTLEENDIAN
  #define bigToLittleLong( x, y )	longReverse(x,y)
  #define bigToLittleWord( x, y )	wordReverse(x,y)
  #define littleToBigLong( x, y )
  #define littleToBigWord( x, y )
#else
  #define bigToLittleLong( x, y )
  #define bigToLittleWord( x, y )
  #define littleToBigLong( x, y )	longReverse(x,y)
  #define littleToBigWord( x, y )	wordReverse(x,y)
#endif /* DATA_LITTLEENDIAN */

/****************************************************************************
*																			*
*						Data Size and Crypto-related Constants				*
*																			*
****************************************************************************/

/* The size of a cryptlib key ID, an SHA-1 hash as per assorted X.509
   profiles */

#define KEYID_SIZE				20

/* The maximum private key data size.  This is used when buffering the last
   read private key from a keyset in case the password used to decrypt it is
   incorrect, and is equal to the overall size of the total number of
   possible PKC parameters in an encryption context, plus a little extra for
   encoding and encryption */

#define MAX_PRIVATE_KEYSIZE		( ( CRYPT_MAX_PKCSIZE * 8 ) + 256 )

/* The maximum public-key object size.  This is used to allocate temporary
   buffers when working with signatures and PKC-encrypted keys.  The size
   estimate is somewhat crude and involves a fair safety margin, it usually
   contains a single PKC object (signature or encrypted key) along with
   algorithm and key ID information */

#define MAX_PKC_OBJECTSIZE		( CRYPT_MAX_PKCSIZE * 2 )

/* The minimum size of an encoded signature or exported key object.  This is
   used by the pointer-check macros (for the OS's which support this) to
   check that the pointers to objects which are passed to functions point to
   the minimal amount of valid memory required for an object */

#define MIN_CRYPT_OBJECTSIZE	64

/* A special return code to inform asynchronous routines to abort the
   operation currently in progress */

#define ASYNC_ABORT				-1234

/* A special return code to indicate that everything went OK but there's
   some special action to perform.  This is generally used when a lower-level
   routine wants to return a CRYPT_OK with some condition attached, typically
   that the calling routine not update state information since it's already
   been done by the returning routine or because the returning routine has
   more work to do on a later call */

#define OK_SPECIAL				1

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Information on an encryption object.  This is an extended version of the
   data returned by the externally-visible cryptQueryObject() routine */

typedef struct {
	/* The object type, format type (eg cryptlib, CMS) and size information */
	CRYPT_OBJECT_TYPE type;			/* Object type */
	CRYPT_FORMAT_TYPE formatType;	/* Object format type */
	long size;						/* Object size */

	/* The encryption algorithm and mode */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */

	/* The key ID for public key objects */
	BYTE keyID[ KEYID_SIZE ];		/* PKC key ID */

	/* The key derivation algorithm and iteration count for conventionally
	   encrypted keys */
	CRYPT_ALGO keySetupAlgo;		/* Key setup algorithm */
	int keySetupIterations;			/* Key setup iteration count */

	/* The hash algorithm for signatures */
	CRYPT_ALGO hashAlgo;			/* Hash algorithm */

	/* The start and length of the payload data */
	void *dataStart;				/* Start of payload data */
	int dataLength;					/* Length of payload data */

	/* The start and length of the IssuerAndSerialNumber for CMS key
	   transport and agreement objects */
	void *iAndSStart;				/* Start of IssuerAndSerialNumber */
	int iAndSLength;				/* Length of IssuerAndSerialNumber */

	/* The algorithm-specific information for conventionally encrypted keys.
	   The algorithm-specific information can be passed directly to
	   cryptCreateContextEx() for any algorithm (even those which would
	   normally use cryptCreateContext()) */
	void *cryptContextExInfo;		/* Algo-specific information */
	} OBJECT_INFO;

/* Information on an encryption context.  This is an extended version of the
   data returned by the externally-visible cryptQueryContext() routine */

typedef struct {
	/* General algorithm information */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */
	int blockSize;					/* The basic block size of the algorithm */
	int maxIVsize;					/* The maximum IV size for the algorithm */

	/* Current context state information */
	BOOLEAN isPKCcontext;			/* Whether it's a PKC context */
	BOOLEAN isPublicKey;			/* If PKC, whether key is pub.or priv.*/
	BOOLEAN keySet;					/* Whether a key is loaded */
	int keySize;					/* Actual key size for PKC context */

	/* Context-specific data */
	BYTE keyID[ KEYID_SIZE ];		/* Key ID for this key */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* IV */
	int ivLength;					/* Length of IV */
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];	/* Hash algorithm hash value */
	} ICRYPT_QUERY_INFO;

/****************************************************************************
*																			*
*								Useful General Macros						*
*																			*
****************************************************************************/

/* Reasonably reliable way to get rid of unused argument warnings in a
   compiler-independant manner */

#define UNUSED( arg )	( ( arg ) = ( arg ) )

/* Although min() and max() aren't in the ANSI standard, most stdlib.h's have
   them anyway for historical reasons.  Just in case they're not defined
   there by some pedantic compiler (some versions of Borland C do this), we
   define them here */

#ifndef max
  #define max( a, b )	( ( ( a ) > ( b ) ) ? ( ( int ) a ) : ( ( int ) b ) )
#endif /* !max */
#ifndef min
  #define min( a, b )	( ( ( a ) < ( b ) ) ? ( ( int ) a ) : ( ( int ) b ) )
#endif /* !min */

/* Macro to round a value up to the nearest multiple of a second value */

#define roundUp( size, roundSize ) \
	( ( ( size ) + ( ( roundSize ) - 1 ) ) & ~( ( roundSize ) - 1 ) )

/* A macro to clear sensitive data from memory.  This is somewhat easier to
   use than calling memset with the second parameter 0 all the time, and
   makes it obvious where sensitive data is being erased */

#define zeroise( memory, size )		memset( memory, 0, size )

/* A macro to check whether an algorithm is regarded as being (relatively)
   insecure or not.  This is used by some of the higher-level internal
   routines which normally use the default algorithm set in the configuration
   database if nothing else is explicitly specified, but which specifically
   check for the weaker algorithms and use something stronger instead if a
   weak algorithm is specified.  This is done both for luser-proofing and to
   avoid possible problems from a trojan patching the configuration
   database */

#define isWeakCryptAlgo( algorithm )	( ( algorithm ) == CRYPT_ALGO_DES || \
										  ( algorithm ) == CRYPT_ALGO_RC4 )

/* A macro to check whether a PKC algorithm is useful for a certain purpose */

#define isSigAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_DSA || \
	  ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isCryptAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isKeyxAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DH )

/****************************************************************************
*																			*
*							Handle/Resource Management						*
*																			*
****************************************************************************/

/* The object types */

typedef enum {
	RESOURCE_TYPE_NONE,				/* No resource */
	RESOURCE_TYPE_CRYPT,			/* Encryption context */
	RESOURCE_TYPE_KEYSET,			/* Keyset */
	RESOURCE_TYPE_ENVELOPE,			/* Envelope */
	RESOURCE_TYPE_CERTIFICATE,		/* Certificate */
	RESOURCE_TYPE_DEVICE,			/* Crypto device */
	RESOURCE_TYPE_SESSION			/* Secure session */
	} RESOURCE_TYPE;

/* The message types which can be sent to an object.  These are the passed
   to krnlSendMessage/Broadcast() and propagated to all objects of the given
   type.  There is a separate class of messages which can be sent to all
   object types, by default messages can only be sent to externally visible
   objects.  This is done as a security precaution to ensure that the usual
   access checks can't accidentally bypassed by code which sends a message to
   an object before the access check is performed.

   The declaration has to be here because it's needed for the resource table
   declaration */

typedef enum {
	/* Control messages to externally visible objects */
	RESOURCE_MESSAGE_NONE,				/* No message */
	RESOURCE_MESSAGE_DESTROY,			/* Destroy the object */
	RESOURCE_MESSAGE_PARTIAL_DESTROY,	/* Destroy contents but keep active */
	RESOURCE_MESSAGE_INCREFCOUNT,		/* Increment object ref.count */
	RESOURCE_MESSAGE_DECREFCOUNT,		/* Decrement object ref.count */
	RESOURCE_MESSAGE_SETPROPERTY,		/* Set object property */
	RESOURCE_MESSAGE_GETPROPERTY,		/* Get object property */

	/* General messages to externally visible objects */
	RESOURCE_MESSAGE_SETDATA,			/* Send data to object */
	RESOURCE_MESSAGE_GETDATA,			/* Get data from object */
	RESOURCE_MESSAGE_COMPARE,			/* Compare objs. or obj.properties */
	RESOURCE_MESSAGE_CLONE,				/* Clone the object */
	RESOURCE_MESSAGE_CHECK,				/* Check object info/permissions */
	RESOURCE_MESSAGE_LOCK,				/* Lock object for exclusive use */
	RESOURCE_MESSAGE_UNLOCK,			/* Unlock object */

	/* Internal messages sent from the kernel to object message handlers */
	RESOURCE_MESSAGE_CHANGENOTIFY,		/* Notification of obj.status chge.*/

	/* Object-type-specific messages */
	RESOURCE_MESSAGE_CTX_GENKEY,		/* Context: Generate a key */
	RESOURCE_MESSAGE_CTX_GENKEY_ASYNC,	/* Context: Async keygen */
/*	RESOURCE_MESSAGE_KEY_xxx,			Keyset-specific messages */
/*	RESOURCE_MESSAGE_ENV_xxx,			Envelope-specific messages */
/*	RESOURCE_MESSAGE_CRT_xxx,			Certificate-specific messages */
	RESOURCE_MESSAGE_DEV_GETCONTEXT,	/* Device: Context from built-in key */
/*	RESOURCE_MESSAGE_SES_xxx,			Session-specific message */
	RESOURCE_MESSAGE_LAST,				/* Last valid message type */

	/* Messages to all (including internal) object types.  Note that these
	   must track the external messages since the message dispatcher maps
	   them down to the general message type after performing the access
	   check */
	RESOURCE_IMESSAGE_DESTROY,			/* Destroy the object */
	RESOURCE_IMESSAGE_PARTIAL_DESTROY,	/* Destroy contents but keep active */
	RESOURCE_IMESSAGE_INCREFCOUNT,		/* Increment object ref.count */
	RESOURCE_IMESSAGE_DECREFCOUNT,		/* Decrement object ref.count */
	RESOURCE_IMESSAGE_SETPROPERTY,		/* Set object property */
	RESOURCE_IMESSAGE_GETPROPERTY,		/* Get object property */
	RESOURCE_IMESSAGE_SETDATA,			/* Send data to object */
	RESOURCE_IMESSAGE_GETDATA,			/* Get data from object */
	RESOURCE_IMESSAGE_COMPARE,			/* Check whether two objs.are ident */
	RESOURCE_IMESSAGE_CLONE,			/* Clone the object */
	RESOURCE_IMESSAGE_CHECK,			/* Check object info/permissions */
	RESOURCE_IMESSAGE_LOCK,				/* Lock object for exclusive use */
	RESOURCE_IMESSAGE_UNLOCK,			/* Unlock object */
	RESOURCE_IMESSAGE_CHANGENOTIFY,		/* Notification of obj.status chge.*/
	RESOURCE_IMESSAGE_CTX_GENKEY,		/* Context: Generate a key */
	RESOURCE_IMESSAGE_LAST				/* Last valid message type */
	} RESOURCE_MESSAGE_TYPE;

/* The last control message which can be sent to an object.  If the object
   status is anything other than CRYPT_OK then any attempt to send a non-
   control message will return the object status as an error code.  This is
   because it's possible to perform control functions (eg changing its
   internal status) on a busy or signalled object, but it's not possible to
   use it in a normal manner */

#define RESOURCE_MESSAGE_LAST_CONTROL	RESOURCE_MESSAGE_GETPROPERTY

/* The properties which RESOURCE_MESSAGE_GETPROPERTY and
   RESOURCE_MESSAGE_SETPROPERTY can get and set */

typedef enum {
	RESOURCE_MESSAGE_PROPERTY_NONE,		/* No property */
	RESOURCE_MESSAGE_PROPERTY_TYPE,		/* Object type (read-only) */
	RESOURCE_MESSAGE_PROPERTY_STATUS,	/* Object status */
	RESOURCE_MESSAGE_PROPERTY_OWNER,	/* Object owner */
	RESOURCE_MESSAGE_PROPERTY_INTERNAL,	/* Object internal flag */
	RESOURCE_MESSAGE_PROPERTY_LOCKED,	/* Whether user-settable props can be chged */
	RESOURCE_MESSAGE_PROPERTY_FORWARDABLE,	/* No of times object can be xferred */
	RESOURCE_MESSAGE_PROPERTY_LAST		/* Last possible property type */
	} RESOURCE_MESSAGE_PROPERTYTYPE_TYPE;

/* The data items which RESOURCE_MESSAGE_GETDATA and RESOURCE_MESSAGE_SETDATA
   can get and set */

typedef enum {
	RESOURCE_MESSAGE_DATA_NONE,			/* No data item */
	RESOURCE_MESSAGE_DATA_CONTEXT,		/* Internal context handle */
	RESOURCE_MESSAGE_DATA_CERTIFICATE,	/* Internal certificate handle */
	RESOURCE_MESSAGE_DATA_DEVICE,		/* Internal device handle */
	RESOURCE_MESSAGE_DATA_ERRORINFO,	/* Extended error info */
	RESOURCE_MESSAGE_DATA_ISSUERANDSERIALNUMBER,/* IssuerAndSerial for cert */
	RESOURCE_MESSAGE_DATA_CERTSET,		/* SET OF cert chain certificates */
	RESOURCE_MESSAGE_DATA_RANDOM,		/* Random data */
	RESOURCE_MESSAGE_DATA_LAST			/* Last possible data type */
	} RESOURCE_MESSAGE_DATA_TYPE;

/* The properties which RESOURCE_MESSAGE_COMPARE can compare */

typedef enum {
	RESOURCE_MESSAGE_COMPARE_NONE,		/* No comparison */
	RESOURCE_MESSAGE_COMPARE_OBJECT,	/* Compare two objects */
	RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER,	/* Compare IAndS */
	RESOURCE_MESSAGE_COMPARE_LAST		/* Last possible compare type */
	} RESOURCE_MESSAGE_COMPARE_TYPE;

/* The checks which RESOURCE_MESSAGE_CHECK performs */

typedef enum {
	RESOURCE_MESSAGE_CHECK_NONE,		/* No check */
	RESOURCE_MESSAGE_CHECK_PKC,			/* Public or private key context */
	RESOURCE_MESSAGE_CHECK_PKC_PRIVATE,	/* Private key context */
	RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT,	/* Public encryption context */
	RESOURCE_MESSAGE_CHECK_PKC_DECRYPT,	/* Private decryption context */
	RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK,/* Public signature check context */
	RESOURCE_MESSAGE_CHECK_PKC_SIGN,	/* Private signature context */
	RESOURCE_MESSAGE_CHECK_PKC_KEYAGREE,/* Key agreement context */
	RESOURCE_MESSAGE_CHECK_CRYPT,		/* Conventional encryption context */
	RESOURCE_MESSAGE_CHECK_HASH,		/* Hash context */
	RESOURCE_MESSAGE_CHECK_MAC,			/* MAC context */
	RESOURCE_MESSAGE_CHECK_KEYGEN,		/* Key generation capability */
	RESOURCE_MESSAGE_CHECK_LAST			/* Last possible check type */
	} RESOURCE_MESSAGE_CHECK_TYPE;

/* When getting/setting data, the information may be a variable-length string
   rather than a simple integer value, which would require two calls (one to
   communicate the length and one for the data).  To avoid this, we pass a
   pointer to a data-and-length structure rather than a pointer to the data.
   Some calls are even more complex, so we need two data pointers */

typedef struct {
	void *data;							/* Data */
	int length;							/* Length */
	} RESOURCE_DATA;

typedef struct {
	void *data1, *data2;				/* Data */
	int length1, length2;				/* Length */
	} RESOURCE_DATA_EX;

#define setResourceData( resDataPtr, dataPtr, dataLength ) \
	{ \
	memset( ( resDataPtr ), 0, sizeof( RESOURCE_DATA ) ); \
	( resDataPtr )->data = ( dataPtr ); \
	( resDataPtr )->length = ( dataLength ); \
	}

#define setResourceDataEx( resDataPtr, data1Ptr, data1Length, data2Ptr, data2Length ) \
	{ \
	memset( ( resDataPtr ), 0, sizeof( RESOURCE_DATA_EX ) ); \
	( resDataPtr )->data1 = ( data1Ptr ); \
	( resDataPtr )->length1 = ( data1Length ); \
	( resDataPtr )->data2 = ( data2Ptr ); \
	( resDataPtr )->length2 = ( data2Length ); \
	}

/* An urgent flag which indicates that the message should be processed
   immediately.  This is only valid for the object property manipulation
   functions and is used in rare cases where a change to an objects property
   needs to take effect immediately (for example to move an object into the
   signalled state once its internal data is destroyed but before the object
   itself is destroyed, which ensures that any further attempts to access it
   fail rather than trying to use the partially-destroyed object) */

#define RESOURCE_MESSAGE_URGENT		0x100

/* The object manipulation functions are implemented as macros since they
   need to access data internal to the object whose location differs
   depending on the object type.  For example the code to lock an object
   needs to manipulate the objects internal mutex, which will be stored in
   different locations for different objects.  Because of this we use macros
   to do this and let the compiler sort out the memory location within the
   object.  It would be somewhat cleaner to do this as a function, but this
   would mean ensuring the object-management related information was stored
   at the same location in each object (at the start of the object), which
   isn't very practical for clonable objects which assume that ephemeral data
   is located at the end of the object.

   To convert from the external handles which are used to reference internal
   data structures to the internal structure itself, we use a mapping table
   which maps from handles to internal data.  This means code outside the
   security perimeter cannot (easily) access sensitive data such as keying
   information.  The following structure is used to contain object information
   and map from handles to internal object data */

typedef struct {
	/* Object type and value */
	RESOURCE_TYPE type;			/* Object type */
	void *resource;				/* Object data */

	/* Object properties */
	BOOLEAN isInternal;			/* Whether the object is internal only */
	BOOLEAN isLocked;			/* Whether object properties can be chged */
	int status;					/* Current object status */
	DECLARE_OWNERSHIP_VARS		/* Information on the objects owner */
	int forwardCount;			/* Number of times ownership can be transferred */

	/* Object methods */
	int ( *messageFunction )( const int resourceHandle,
							  const RESOURCE_MESSAGE_TYPE message,
							  void *messageData, const int messageValue,
							  const int errorCode );
								/* The objects message handler */
	} RESOURCE_INFO;

extern RESOURCE_INFO *resourceTable;
extern int resourceTableSize;

/* The variables required to synchronise access to the object map */

DEFINE_LOCKING_VARS( resourceMap )

/* Map an external object handle to an object data pointer.  This macro is
   used in a number of the following macros, but should never be called
   directly since it doesn't perform any object locking.  The checks
   performed are as follows:

	Check that the handle refers to an object within the object table
	Check that the object isn't a cryptlib-internal object
	Check that the object is accessible to the caller
	Check that the object is of the requested type

   If all these checks succeed, a pointer to the object data is returned */

#define mapResourceHandle( handle, resType ) \
	( ( ( handle ) >= 0 && ( handle ) < resourceTableSize && \
			!resourceTable[ handle ].isInternal && \
			checkResourceOwnership( resourceTable[ handle ] ) && \
			( resourceTable[ handle ].type == resType || \
			  resType == RESOURCE_TYPE_NONE ) ) ? \
			resourceTable[ ( handle ) ].resource : NULL )

/* Map an internal object handle to an object data pointer.  This macro is
   almost identical to mapResourceHandle() except that it doesn't check
   whether the handle is for internal use only */

#define mapInternalResourceHandle( handle, resType ) \
	( ( ( handle ) >= 0 && ( handle ) < resourceTableSize && \
			( resourceTable[ handle ].type == resType || \
			  resType == RESOURCE_TYPE_NONE ) ) ? \
			resourceTable[ ( handle ) ].resource : NULL )

/* Create a new object.  This function has to be very careful about locking
   to ensure that another thread can't manipulate the newly-created object
   while it's in an indeterminate state.  To accomplish this it locks the
   object table and tries to create the new object.  If this succeeds it sets
   up the objects own lock and returns the locked object.  If it fails, it
   does nothing, so the function either returns a locked, ready-to-use
   object, or an error code.

   The locking is complicated by the fact that the object table and lock may
   not have been initialised yet, so we also need to check the initialisation
   lock before we try to lock or use the object table.  Even this can create
   problems since the initialisation lock may not have been set up yet, but
   we can't really fix that.  In any case under Win32 it's OK since the mutex
   is set up by DllMain(), and under most Unixen the storage for the mutex is
   set to all-zero which is equivalent to an initialised mutex */

DEFINE_LOCKING_VARS( initialisation )
extern BOOLEAN isInitialised;

#define krnlCreateObject( handle, resourcePtr, resType, size, flags, messageFunction ) \
	{ \
	lockGlobalResource( initialisation ); \
	if( !isInitialised ) \
		{ \
		unlockGlobalResource( initialisation ); \
		handle = CRYPT_NOTINITED; \
		} \
	else \
		{ \
		lockGlobalResource( resourceMap ); \
		unlockGlobalResource( initialisation ); \
		handle = addResource( resType, size, flags, messageFunction ); \
		if( !cryptStatusError( handle ) ) \
			{ \
			resourcePtr = mapInternalResourceHandle( handle, resType ); \
			initResourceLock( resourcePtr ); \
			lockResource( resourcePtr ); \
			} \
		unlockGlobalResource( resourceMap ); \
		} \
	}

/* Get a resource, lock it for exclusive use, and exit with an error code if
   the resource isn't present.  This function is only used with resources
   used internally by other resources (for example an encryption context
   contained within an envelope), so the only way the resource could be
   absent is if it was signalled.  Returning any other form of error code in
   fact presents considerable difficulties since internal resources are
   hidden from the user, and a return code of (say) CRYPT_BADPARM2 wouldn't
   make much sense */

#define getCheckInternalResource( handle, resourcePtr, resType ) \
	{ \
	lockGlobalResource( resourceMap ); \
	resourcePtr = mapInternalResourceHandle( handle, resType ); \
	if( resourcePtr != NULL ) \
		{ lockResource( resourcePtr ); } \
	unlockGlobalResource( resourceMap ); \
	if( resourcePtr == NULL ) \
		return( CRYPT_SIGNALLED ); \
	}

/* Get a resource, checks it's of the required type, and exit with an error
   code if there's a problem */

#define getCheckResource( handle, resourcePtr, resType, errCode ) \
	{ \
	int status; \
	\
	lockGlobalResource( resourceMap ); \
	resourcePtr = mapResourceHandle( handle, resType ); \
	if( resourcePtr != NULL && \
		( status = resourceTable[ ( handle ) ].status ) == CRYPT_OK ) \
		{ lockResource( resourcePtr ); } \
	unlockGlobalResource( resourceMap ); \
	if( ( resourcePtr ) == NULL ) \
		return( errCode ); \
	if( cryptStatusError( status ) ) \
		return( status ); \
	}

/* Sometimes we have multiple resources which need to be unlocked on exit.
   The following variant of the previous macros unlock an extra resource
   before returning */

#define getCheckInternalResource2( handle, resourcePtr, resType, secondResource ) \
	{ \
	lockGlobalResource( resourceMap ); \
	resourcePtr = mapInternalResourceHandle( handle, resType ); \
	if( resourcePtr != NULL ) \
		{ lockResource( resourcePtr ); } \
	unlockGlobalResource( resourceMap ); \
	if( resourcePtr == NULL ) \
		{ unlockResourceExit( secondResource, CRYPT_SIGNALLED ); } \
	}

#define getCheckResource2( handle, resourcePtr, resType, errCode, secondResource ) \
	{ \
	int status; \
	\
	lockGlobalResource( resourceMap ); \
	resourcePtr = mapResourceHandle( handle, resType ); \
	if( resourcePtr != NULL && \
		( status = resourceTable[ ( handle ) ].status ) == CRYPT_OK ) \
		{ lockResource( resourcePtr ); } \
	unlockGlobalResource( resourceMap ); \
	if( ( resourcePtr ) == NULL ) \
		{ unlockResourceExit( secondResource, errCode ); } \
	if( cryptStatusError( status ) ) \
		{ unlockResourceExit( secondResource, status ); } \
	}

/* Sometimes we can be passed one of two different resource types.  This gets
   rather complex since the resource locking and unlocking are implemented as
   preprocessor macros so we can't pass the same resource pointer to the
   same lock/unlock macro since the locking information (if it exists) will
   be in a different location for the two resource types.  The following two
   macros take care of this special case.  The first version checks the
   resource types and obtains and locks the resource if the resource is of
   the first type, the second version checks the resource types, obtains
   the appropriate resource pointer, and locks the resource if the resource
   is of either type.  The resource pointer or other resource pointer is
   set to NULL */

#define getCheckInternalResourceOpt( handle, resPtr, res1Type, res2Type ) \
	{ \
	BOOLEAN resOK = FALSE; \
	\
	lockGlobalResource( resourceMap ); \
	resPtr = mapInternalResourceHandle( handle ); \
	if( resPtr != NULL ) \
		if( resourceTable[ ( handle ) ].type == ( res1Type ) ) \
			{ \
			lockResource( resPtr ); resOK = TRUE; \
			} \
		else \
			if( resourceTable[ ( handle ) ].type == ( res2Type ) ) \
				resPtr = NULL; resOK = TRUE; \
	unlockGlobalResource( resourceMap ); \
	if( !resOK ) \
		return( CRYPT_SIGNALLED ); \
	}

#define getCheckResourceOpt( handle, resPtr, res1Type, res2Type, errCode ) \
	{ \
	BOOLEAN resOK = FALSE; \
	\
	lockGlobalResource( resourceMap ); \
	resPtr = mapResourceHandle( handle ); \
	if( resPtr != NULL ) \
		if( resourceTable[ ( handle ) ].type == ( res1Type ) ) \
			{ \
			lockResource( resPtr ); resOK = TRUE; \
			} \
		else \
			if( resourceTable[ ( handle ) ].type == ( res2Type ) ) \
				resPtr = NULL; resOK = TRUE; \
	unlockGlobalResource( resourceMap ); \
	if( !resOK ) \
		return( errCode ); \
	}

#define getCheckResourceEx( handle, res1Ptr, res1Type, res2Ptr, res2Type, errCode ) \
	{ \
	void *resourcePtr; \
	\
	lockGlobalResource( resourceMap ); \
	resourcePtr = mapResourceHandle( handle ); \
	if( resourcePtr != NULL ) \
		if( resourceTable[ ( handle ) ].type == ( res1Type ) ) \
			{ \
			res1Ptr = resourcePtr; res2Ptr = NULL; \
			lockResource( res1Ptr ); \
			} \
		else \
			if( resourceTable[ ( handle ) ].type == ( res2Type ) ) \
				{ \
				res2Ptr = resourcePtr; res1Ptr = NULL; \
				lockResource( res2Ptr ); \
				} \
			else \
				resourcePtr = NULL; \
	unlockGlobalResource( resourceMap ); \
	if( ( resourcePtr ) == NULL ) \
		return( errCode ); \
	}

/* Resource management functions */

#define RESOURCE_FLAG_SECUREMALLOC	0x01	/* Use secureMalloc() to alloc obj.*/
#define RESOURCE_FLAG_INTERNAL		0x02	/* cryptlib-internal object */

int addResource( const RESOURCE_TYPE type, const int resourceSize,
				 const int flags,
				 int ( *messageFunction )( const int resourceHandle,
										   const RESOURCE_MESSAGE_TYPE message,
										   void *messageDataPtr,
										   const int messageValue,
										   const int errorCode ) );

/* Resource messaging functions.  These have the following arguments:

	Type								DataPtr			Value
	---------------------------			-------			-----
	RESOURCE_MESSAGE_DESTROY			NULL			0
	RESOURCE_MESSAGE_INCREFCOUNT		NULL			0
	RESOURCE_MESSAGE_DECREFCOUNT		NULL			0
	RESOURCE_MESSAGE_SETPROPERTY		&value			propertyType
	RESOURCE_MESSAGE_GETPROPERTY		&value			propertyType
	RESOURCE_MESSAGE_SETDATA			&value			dataType
	RESOURCE_MESSAGE_GETDATA			&value			dataType
	RESOURCE_MESSAGE_COMPARE			value or &value	compareType
	RESOURCE_MESSAGE_CLONE				&clonedHandle	arg
	RESOURCE_MESSAGE_CHECKPERM			NULL			permissions */

int krnlSendMessage( const int resourceHandle,
					 const RESOURCE_MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue,
					 const int errorCode );
void krnlSendBroadcast( const RESOURCE_TYPE type,
						const RESOURCE_MESSAGE_TYPE message,
						void *messageDataPtr, const int messageValue,
						const int errorCode );

/* Since some messages contain no data but act only as notifiers, we define
   the following macro to make using them less messy */

#define krnlSendNotifier( handle, message ) \
		krnlSendMessage( handle, message, NULL, 0, 0 )

/* Semaphores */

typedef enum {
	SEMAPHORE_NONE,					/* No semaphore */
	SEMAPHORE_DRIVERBIND,			/* Async driver bind */
	SEMAPHORE_LAST					/* Last semaphore */
	} SEMAPHORE_TYPE;

/* Set/clear/wait on a semaphore */

void setSemaphore( const SEMAPHORE_TYPE semaphore, 
				   const SEMAPHORE_HANDLE object );
void clearSemaphore( const SEMAPHORE_TYPE semaphore );
void waitSemaphore( const SEMAPHORE_TYPE semaphore );

/* Register and deregister service functions to be called by cryptlibs
   background thread */

int registerServiceRoutine( void ( *serviceDispatchFunction )
	( const int object, void ( *serviceFunction )( void *info ) ),
	void ( *serviceFunction )( void *info ), const int object );
void deregisterServiceRoutine( const int serviceID );

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* The data formats for recipient (key transport) and signature types.  These
   are an extension of the externally-visible cryptlib formats and are needed
   for things like X.509 signatures and various secure session protocols
   which wrap stuff other than straight keys up using a KEK.  In addition to
   the basic CMS signature data we can also handle (for reading only) the
   extra information associated with CMS signatures which is needed to
   process them */

typedef enum { RECIPIENT_NONE, RECIPIENT_CRYPTLIB, RECIPIENT_CMS,
			   RECIPIENT_RAW } RECIPIENT_TYPE;

typedef enum { SIGNATURE_NONE, SIGNATURE_CRYPTLIB, SIGNATURE_X509,
			   SIGNATURE_CMS, SIGNATURE_CMS_SIGNATUREINFO } SIGNATURE_TYPE;

/* Internal forms of various external functions.  These work with internal
   resources which are marked as being inaccessible to the corresponding
   external functions, and return slightly different error codes in place of
   parameter errors, since odd parameter errors coming from a deeply-buried
   internal function won't make much sense to the caller.  In addition some
   of them exhibit slighly different behaviour than the external versions
   (for example iCryptQueryContext() returns more information than would be
   passed to an external caller)

   Encryption context functions */

int iCryptCreateContext( CRYPT_CONTEXT *cryptContext,
						 const CRYPT_ALGO cryptAlgo,
						 const CRYPT_MODE cryptMode );
int iCryptCreateContextEx( CRYPT_CONTEXT *cryptContext,
						   const CRYPT_ALGO cryptAlgo,
						   const CRYPT_MODE cryptMode,
						   const void *cryptContextEx );
int iCryptDestroyObject( const CRYPT_HANDLE cryptObject );
int iCryptQueryContext( const CRYPT_CONTEXT cryptContext,
						ICRYPT_QUERY_INFO CPTR cryptQueryInfo );
int iCryptLoadKey( const CRYPT_CONTEXT cryptContext, const void *userKey,
				   const int userKeyLength );
int iCryptLoadIV( const CRYPT_CONTEXT cryptContext, const void *iv,
				  const int ivLength );
int iCryptDeriveKey( const CRYPT_CONTEXT cryptContext, const void *userKey,
					 const int userKeyLength );
int iCryptDeriveKeyEx( const CRYPT_CONTEXT cryptContext, const void *userKey,
					   const int userKeyLength, const CRYPT_ALGO algorithm,
					   const int iterations );
int iCryptEncrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length );
int iCryptDecrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length );

/* Mid-level functions */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_CERTIFICATE iExtraData );
int iCryptCheckSignatureEx( const void *signature,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *iExtraData );
int iCryptImportKeyEx( void *encryptedKey, const CRYPT_CONTEXT iImportKey,
					   CRYPT_CONTEXT *iSessionKeyContext );
int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iExportKey,
					   const CRYPT_CONTEXT iSessionKeyContext );

/* Keyset functions */

int iCryptKeysetOpen( CRYPT_KEYSET *keySet, const CRYPT_KEYSET_TYPE keysetType,
					  const char *name );

/* Certificate functions */

int iCryptCreateCert( CRYPT_CERTIFICATE *iCertificate,
					  const CRYPT_CERTTYPE_TYPE certType );
int iCryptImportCert( const void *certObject, CRYPT_CERTIFICATE *iCertificate,
					  CRYPT_CONTEXT *iCryptContext );
int iCryptExportCert( void *certObject, int *certObjectLength,
					  const CRYPT_CERTIFICATE iCertificate );
int iCryptGetCertComponent( const CRYPT_CERTIFICATE iCertificate,
							const CRYPT_CERTINFO_TYPE certInfoType,
							void *certInfo, int *certInfoLength );
int iCryptAddCertComponent( const CRYPT_CERTIFICATE iCertificate,
							const CRYPT_CERTINFO_TYPE certInfoType,
							const void *certInfo, const int certInfoLength );
int iCryptDeleteCertComponent( const CRYPT_CERTIFICATE iCertificate,
							   const CRYPT_CERTINFO_TYPE certInfoType );

/* Special-case versions of iCryptImport/ExportKey() which work with
   unstructured data rather than contexts */

int importEncryptedSecret( void *data, const int dataLength,
						   const CRYPT_CONTEXT iImportKey, void *payload );
int exportEncryptedSecret( void *data, int *dataLength,
						   const CRYPT_CONTEXT iExportKey,
						   const void *payload, const int payloadSize );

/* Secure memory handling functions */

int krnlMemalloc( void **pointer, int size );
void krnlMemfree( void **pointer );
int krnlMemsize( const void *pointer );

/* Get a unique but not necessarily unpredictable nonce */

void getNonce( void *nonce, int nonceLength );

/* Check whether a password is valid or not.  Currently this just checks that
   it contains at least one character, but stronger checking can be
   substituted if required */

#define checkBadPassword( password ) \
	( checkBadPtrRead( password, 1 ) || ( strlen( password ) < 1 ) )

/* Key database routines.  These are handled internally by cryptdbx.c since
   they involve manipulation of KEYSET_INFO structures which aren't exported
   to the library as a whole */

int getKeyFromID( const CRYPT_KEYSET keyset, CRYPT_HANDLE *iCryptHandle,
				  const void *keyID, const void *password, char *ownerName );

/* Compare two strings in a case-insensitive manner for those systems which
   don't have this function.

   [This line of comment is necessary to bypass a bug in the Borland C parser] */

#if !( defined( __WINDOWS__ ) || defined( __MSDOS__ ) || \
	   defined( __OS2__ ) ) || defined( NT_DRIVER )

int strnicmp( const char *src, const char *dest, const int length );
int stricmp( const char *src, const char *dest );

#endif /* !( __WINDOWS__ || __MSDOS__ || __OS2__ ) || NT_DRIVER */

/* Hash state information.  We can either call the hash function with
   HASH_ALL to process an entire buffer at a time, or HASH_START/
   HASH_CONTINUE/HASH_END to process it in parts */

typedef enum { HASH_START, HASH_CONTINUE, HASH_END, HASH_ALL } HASH_STATE;

/* The hash functions are used quite a bit by the library so we provide an
   internal API for them to avoid the overhead of having to set up an
   encryption context every time they're needed.  These take a block of
   input data and hash it, leaving the result in the output buffer.  If the
   hashState parameter is HASH_ALL the hashInfo parameter may be NULL, in
   which case the function will use its own memory for the hashInfo */

#define MAX_HASHINFO_SIZE	200

typedef void ( *HASHFUNCTION )( void *hashInfo, BYTE *outBuffer, \
								BYTE *inBuffer, int length, \
								const HASH_STATE hashState );

BOOLEAN getHashParameters( const CRYPT_ALGO hashAlgorithm,
						   HASHFUNCTION *hashFunction, int *hashInputSize,
						   int *hashOutputSize, int *hashInfoSize );

/* Query and set library config options */

int getOptionNumeric( const CRYPT_OPTION_TYPE option );
char *getOptionString( const CRYPT_OPTION_TYPE option );
int setOptionNumeric( const CRYPT_OPTION_TYPE option, const int value );
int setOptionString( const CRYPT_OPTION_TYPE option, const char *value );
char *mapOLEName( const CRYPT_OPTION_TYPE option );

/* base64 and S/MIME-en/decode routines */

int base64checkHeader( const char *data );
int smimeCheckHeader( const char *data );
int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType,
					 const CRYPT_CERTFORMAT_TYPE format );
int base64encode( char *outBuffer, const void *inBuffer, const int count,
				  const CRYPT_CERTTYPE_TYPE certType,
				  const CRYPT_CERTFORMAT_TYPE format );
int base64decodeLen( const char *data );
int base64decode( void *outBuffer, const char *inBuffer, const int count,
				  const CRYPT_CERTFORMAT_TYPE format );

#endif /* _CRYPT_DEFINED */
