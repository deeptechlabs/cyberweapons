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

#if ( defined( SYMANTEC_C ) || defined( __BEOS__ ) ) && \
	!defined( INC_ALL )
  #error You need to predefine INC_ALL in your project file
#elif defined( _MSC_VER ) && !defined( INC_CHILD )
  #error You need to predefine INC_CHILD in your project/make file
#endif /* Checks for various compiler/OS-dependant include paths */

/* If we're on a new enough version of VC++, set a flag to only include
   header files once */

#if defined( _MSC_VER ) && ( _MSC_VER >= 1000 )
  #pragma once
#endif /* VC++ 5.0 or higher */

/* If the global cryptlib header hasn't been included yet, include it now */

#ifndef _CRYPTLIB_DEFINED
  #include "cryptlib.h"
#endif /* _CRYPTLIB_DEFINED */

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
   4.1.  It actually remains the same after 4.1) */

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

/* In some cases we're using a DOS or Windows system as a cross-development
   platform, if we are we add extra defines to turn off some Windows-
   specific features */

#ifdef _SCCTK
  #define __IBM4758__
#endif /* _SCCTK */

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
  #pragma warning( disable: 4018 )	/* Comparing signed <-> unsigned value */
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

/* Make the Tandem NSK and Macintowsh defines look a bit more like the usual 
   ANSI defines used to identify the other OS types */

#ifdef __TANDEM
  #define __TANDEM__
#endif /* __TANDEM */

#if defined( __MWERKS__ ) || defined( SYMANTEC_C ) 
  #define __MAC__
#endif /* __MWERKS__ || SYMANTEC_C */

/* If we're compiling on the AS/400, make enums a fixed size rather than 
   using the variable-length values which IBM compilers default to, and force
   strings into a readonly segment (by default they're writeable) */

#if defined( __OS400__ ) || defined( __ILEC400__ )
  #define __AS400__
  #pragma enumsize( 4 )
  #pragma strings( readonly )
#endif /* __OS400__ || __ILEC400__ */

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

/* If we're using DOS or Windows as a cross-development platform, we need
   the OS-specific value defined initially to get the types right but don't
   want it defined later on since the target platform won't really be 
   running DOS or Windows, so we undefine it after the types have been sorted
   out */

#ifdef __IBM4758__
  #undef __MSDOS__
  #undef __WINDOWS__
  #undef __WIN32__
#endif /* __IBM4758__ */

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
	   defined( __Mach__ ) || defined( _AIX ) )
	#define USE_THREADS
  #endif /* Slowaris || OSF1/DEC Unix || Mach || AIX */
#endif /* __UNIX__ && !NO_THREADS */

/* If we're running under Windows, enable network access, ODBC (if the 
   compiler understands ODBC), and LDAP and HTTP keyset access */

#ifdef __WINDOWS__
  #define NET_TCP
  #if !( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 ) )
	#define DBX_ODBC
  #endif /* Old Borland C++ */
  #define DBX_LDAP
  #define DBX_HTTP
#endif /* __WINDOWS__ */

/* On systems which support dynamic loading, we bind various drivers and
   libraries at runtime rather than at compile time.  Under Windows this is 
   fairly easy but under Unix it's only supported selectively and may be 
   buggy or platform-specific */

#if defined( __WINDOWS__ ) || ( defined( __UNIX__ ) && \
		( ( defined( sun ) && OSVERSION > 4 ) || defined( linux ) ) )

  #define DYNAMIC_LOAD

  /* Macros to map OS-specific dynamic-load values to generic ones */
  #if defined( __WINDOWS__ )
	#define INSTANCE_HANDLE		HINSTANCE
	#define NULL_INSTANCE		( HINSTANCE ) NULL
	#define DynamicLoad( name )	LoadLibrary( name )
	#define DynamicUnload		FreeLibrary
	#define DynamicBind			GetProcAddress
  #elif defined( __UNIX__ )
	#include <dlfcn.h>

	#define INSTANCE_HANDLE		void *
	#define NULL_INSTANCE		NULL
	#define DynamicLoad( name )	dlopen( name, RTLD_LAZY )
	#define DynamicUnload		dlclose
	#define DynamicBind			dlsym
  #endif /* OS-specific instance handles */
#endif /* Windows || Some Unix versions */

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
  #elif defined( __AS400__ )
	#define DATA_BIGENDIAN		/* AS/400 always big-endian */
  #elif defined( __VMCMS__ )
	#define DATA_BIGENDIAN		/* IBM big iron always big-endian */
  #elif defined __GNUC__
	#ifdef BYTES_BIG_ENDIAN
	  #define DATA_BIGENDIAN	/* Big-endian byte order */
	#else
	  #define DATA_LITTLEENDIAN	/* Undefined = little-endian byte order */
	#endif /* __GNUC__ */
  #endif /* Compiler-specific endianness checks */
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

/* When performing file I/O we need to know how large path names can get in 
   order to perform range checking and allocate buffers.  This gets a bit 
   tricky since not all systems have PATH_MAX, so we first try for PATH_MAX,
   if that fails we try _POSIX_PATH_MAX (which is a generic 255 bytes and if
   defined always seems to be less than whatever the real PATH_MAX should be),
   if that also fails we grab stdio.h and try and get FILENAME_MAX, with an
   extra check for PATH_MAX in case it's defined in stdio.h instead of 
   limits.h where it should be.  FILENAME_MAX isn't really correct since it's
   the maximum length of a filename rather than a path, but some environments
   treat it as if it were PATH_MAX and in any case it's the best we can do in 
   the absence of anything better */

#if defined( PATH_MAX )
  #define MAX_PATH_LENGTH		PATH_MAX
#elif defined( _POSIX_PATH_MAX )
  #define MAX_PATH_LENGTH		_POSIX_PATH_MAX
#else
  #ifndef FILENAME_MAX
	#include <stdio.h>
  #endif /* FILENAME_MAX */
  #ifdef PATH_MAX
	#define MAX_PATH_LENGTH		PATH_MAX
  #else
	#define MAX_PATH_LENGTH		FILENAME_MAX
  #endif /* PATH_MAX or FILENAME_MAX */
#endif /* PATH_MAX */
#ifdef __UNIX__
  /* SunOS 4.1.x doesn't define FILENAME_MAX in limits.h, however it does
	 define a POSIX path length limit so we use that instead.  There are a
	 number of places in various headers in which a max.path length is
	 defined either as 255 or 1024, but we use the POSIX limit since this is
	 the only thing defined in limits.h */
  #if defined( sun ) && ( OSVERSION == 4 ) && !defined( FILENAME_MAX )
	#define FILENAME_MAX  _POSIX_PATH_MAX
  #endif /* SunOS 4.1.x FILENAME_MAX define */
#endif /* __UNIX__ */

/* SunOS 4 doesn't have memmove(), but SunOS 5 (Slowaris) does, so we define
   memmove() to bcopy() under 4.  In addition SunOS doesn't define the
   fseek position indicators so we define those as well */

#if defined( __UNIX__ ) && defined( sun ) && ( OSVERSION == 4 )
  #define memmove	bcopy

  #define SEEK_SET	0
  #define SEEK_CUR	1
  #define SEEK_END	2
#endif /* SunOS 4 */

/* cryptlib contains a few static functions where are prototyped with block
   scope inside a preceding function:

		{
		static int foo( int bar );

		foo( 1 );
		}

	static int foo( int bar )
		{
		[...]
		}

   Compiler opinions on this vary.  Some compile it as is, some don't allow
   the 'static', some allow both variants, and some produce warnings with 
   both but allow them anyway (there are probably more variants with further 
   compilers).  To get around this, we use the following define and then vary 
   it for broken compilers (the following is the minimum required to get it
   to compile, other broken compilers will still produce warnings) */

#if ( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x600 ) ) || \
	defined( __VMCMS__ )
  #define STATIC_FN
#else
  #define STATIC_FN		static
#endif /* Fn.prototyping workarounds for borken compilers */

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
   the huge S-boxes.

   For embedded environments we remove a different set of functions, PGP file
   access isn't useful in an embedded system so we eliminate that as well as
   some of the less-useful algorithms */

#ifdef __MSDOS16__
  #define CRYPTLIB_LITE
#endif /* __MSDOS16__ */

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
#ifdef __IBM4758__
  #define NO_PGP
  #define NO_IDEA
  #define NO_MD4
  #define NO_MDC2
  #define NO_SAFER
#endif /* Embedded systems */
#if defined( CRYPTLIB_LITE ) || defined( __IBM4758__ ) || defined( __VMCMS__ )
  #define NO_COMPRESSION
#endif /* Systems where it's not terribly useful */

/****************************************************************************
*																			*
*								OS-Specific Macros							*
*																			*
****************************************************************************/

/* cryptlib provides support for a number of extended OS-specific services
   such as multithreading, resource locking, bounds checking, and so on.
   The macros for the OS-specific services and resource management are 
   defined in their own include file */

#include "cryptos.h"

/* The cryptlib kernel has its own interface, defined in the kernel include
   file */

#include "cryptkrn.h"

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

/* The minimum and maximum conventional key size in bits.  In order to avoid 
   problems with space inside shorter RSA-encrypted blocks, we limit the 
   total keysize to 256 bits, which is adequate for all purposes - the 
   limiting factor is three-key triple DES, which requires 3 * 64 bits of key 
   and absolutely must have that many bits or it just reduces to two-key 
   triple-DES.  Unfortunately when loading a default-length key into a 
   context we can't tell what the user is going to do with the generated key 
   (for example whether they will export it using a very short public key) so 
   we have to take the approach of using a practical length which will work 
   even with a 512-bit public key.  This means that for Blowfish, RC2, RC4, 
   and RC5 the keylength is shorter than strictly necessary (actually for RC2 
   we have to limit the keysize to 128 bits for CMS/SMIME compatibility) */

#define MIN_KEYSIZE_BITS		40
#define MAX_KEYSIZE_BITS		256

/* The maximum public-key size in bits.  This is used to save having to do
   lots of bit -> byte conversion when checking the lengths of PKC values 
   which have the length specified in bits */

#define MAX_PKCSIZE_BITS		bytesToBits( CRYPT_MAX_PKCSIZE )

/* The maximum public-key object size.  This is used to allocate temporary
   buffers when working with signatures and PKC-encrypted keys.  The size
   estimate is somewhat crude and involves a fair safety margin, it usually
   contains a single PKC object (signature or encrypted key) along with
   algorithm and key ID information */

#define MAX_PKC_OBJECTSIZE		( CRYPT_MAX_PKCSIZE * 2 )

/* The minimum size of an encoded signature or exported key object.  This is
   used by the pointer-check macros (for the OS's which support this) to
   check that the pointers to objects which are passed to functions point to
   the minimal amount of valid memory required for an object, and also to
   zero the buffer for the object to ensure the caller gets invalid data if
   the function fails */

#define MIN_CRYPT_OBJECTSIZE	64

/* The minimum size of a certificate.  This is used by the pointer-check
   macros (for the OS's which support this) to check that the pointers being
   passed to these functions point to the minimal amount of valid memory
   required for an object */

#define MIN_CERTSIZE		256

/* The maximum size of an object attribute.  In theory this can be any size, 
   but in practice we limit it to the following maximum to stop people 
   creating things like certs containing MPEGs of themselves playing with 
   their cat */

#define MAX_ATTRIBUTE_SIZE		1024

/* Some objects contain internal buffers used to process data whose size can 
   be specified by the user, the following is the minimum size allowed for
   these buffers */

#define MIN_BUFFER_SIZE			8192

/* The minimum and maximum size of various Internet-related values, used for 
   range checking */

#define MIN_DNS_SIZE			4			/* x.com */
#define MAX_DNS_SIZE			255			/* Max hostname size */
#define MIN_RFC822_SIZE			8			/* xx@yy.zz */
#define MAX_RFC822_SIZE			255
#define MIN_URL_SIZE			12			/* http://x.com */
#define MAX_URL_SIZE			MAX_DNS_SIZE

/* The HMAC input and output padding values.  These are defined here rather
   than in cryptctx.h because they're needed by some routines which perform
   HMAC operations using raw SHA-1 contexts, since some devices provide SHA-1
   but not HMAC-SHA1 so we have to build it ourselves where it's needed for
   things like key hashing */

#define HMAC_IPAD				0x36
#define HMAC_OPAD				0x5C

/* Generic error return code/invalid value code */

#define CRYPT_ERROR				-1

/* A special return code to inform asynchronous routines to abort the
   operation currently in progress */

#define ASYNC_ABORT				-1234

/* A special return code to indicate that everything went OK but there's
   some special action to perform.  This is generally used when a lower-level
   routine wants to return a CRYPT_OK with some condition attached, typically
   that the calling routine not update state information since it's already
   been done by the returning routine or because the returning routine has
   more work to do on a later call */

#define OK_SPECIAL				-4321

/* When parameters get passed in messages, their mapping to parameters passed
   to the calling function gets lost.  The following error codes are used to
   denote errors in message parameters which are mapped to function parameter
   error codes by the caller.  For a message call:

	krnlSendMessage( object, {args}, MESSAGE_TYPE, value );

   we have the following possible error codes */

#define CRYPT_ARGERROR_OBJECT	-1000		/* Error in object being sent msg.*/
#define CRYPT_ARGERROR_VALUE	-1001		/* Error in message value */
#define CRYPT_ARGERROR_STR1		-1002		/* Error in first string arg */
#define CRYPT_ARGERROR_STR2		-1003		/* Error in second string arg */
#define CRYPT_ARGERROR_NUM1		-1004		/* Error in first numeric arg */
#define CRYPT_ARGERROR_NUM2		-1005		/* Error in second numeric arg */

#define cryptArgError( status )	\
		( ( status ) >= CRYPT_ARGERROR_NUM2 && ( status ) <= CRYPT_ARGERROR_OBJECT )
		
/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* Information on a exported key/signature data.  This is an extended version 
   of the data returned by the externally-visible cryptQueryObject() routine */

typedef struct {
	/* The object type, format type (eg cryptlib, CMS) and size information */
	CRYPT_OBJECT_TYPE type;			/* Object type */
	CRYPT_FORMAT_TYPE formatType;	/* Object format type */
	long size;						/* Object size */

	/* The encryption algorithm and mode */
	CRYPT_ALGO cryptAlgo;			/* The encryption algorithm */
	CRYPT_MODE cryptMode;			/* The encryption mode */

	/* The key ID for public key objects */
	BYTE keyID[ CRYPT_MAX_HASHSIZE ];	/* PKC key ID */
	int keyIDlength;

	/* The key derivation algorithm and iteration count for conventionally
	   encrypted keys */
	CRYPT_ALGO keySetupAlgo;		/* Key setup algorithm */
	int keySetupIterations;			/* Key setup iteration count */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];/* Key setup salt */
	int saltLength;

	/* The hash algorithm for signatures */
	CRYPT_ALGO hashAlgo;			/* Hash algorithm */

	/* The start and length of the payload data */
	void *dataStart;				/* Start of payload data */
	int dataLength;

	/* The start and length of the IssuerAndSerialNumber for CMS key
	   transport and agreement objects */
	void *iAndSStart;				/* Start of IssuerAndSerialNumber */
	int iAndSLength;
	} QUERY_INFO;

/* When calling key agreement functions we have to pass a mass of cruft 
   around instead of the usual flat data, for which we use the following 
   structure.  The public value is the public key value used for the 
   agreement process, typically y = g^x mod p for DH-like mechanisms.  The 
   ukm is the user keying material, typically something which is mixed into 
   the DH process to make the new key unique.  The wrapped key is the output
   (originator)/input(recipient) to the keyagreement process.  The session 
   key context contains a context into which the derived key is loaded.  
   Typical examples of use are:

	Fortezza: publicValue = y, ukm = Ra, wrappedKey = TEK-wrapped MEK
	S/MIME: publicValue = y, ukm = 512-bit nonce, wrappedKey = g^x mod p */

typedef struct {
	BYTE publicValue[ CRYPT_MAX_PKCSIZE ];
	int publicValueLen;				/* Public key value */
	BYTE ukm[ CRYPT_MAX_PKCSIZE ];
	int ukmLen;						/* User keying material */
	BYTE wrappedKey[ CRYPT_MAX_PKCSIZE ];
	int wrappedKeyLen;				/* Wrapped key */
	CRYPT_CONTEXT sessionKeyContext;/* Context for derived key */
	} KEYAGREE_INFO;

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

/* A macro to check that a value is a possibly valid handle.  This doesn't 
   check that the handle refers to a valid object, merely that the value is 
   in the range for valid handles */

#define checkHandleRange( handle ) \
		( ( handle ) > NO_SYSTEM_OBJECTS - 1 && ( handle ) < MAX_OBJECTS )

/* A macro to check whether an encryption mode needs an IV or not */

#define needsIV( mode )	( ( mode ) == CRYPT_MODE_CBC || \
						  ( mode ) == CRYPT_MODE_CFB || \
						  ( mode ) == CRYPT_MODE_OFB )

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

/* Macros to check whether a PKC algorithm is useful for a certain purpose */

#define isSigAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_DSA || \
	  ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isCryptAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_RSA || ( algorithm ) == CRYPT_ALGO_ELGAMAL )
#define isKeyxAlgo( algorithm ) \
	( ( algorithm ) == CRYPT_ALGO_DH )

/* The EOL convention used when outputting text */

#if defined( __MSDOS16__ ) || defined( __MSDOS32__ ) || \
	defined( __WINDOWS__ ) || defined( __OS2__ )
  #define EOL		"\r\n"
  #define EOL_LEN	2
#elif defined( __UNIX__ ) || defined( __BEOS__ ) || defined( __AMIGA__ ) || \
	  defined( __IBM4758__ ) || defined( __TANDEM__ ) || defined( __VMCMS__ )
  #define EOL		"\n"
  #define EOL_LEN	1
#elif defined( __MAC__ )
  #define EOL		"\r"
  #define EOL_LEN	1
#else
  #error You need to add the OS-specific define to enable end-of-line handling
#endif /* OS-specific EOL markers */

/* Clear/set object error information */

#define clearErrorInfo( objectInfoPtr ) \
	{ \
	objectInfoPtr->errorLocus = CRYPT_ATTRIBUTE_NONE; \
	objectInfoPtr->errorType = CRYPT_OK; \
	}

#define setErrorInfo( objectInfoPtr, locus, type ) \
	{ \
	objectInfoPtr->errorLocus = locus; \
	objectInfoPtr->errorType = type; \
	}

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

/* When importing certs for internal use we occasionally need to have special
   control over the final object which is created, and also need to be able
   to handle things which aren't normal certs.  The following values tell the
   cert import code to create special-case objects on import, and to handle
   data formats which aren't quite the normal certs or cert chains.  Note 
   that for cert formats CERTFORMAT_NORMAL must be the first value because
   it's the default setting (0) used when sending create object messages */

typedef enum {
	CERTIMPORT_NONE,				/* No import type */
	CERTIMPORT_NORMAL,				/* Create contexts for all certs */
	CERTIMPORT_DATA_ONLY,			/* Create data-only certs */
	CERTIMPORT_LEAFCONTEXT_ONLY,	/* Create context only for leaf cert */
	CERTIMPORT_LAST					/* Last cert import type */
	} CERTIMPORT_TYPE;

typedef enum {
	CERTFORMAT_NORMAL,				/* Default format type */
	CERTFORMAT_CERTSET,				/* SET OF Certificate */
	CERTFORMAT_SSLCHAIN,			/* SSL cert chain */
	CERTFORMAT_LAST					/* Last cert format type */
	} CERTFORMAT_TYPE;

/* Internal forms of various external functions.  These work with internal
   resources which are marked as being inaccessible to the corresponding
   external functions, and return slightly different error codes in place of
   parameter errors, since odd parameter errors coming from a deeply-buried
   internal function won't make much sense to the caller.

   Mid-level functions */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_CERTIFICATE iExtraData,
							 const char *tsaInfo );
int iCryptCheckSignatureEx( const void *signature,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *iExtraData );
int iCryptImportKeyEx( const void *encryptedKey, 
					   const CRYPT_CONTEXT iImportKey,
					   const CRYPT_CONTEXT iSessionKeyContext );
int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportKey,
					   const CRYPT_CONTEXT iAuxContext );

/* Special-case certificate functions.  This works somewhat like the import
   cert messages, but reads certs by sending get_next_cert messages to the
   message source and provides extended control over the format of the
   imported object.  This isn't strictly speaking a certificate function since
   the work is done by the caller (via callback messages), but the best place
   to put it is with the cert-management code */

int iCryptImportCertIndirect( CRYPT_CERTIFICATE *iCertificate,
							  const CRYPT_HANDLE iCertSource, 
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  const CERTIMPORT_TYPE importType );

/* Get a unique but not necessarily unpredictable nonce */

void getNonce( void *nonce, int nonceLength );

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics */

int attributeCopy( RESOURCE_DATA *msgData, const void *attribute, 
				   const int attributeLength );

/* Check whether a password is valid or not.  Currently this just checks that
   it contains at least one character, but stronger checking can be
   substituted if required */

#define checkBadPassword( password ) \
	( checkBadPtrRead( password, 1 ) || ( strlen( password ) < 1 ) )

/* When we encounter an internal consistency check failure, we usually want 
   to display some sort of message telling the user that something has gone
   catastrophically wrong, however people probably don't want klaxons going
   off when there's a problem in production code so we only enable it in
   debug versions.  The command-line makefiles by default build release
   versions, so in practice the warn-the-user action is only taken under
   Windows unless the user explicitly enables the user of assertions */

#include <assert.h>
#define NOTREACHED	0	/* Force an assertion failure via assert( NOTREACHED ) */

/* Compare two strings in a case-insensitive manner for those systems which
   don't have this function.

   [This line of comment is necessary to bypass a bug in the Borland C parser] */

#if !( defined( __WINDOWS__ ) || defined( __MSDOS__ ) || \
	   defined( __OS2__ ) || defined( __IBM4758__ ) ) || defined( NT_DRIVER )

int strnicmp( const char *src, const char *dest, const int length );
int stricmp( const char *src, const char *dest );

#endif /* !( __WINDOWS__ || __MSDOS__ || __OS2__ || __IBM4758__ ) || NT_DRIVER */

/* Try and match a substring in a string */

BOOLEAN matchSubstring( const char *subString, const int subStringLength,
						const char *string, const int stringLength );

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

#ifdef _BIG_WORDS
  #define MAX_HASHINFO_SIZE	280	/* RIPEMD160: 24 * sizeof( long64 ) + 64 */
#else
  #define MAX_HASHINFO_SIZE	100	/* RIPEMD160: 24 * sizeof( long ) */
#endif /* _BIG_WORDS */

typedef void ( *HASHFUNCTION )( void *hashInfo, BYTE *outBuffer, \
								BYTE *inBuffer, int length, \
								const HASH_STATE hashState );

void getHashParameters( const CRYPT_ALGO hashAlgorithm, 
						HASHFUNCTION *hashFunction, int *hashOutputSize );

/* base64 and S/MIME-en/decode routines */

int base64checkHeader( const char *data, const int dataLength );
int smimeCheckHeader( const char *data, const int dataLength );
int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType );
int base64encode( char *outBuffer, const void *inBuffer, const int count,
				  const CRYPT_CERTTYPE_TYPE certType );
int base64decodeLen( const char *data, const int dataLength );
int base64decode( void *outBuffer, const char *inBuffer, const int count,
				  const CRYPT_CERTFORMAT_TYPE format );

#endif /* _CRYPT_DEFINED */
