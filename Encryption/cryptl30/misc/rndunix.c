/****************************************************************************
*																			*
*						  Unix Randomness-Gathering Code					*
*	Copyright Peter Gutmann, Paul Kendall, and Chris Wedgwood 1996-1999		*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#include "misc/random.h"

/* OS-specific includes */

#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#ifndef __QNX__
  #include <sys/errno.h>
  #include <sys/ipc.h>
#endif /* __QNX__ */
#include <sys/time.h>	/* SCO and SunOS need this before resource.h */
#ifndef __QNX__
  #include <sys/resource.h>
#endif /* __QNX__ */
#ifdef _AIX
  #include <sys/select.h>
  #include <sys/systemcfg.h>
#endif /* _AIX */
#ifndef __QNX__
  #include <sys/shm.h>
  #include <sys/signal.h>
#endif /* __QNX__ */
#include <sys/stat.h>
#include <sys/types.h>	/* Verschiedene komische Typen */
#if defined( __hpux ) && ( OS_VERSION == 9 )
  #include <vfork.h>
#endif /* __hpux 9.x, after that it's in unistd.h */
#include <sys/wait.h>
/* #include <kitchensink.h> */

extern int errno;

/* The structure containing information on random-data sources.  Each
   record contains the source and a relative estimate of its usefulness
   (weighting) which is used to scale the number of kB of output from the
   source (total = data_bytes / usefulness).  Usually the weighting is in the
   range 1-3 (or 0 for especially useless sources), resulting in a usefulness
   rating of 1...3 for each kB of source output (or 0 for the useless
   sources).

   If the source is constantly changing (certain types of network statistics
   have this characteristic) but the amount of output is small, the weighting
   is given as a negative value to indicate that the output should be treated
   as if a minimum of 1K of output had been obtained.  If the source produces
   a lot of output then the scale factor is fractional, resulting in a
   usefulness rating of < 1 for each kB of source output.

   In order to provide enough randomness to satisfy the requirements for a
   slow poll, we need to accumulate at least 20 points of usefulness (a
   typical system should get about 30 points).

   Some potential options are missed out because of special considerations.
   pstat -i and pstat -f can produce amazing amounts of output (the record
   is 600K on an Oracle server) which floods the buffer and doesn't yield
   anything useful (apart from perhaps increasing the entropy of the vmstat
   output a bit), so we don't bother with this.  pstat in general produces
   quite a bit of output, but it doesn't change much over time, so it gets
   very low weightings.  netstat -s produces constantly-changing output but
   also produces quite a bit of it, so it only gets a weighting of 2 rather
   than 3.  The same holds for netstat -in, which gets 1 rather than 2.

   Some binaries are stored in different locations on different systems so
   alternative paths are given for them.  The code sorts out which one to
   run by itself, once it finds an exectable somewhere it moves on to the
   next source.  The sources are arranged roughly in their order of
   usefulness, occasionally sources which provide a tiny amount of
   relatively useless data are placed ahead of ones which provide a large
   amount of possibly useful data because another 100 bytes can't hurt, and
   it means the buffer won't be swamped by one or two high-output sources.
   All the high-output sources are clustered towards the end of the list
   for this reason.  Some binaries are checked for in a certain order, for
   example under Slowaris /usr/ucb/ps understands aux as an arg, but the
   others don't.  Some systems have conditional defines enabling alternatives
   to commands which don't understand the usual options but will provide
   enough output (in the form of error messages) to look like they're the
   real thing, causing alternative options to be skipped (we can't check the
   return either because some commands return peculiar, non-zero status even
   when they're working correctly).

   In order to maximise use of the buffer, the code performs a form of run-
   length compression on its input where a repeated sequence of bytes is
   replaced by the occurrence count mod 256.  Some commands output an awful
   lot of whitespace, this measure greatly increases the amount of data we
   can fit in the buffer.

   When we scale the weighting using the SC() macro, some preprocessors may
   give a division by zero warning for the most obvious expression
   'weight ? 1024 / weight : 0' (and gcc 2.7.2.2 dies with a division by zero
   trap), so we define a value SC_0 which evaluates to zero when fed to
   '1024 / SC_0' */

#define SC( weight )	( 1024 / weight )	/* Scale factor */
#define SC_0			16384				/* SC( SC_0 ) evalutes to 0 */

static struct RI {
	const char *path;		/* Path to check for existence of source */
	const char *arg;		/* Args for source */
	const int usefulness;	/* Usefulness of source */
	FILE *pipe;				/* Pipe to source as FILE * */
	int pipeFD;				/* Pipe to source as FD */
	pid_t pid;				/* pid of child for waitpid() */
	int length;				/* Quantity of output produced */
	const BOOLEAN hasAlternative;	/* Whether source has alt.location */
	} dataSources[] = {
	{ "/bin/vmstat", "-s", SC( -3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-s", SC( -3 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-c", SC( -3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-c", SC( -3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/pfstat", NULL, SC( -2 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-i", SC( -2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-i", SC( -2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-s", SC( 2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/nfsstat", NULL, SC( 2 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-m", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-in", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/ntptrace", "-r2 -t1 -nv", SC( -1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.7.1.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* UDP in */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.7.4.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* UDP out */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.4.3.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* IP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.10.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* TCP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.11.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* TCP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.6.13.0", SC( -1 ), NULL, 0, 0, 0, FALSE }, /* TCP ? */
	{ "/usr/bin/mpstat", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/w", NULL, SC( 1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bsd/w", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/df", NULL, SC( 1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/df", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/portstat", NULL, SC( 1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/iostat", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/uptime", NULL, SC( SC_0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bsd/uptime", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", "-f", SC( SC_0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", "-f", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/vmstat", NULL, SC( SC_0 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/vmstat", NULL, SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/ucb/netstat", "-n", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/netstat", "-n", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, TRUE },
	{ "/bin/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/netstat", "-n", SC( 0.5) , NULL, 0, 0, 0, FALSE },
#if defined( __sgi ) || defined( __hpux )
	{ "/bin/ps", "-el", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
#endif /* __sgi || __hpux */
	{ "/usr/ucb/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/ps", "aux", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/ipcs", "-a", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/ipcs", "-a", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
							/* Unreliable source, depends on system usage */
	{ "/etc/pstat", "-p", SC( 0.5 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-p", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-S", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-S", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-v", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-v", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-x", SC( 0.2 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-x", SC( 0.2 ), NULL, 0, 0, 0, FALSE },
	{ "/etc/pstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/bin/pstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
							/* pstat is your friend */
	{ "/usr/bin/last", "-n 50", SC( 0.3 ), NULL, 0, 0, 0, TRUE },
#ifdef __sgi
	{ "/usr/bsd/last", "-50", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
#endif /* __sgi */
#ifdef __hpux
	{ "/etc/last", "-50", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
#endif /* __hpux */
	{ "/usr/bsd/last", "-n 50", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/local/bin/lsof", "-lnwP", SC( 0.3 ), NULL, 0, 0, 0, FALSE },
							/* Output is very system and version-dependent */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.5.1.0", SC( 0.1 ), NULL, 0, 0, 0, FALSE }, /* ICMP ? */
	{ "/usr/sbin/snmp_request", "localhost public get 1.3.6.1.2.1.5.3.0", SC( 0.1 ), NULL, 0, 0, 0, FALSE }, /* ICMP ? */
	{ "/etc/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/etc/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/sbin/arp", "-a", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/ripquery", "-nw 1 127.0.0.1", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/lpstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/bin/lpstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, TRUE },
	{ "/usr/ucb/lpstat", "-t", SC( 0.1 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/bin/tcpdump", "-c 5 -efvvx", SC( 1 ), NULL, 0, 0, 0, FALSE },
							/* This is very environment-dependant.  If
							   network traffic is low, it'll probably time
							   out before delivering 5 packets, which is OK
							   because it'll probably be fixed stuff like
							   ARP anyway */
	{ "/usr/sbin/advfsstat", "-b usr_domain", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/advfsstat", "-l 2 usr_domain", SC( 0.5 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/sbin/advfsstat", "-p usr_domain", SC( SC_0 ), NULL, 0, 0, 0, FALSE },
							/* This is a complex and screwball program.  Some
							   systems have things like rX_dmn, x = integer,
							   for RAID systems, but the statistics are
							   pretty dodgy */
#if 0
	/* The following aren't enabled since they're somewhat slow and not very
	   unpredictable, however they give an indication of the sort of sources
	   you can use (for example the finger might be more useful on a
	   firewalled internal network) */
	{ "/usr/bin/finger", "@ml.media.mit.edu", SC( 0.9 ), NULL, 0, 0, 0, FALSE },
	{ "/usr/local/bin/wget", "-O - http://lavarand.sgi.com/block.html", SC( 0.9 ), NULL, 0, 0, 0, FALSE },
	{ "/bin/cat", "/usr/spool/mqueue/syslog", SC( 0.9 ), NULL, 0, 0, 0, FALSE },
#endif /* 0 */
	{ NULL, NULL, 0, NULL, 0, 0, 0, FALSE } };

/* Variables to manage the child process which fills the buffer */

static pid_t gathererProcess = 0;/* The child process which fills the buffer */
static BYTE *gathererBuffer;	/* Shared buffer for gathering random noise */
static int gathererMemID;		/* ID for shared memory */
static int gathererBufSize;		/* Size of the shared memory buffer */
static uid_t gathererID = ( uid_t ) -1;	/* Gatherers user ID */

/* The struct at the start of the shared memory buffer used to communicate
   information from the child to the parent */

typedef struct {
	int usefulness;				/* Usefulness of data in buffer */
	int noBytes;				/* No.of bytes in buffer */
	} GATHERER_INFO;

/* Under SunOS popen() doesn't record the pid of the child process.  When
   pclose() is called, instead of calling waitpid() for the correct child, it
   calls wait() repeatedly until the right child is reaped.  The problem is
   that this reaps any other children that happen to have died at that
   moment, and when their pclose() comes along, the process hangs forever.
   The fix is to use a wrapper for popen()/pclose() which saves the pid in
   the dataSources structure (code adapted from GNU-libc's popen() call).

   Aut viam inveniam aut faciam */

static FILE *my_popen( struct RI *entry )
	{
	int pipedes[ 2 ];
	FILE *stream;

	/* Create the pipe */
	if( pipe( pipedes ) < 0 )
		return( NULL );

	/* Fork off the child ("vfork() is like an OS orgasm.  All OS's want to
	   do it, but most just end up faking it" - Chris Wedgwood).  If your OS
	   supports it, you should try to use vfork() here because it's somewhat
	   more efficient */
#if defined( sun ) || defined( __ultrix__ ) || defined( __osf__ ) || \
	defined( __hpux )
	entry->pid = vfork();
#else
	entry->pid = fork();
#endif /* Unixen which have vfork() */
	if( entry->pid == ( pid_t ) -1 )
		{
		/* The fork failed */
		close( pipedes[ 0 ] );
		close( pipedes[ 1 ] );
		return( NULL );
		}

	if( entry->pid == ( pid_t ) 0 )
		{
		struct passwd *passwd;

		/* We are the child.  Make the read side of the pipe be stdout */
		if( dup2( pipedes[ STDOUT_FILENO ], STDOUT_FILENO ) < 0 )
			exit( 127 );

		/* Now that everything is set up, give up our permissions to make
		   sure we don't read anything sensitive.  If the getpwnam() fails,
		   we default to -1, which is usually nobody */
		if( gathererID == ( uid_t ) -1 && \
			( passwd = getpwnam( "nobody" ) ) != NULL )
			gathererID = passwd->pw_uid;
		setuid( gathererID );

		/* Close the pipe descriptors */
		close( pipedes[ STDIN_FILENO ] );
		close( pipedes[ STDOUT_FILENO ] );

		/* Try and exec the program */
		execl( entry->path, entry->path, entry->arg, NULL );

		/* Die if the exec failed */
		exit( 127 );
		}

	/* We are the parent.  Close the irrelevant side of the pipe and open the
	   relevant side as a new stream.  Mark our side of the pipe to close on
	   exec, so new children won't see it */
	close( pipedes[ STDOUT_FILENO ] );
	fcntl( pipedes[ STDIN_FILENO ], F_SETFD, FD_CLOEXEC );
	stream = fdopen( pipedes[ STDIN_FILENO ], "r" );
	if( stream == NULL )
		{
		int savedErrno = errno;

		/* The stream couldn't be opened or the child structure couldn't be
		   allocated.  Kill the child and close the other side of the pipe */
		kill( entry->pid, SIGKILL );
		if( stream == NULL )
			close( pipedes[ STDOUT_FILENO ] );
		else
			fclose( stream );
		waitpid( entry->pid, NULL, 0 );
		entry->pid = 0;
		errno = savedErrno;
		return( NULL );
		}

	return( stream );
	}

static int my_pclose( struct RI *entry )
	{
	int status = 0;

	if( fclose( entry->pipe ) )
		return( -1 );

	/* We ignore the return value from the process because some programs
	   return funny values which would result in the input being discarded
	   even if they executed successfully.  This isn't a problem because
	   the result data size threshold will filter out any programs which exit
	   with a usage message without producing useful output */
	if( waitpid( entry->pid, NULL, 0 ) != entry->pid )
		status = -1;

	entry->pipe = NULL;
	entry->pid = 0;
	return( status );
	}

/* Unix fast poll - not terribly useful */

#if defined( __hpux ) && ( OSVERSION == 9 )

/* PHUX 9.x doesn't support getrusage in libc (wonderful...) */

#include <syscall.h>

static int getrusage( int who, struct rusage *rusage )
	{
	return( syscall( SYS_getrusage, who, rusage ) );
	}
#endif /* __hpux */

/* SCO has a gettimeofday() prototype but no actual system call which
   implements it, and no getrusage() at all, so we use times() instead */

#ifdef _M_XENIX

#include <sys/times.h>
#endif /* _M_XENIX */

void fastPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	int bufIndex = 0;
#ifndef _M_XENIX
	struct timeval tv;
	struct rusage rusage;
#else
	struct tms tms;
#endif /* _M_XENIX */
#ifdef _AIX
	timebasestruct_t cpuClockInfo;
#endif /* _AIX */

	/* Mix in the process ID.  This doesn't change per process but will
	   change if the process forks, ensuring that the parent and child data 
	   differs from the parent */
	addRandom( buffer, &bufIndex, getpid() );

#ifndef _M_XENIX
	gettimeofday( &tv, NULL );
	addRandom( buffer, &bufIndex, tv.tv_sec );
	addRandom( buffer, &bufIndex, tv.tv_usec );

	/* SunOS 5.4 has the function call but no prototypes for it, if you're
	   compiling this under 5.4 you'll have to copy the header files from 5.5
	   or something similar */
	getrusage( RUSAGE_SELF, &rusage );
	addRandomString( buffer, &bufIndex, &rusage, sizeof( struct rusage ) );
#else
	times( &tms );
	addRandomString( buffer, &bufIndex, &tms, sizeof( struct tms ) );
#endif /* _M_XENIX */
#ifdef _AIX
	/* Add the value of the nanosecond-level CPU clock or time base register */
	read_real_time( &cpuClockInfo, sizeof( timebasestruct_t ) );
	addRandomString( buffer, &bufIndex, &cpuClockInfo, 
					 sizeof( timebasestruct_t ) );
#endif /* _AIX */

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	}

/* Unix slow poll with special support for Linux.  Really for Linux >=1.3.43
   (>=2.0.12 recommended), "mknod /dev/urandom c 1 9" if you don't have this
   device, and also "mknod /dev/random c 1 8" (this assumes you're root -
   "Use Linux, be your own luser").

   If a few of the randomness sources create a large amount of output then
   the slowPoll() stops once the buffer has been filled (but before all the
   randomness sources have been sucked dry) so that the 'usefulness' factor
   remains below the threshold.  For this reason the gatherer buffer has to
   be fairly sizeable on moderately loaded systems.  This is something of a
   bug since the usefulness should be influenced by the amount of output as
   well as the source type */

#define DEVRANDOM_BITS		1024
#define SHARED_BUFSIZE 		49152	/* Usually about 25K are filled */

void slowPoll( void )
	{
	GATHERER_INFO *gathererInfo;
	BOOLEAN moreSources;
	struct timeval tv;
	fd_set fds;
	const int pageSize = getPageSize();
#if defined( __hpux )
	size_t maxFD = 0;
#else
	int maxFD = 0;
#endif /* OS-specific brokenness */
	int bufPos, i, usefulness = 0, fd;

	/* Make sure we don't start more than one slow poll at a time */
	if( gathererProcess	)
		return;

	/* If there's a /dev/random present, use that if possible */
	if( ( fd = open( "/dev/urandom", O_RDONLY ) ) >= 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ DEVRANDOM_BITS / 8 ];
		int quality = 100;

		/* Read data from /dev/urandom, which won't block (although the
		   quality of the noise is lesser).  This is Linux-specific, but we
		   may as well leave it in for other systems in case it's present
		   there */
		read( fd, buffer, DEVRANDOM_BITS / 8 );
		setResourceData( &msgData, buffer, DEVRANDOM_BITS / 8 );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
		zeroise( buffer, DEVRANDOM_BITS / 8 );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
						 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
		close( fd );
		return;
		}

	/* If there's a procfs present, read the first 1K from some of the more
	   useful sources (most of these produce far less than 1K output) */
	if( access( "/proc/interrupts", R_OK ) )
		{
		static const char *procSources[] = {
			"/proc/interrupts", "/proc/loadavg", "/proc/locks",
			"/proc/meminfo", "/proc/stat", "/proc/net/tcp", "/proc/net/udp", 
			"/proc/net/dev", "/proc/net/ipx", NULL };
		RESOURCE_DATA msgData;
		BYTE buffer[ 1024 ];
		int quality = 4, index = 0;

		while( procSources[ index ] != NULL )
			{
			if( ( fd = open( procSources[ index ], O_RDONLY ) ) >= 0 )
				{
				int count = read( fd, buffer, 1024 );
				setResourceData( &msgData, buffer, count );
				krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								 CRYPT_IATTRIBUTE_RANDOM );
				close( fd );
				krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								 RESOURCE_IMESSAGE_SETATTRIBUTE, &quality, 
								 CRYPT_IATTRIBUTE_RANDOM_QUALITY );
				}
			index++;
			}
		zeroise( buffer, 1024 );
		}

	/* Set up the shared memory */
	gathererBufSize = ( SHARED_BUFSIZE / pageSize ) * ( pageSize + 1 );
	if( ( gathererMemID = shmget( IPC_PRIVATE, gathererBufSize,
								  IPC_CREAT | 0600 ) ) == -1 )
		return;	/* Something broke */
	if( ( gathererBuffer = ( BYTE * ) shmat( gathererMemID, NULL, 0 ) ) == ( BYTE * ) -1 )
		return; /* Something broke */

	/* Fork off the gatherer, the parent process returns to the caller */
	if( ( gathererProcess = fork() ) || ( gathererProcess == -1 ) )
		return;	/* Error/parent process returns */

	fclose( stderr );	/* Arrghh!!  It's Stuart code!! */

	/* Reset the SIGC(H)LD handler to the system default.  This is necessary
	   because if the program which cryptlib is a part of installs its own
	   SIGC(H)LD handler, it will end up reaping the cryptlib children before
	   cryptlib can.  As a result, my_pclose() will call waitpid() on a
	   process which has already been reaped by the installed handler and
	   return an error, so the read data won't be added to the randomness
	   pool.

	   There are two types of SIGC(H)LD naming, the SysV SIGCLD and the
	   BSD/Posix SIGCHLD, so we need to handle either possibility */
#ifdef SIGCLD
	signal( SIGCLD, SIG_DFL );
#else
	signal( SIGCHLD, SIG_DFL );
#endif /* SIGCLD */

	/* Fire up each randomness source */
	FD_ZERO( &fds );
	for( i = 0; dataSources[ i ].path != NULL; i++ )
		{
		/* Since popen() is a fairly heavy function, we check to see whether
		   the executable exists before we try to run it */
		if( access( dataSources[ i ].path, X_OK ) )
			{
#ifdef DEBUG_RANDOM
			printf( "%s not present%s\n", dataSources[ i ].path,
					dataSources[ i ].hasAlternative ? ", has alternatives" : "" );
#endif /* DEBUG_RANDOM */
			dataSources[ i ].pipe = NULL;
			}
		else
			dataSources[ i ].pipe = my_popen( &dataSources[ i ] );
		if( dataSources[ i ].pipe != NULL )
			{
			dataSources[ i ].pipeFD = fileno( dataSources[ i ].pipe );
			if( dataSources[ i ].pipeFD > maxFD )
				maxFD = dataSources[ i ].pipeFD;
			fcntl( dataSources[ i ].pipeFD, F_SETFL, O_NONBLOCK );
			FD_SET( dataSources[ i ].pipeFD, &fds );
			dataSources[ i ].length = 0;

			/* If there are alternatives for this command, don't try and
			   execute them */
			while( dataSources[ i ].hasAlternative )
				{
#ifdef DEBUG_RANDOM
				printf( "Skipping %s\n", dataSources[ i + 1 ].path );
#endif /* DEBUG_RANDOM */
				i++;
				}
			}
		}
	gathererInfo = ( GATHERER_INFO * ) gathererBuffer;
	bufPos = sizeof( GATHERER_INFO );	/* Start of buf.has status info */

	/* Suck all the data we can get from each of the sources */
	moreSources = TRUE;
	while( moreSources && bufPos <= gathererBufSize )
		{
		/* Wait for data to become available from any of the sources, with a
		   timeout of 10 seconds.  This adds even more randomness since data
		   becomes available in a nondeterministic fashion.  Kudos to HP's QA
		   department for managing to ship a select() which breaks its own
		   prototype */
		tv.tv_sec = 10;
		tv.tv_usec = 0;
#if defined( __hpux ) && ( OS_VERSION == 9 )
		if( select( maxFD + 1, ( int * ) &fds, NULL, NULL, &tv ) == -1 )
#else
		if( select( maxFD + 1, &fds, NULL, NULL, &tv ) == -1 )
#endif /* __hpux */
			break;

		/* One of the sources has data available, read it into the buffer */
		for( i = 0; dataSources[ i ].path != NULL; i++ )
			if( dataSources[ i ].pipe != NULL && \
				FD_ISSET( dataSources[ i ].pipeFD, &fds ) )
				{
				size_t noBytes;

				if( ( noBytes = fread( gathererBuffer + bufPos, 1,
									   gathererBufSize - bufPos,
									   dataSources[ i ].pipe ) ) == 0 )
					{
					if( my_pclose( &dataSources[ i ] ) == 0 )
						{
						int total = 0;

						/* Try and estimate how much entropy we're getting
						   from a data source */
						if( dataSources[ i ].usefulness )
							if( dataSources[ i ].usefulness < 0 )
								total = ( dataSources[ i ].length + 999 ) / \
										-dataSources[ i ].usefulness;
							else
								total = dataSources[ i ].length / \
										dataSources[ i ].usefulness;
#ifdef DEBUG_RANDOM
						printf( "%s %s contributed %d bytes (compressed), "
								"usefulness = %d\n", dataSources[ i ].path,
								( dataSources[ i ].arg != NULL ) ? \
								dataSources[ i ].arg : "",
								dataSources[ i ].length, total );
#endif /* DEBUG_RANDOM */
						usefulness += total;
						}
					dataSources[ i ].pipe = NULL;
					}
				else
					{
					int currPos = bufPos;
					int endPos = bufPos + noBytes;

					/* Run-length compress the input byte sequence */
					while( currPos < endPos )
						{
						int ch = gathererBuffer[ currPos ];

						/* If it's a single byte, just copy it over */
						if( ch != gathererBuffer[ currPos + 1 ] )
							{
							gathererBuffer[ bufPos++ ] = ch;
							currPos++;
							}
						else
							{
							int count = 0;

							/* It's a run of repeated bytes, replace them with
							   the byte count mod 256 */
							while( ( ch == gathererBuffer[ currPos ] ) && \
								   currPos < endPos )
								{
								count++;
								currPos++;
								}
							gathererBuffer[ bufPos++ ] = count;
							noBytes -= count - 1;
							}
						}

					/* Remember the number of (compressed) bytes of input we
					   obtained */
					dataSources[ i ].length += noBytes;
					}
				}

		/* Check if there is more input available on any of the sources */
		moreSources = FALSE;
		FD_ZERO( &fds );
		for( i = 0; dataSources[ i ].path != NULL; i++ )
			if( dataSources[ i ].pipe != NULL )
				{
				FD_SET( dataSources[ i ].pipeFD, &fds );
				moreSources = TRUE;
				}
		}
	gathererInfo->usefulness = usefulness;
	gathererInfo->noBytes = bufPos;
#ifdef DEBUG_RANDOM
	printf( "Got %d bytes, usefulness = %d\n", bufPos, usefulness );
#endif /* DEBUG_RANDOM */

	/* "Thou child of the daemon, ... wilt thou not cease...?" -- Acts 13:10 */
	exit( 0 );
	}

/* Wait for the randomness gathering to finish.  Anything that requires the
   gatherer process to have completed gathering entropy should call
   waitforRandomCompletion(), which will block until the background process
   completes */

void waitforRandomCompletion( void )
	{
	if( gathererProcess	)
		{
		RESOURCE_DATA msgData;
		GATHERER_INFO *gathererInfo = ( GATHERER_INFO * ) gathererBuffer;
		int quality = gathererInfo->usefulness * 5;	/* 0-20 -> 0-100 */
		int	status;

		/* Wait for the gathering process to finish, add the randomness it's
		   gathered, and detach the shared memory */
		waitpid( gathererProcess, &status, 0 ); /* Should prob.check status */
		setResourceData( &msgData, gathererBuffer, gathererInfo->noBytes );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
						 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
		zeroise( gathererBuffer, gathererBufSize );
		shmdt( gathererBuffer );
		shmctl( gathererMemID, IPC_RMID, NULL );
		gathererProcess = 0;
		}
	}

/* Check whether we've forked and we're the child.  The mechanism used varies
   depending on whether we're running in a single-threaded or multithreaded
   environment, for single-threaded we check whether the pid has changed 
   since the last check, for multithreaded environments this isn't reliable
   since some systems have per-thread pid's so we need to use 
   pthread_atfork() as a trigger to set the pid-changed flag.
   
   Under Aches, calling pthread_atfork() with any combination of arguments or
   circumstances produces a segfault, so we undefine USE_THREADS to force the
   use of the getpid()-based fork detection.  Since later code expects to at
   least find the mutex which protects the forked flag, we define it as a 
   dummy variable here */

#if defined( USE_THREADS ) && defined( _AIX )
  #undef USE_THREADS
  DECLARE_LOCKING_VARS( forkProtection )
#endif /* USE_THREADS && _AIX */

#ifdef USE_THREADS

DECLARE_LOCKING_VARS( forkProtection )
static BOOLEAN forked = FALSE;

BOOLEAN checkForked( void )
	{
	BOOLEAN hasForked;

	/* Read the forked-t flag in a thread-safe manner */
	lockGlobalResource( forkProtection );
	hasForked = forked;
	forked = FALSE;
	unlockGlobalResource( forkProtection );

	return( hasForked );
	}

void setForked( void )
	{
	/* Set the forked-t flag in a thread-safe manner */
	lockGlobalResource( forkProtection );
	forked = TRUE;
	unlockGlobalResource( forkProtection );
	}

#else

BOOLEAN checkForked( void )
	{
	static pid_t originalPID = -1;
	
	/* Set the initial PID if necessary */
	if( originalPID == -1 )
		originalPID = getpid();

	/* If the pid has changed we've forked and we're the child, remember the 
	   new pid */
	if( getpid() != originalPID )
		{
		originalPID = getpid();
		return( TRUE );
		}

	return( FALSE );
	}

#endif /* USE_THREADS */

/* Initialise and clean up any auxiliary randomness-related objects */

void initRandomPolling( void )
	{
	/* Create any required thread synchronization variables and the trust
	   information table */
	initGlobalResourceLock( forkProtection );

	/* If it's multithreaded code, we need to ensure that we're signalled
	   if another thread calls fork().  Hardcoding in the Posix function
	   name at this point is safe because it also works for Solaris threads.
	   We set the forked flag in both the child and the parent to ensure
	   that both sides remix the pool thoroughly */
#ifdef USE_THREADS
	pthread_atfork( NULL, setForked, setForked );
#endif /* USE_THREADS */
	}

void endRandomPolling( void )
	{
	deleteGlobalResourceLock( forkProtection );
	}
