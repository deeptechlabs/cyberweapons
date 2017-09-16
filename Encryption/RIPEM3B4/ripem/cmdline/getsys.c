/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- getsys.c -- System-dependent routines to return various
 *  information from the system or user.
 *
 *  I predict that this module will be the least portable of
 *  the modules in RIPEM, despite efforts on my part to adapt
 *  to different systems.
 *
 *  Mark Riordan  riordanmr@clvax1.cl.msu.edu   10 March 1991
 *  This code is hereby placed in the public domain.
 *
 *  Modified to be able to work even on OS which doesn't have
 *  statfs() function call by Uri Blumenthal  21 Dec 1992
 *                                      uri@watson.ibm.com
 *
 *  Bugfixes to make Macintosh getenvRsrc() re-entrant [oops!]
 *                                      outer 940223
 */

#if defined(sgi) || defined(_AIX)
/* use POSIX flavour termios instead of BSD sgttyb */
#define USE_TERMIOS
#endif

#ifdef SOLARIS
#define _SVID_GETTOD  /* Use the SVID version of gettimeofday */
#endif

#include <stdio.h>
#ifndef IBMRT
#include <stdlib.h>
#endif
#include <string.h>
#include <ctype.h>
#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "getsyspr.h"

#ifdef __STDC__
# define        P(s) s
#else
# define P(s) ()
#endif

static char *GetDefaultHomeDir P((char **));

#ifdef MACTC
#include <console.h>
#include <time.h>
#include <unix.h>
static char *getenvRsrc(short strnum, char **fname);
#else

#ifndef MSDOS
#if defined(__MSDOS__) || defined(_MSDOS)
#define MSDOS
#endif
#endif

#if defined(MSDOS)
#include <time.h>
#include <string.h>
#include <dos.h>
#ifdef __TURBOC__
#include <alloc.h>
#include <conio.h>
#include <dir.h>
#else
#include <memory.h>
#include <direct.h>
#ifndef IBMRT
#include <malloc.h>
#endif
#ifndef __GNUC__
#include <conio.h>
#endif
#endif
#endif

#ifdef WINNT
#include <time.h>
#include <string.h>
#include <dos.h>
#include <io.h>
#endif

#ifdef UNIX
#ifdef USE_TERMIOS
#include <termios.h>
#include <time.h>
#include <unistd.h>
#else
#include <sgtty.h>
#endif
#include <sys/time.h>
#endif

#ifdef USEBSD
#include <sys/types.h>
#include <sys/resource.h>
#if !defined(sgi) && !defined(sco) && !defined(apollo)
#ifdef ultrix
#include <sys/param.h>
#include <sys/mount.h>
#else
#if defined(I386BSD) || defined(_IBMESA) || defined(__alpha)
#ifdef I386BSD
#include <sys/param.h>
#endif
#include <sys/stat.h>
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif
#endif
#else
#include <sys/statfs.h>
#endif

#ifdef __MACH__
#include <libc.h>
#endif
#endif

#ifdef linux
#ifndef DOGETRUSAGE
#define DOGETRUSAGE
#endif
#include <unistd.h>
#include <sys/resource.h>
#endif

#ifdef UNISTD
#include <unistd.h>
#endif
#ifdef HP
#include <sys/unistd.h>
#endif
#ifdef AIX
#if defined(_AIX370) || defined(ps2)
#include <sys/stat.h>
#else
#include <sys/statfs.h>
#endif /* _AIX370 | ps2 */
#include <limits.h>
#endif

#ifdef UNIX
#include <pwd.h>
#endif

#ifdef SYSV
#include <sys/types.h>
#if defined(sgi) || defined(MOTOROLA) || defined(sco) || defined(SVR4) || defined(SVRV32)
#include <sys/statfs.h>
#else
#include <statfs.h>
#endif

#if defined(SVR4)
#include <sys/time.h>
#ifndef SOLARIS
#include <sys/rusage.h>
#endif
#include <sys/resource.h>
#endif

#endif

#ifdef _MSC_VER
#if _MSC_VER >= 700
#define REGS _REGS
#endif
#endif

#ifndef MSDOS
FILE *userstream;
#endif

#ifdef MSDOS
#if !defined(OS2) && !defined(__GNUC__) && !defined(WINNT)
#define TIMER_OK
#endif

#define TIMER_PORT                     0x40
#define TIMER_MODE_OFFSET              3
#define TIMER_SHIFT_SELECT_COUNTER     6
#define TIMER_SHIFT_READ_LOAD          4
#define TIMER_SHIFT_MODE               1
#endif

#endif
/* endif above is for ifdef MACTC */

#define LINESIZE 120

#define MAX_X520_AVA_TYPE 20
static char *X520_AVA_TYPES[MAX_X520_AVA_TYPE + 1] = {
  "unknownType", "type1", "type2", "CN", "type4", "type5", "C", "L", "ST",
  "SA", "O", "OU", "T", "type13", "type14", "type15", "type16", "PC",
  "type18", "type19", "TEL"
};

#define MAX_PKCS9_AVA_TYPE 1
static char *PKCS9_AVA_TYPES[MAX_PKCS9_AVA_TYPE + 1] = {
  "unknownType", "EMAIL"
};

#define LEN_OF_MONTH(year, month) \
  ((((year) % 4) || (month) != 2) ? MONTH_LENS[((month)-1)] : 29)

#define SECONDS_IN_DAY ((UINT4)3600 * (UINT4)24)

static unsigned int MONTH_LENS[] =
  {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

char *ERROR_MALLOC = "Cannot allocate memory";

extern R_RANDOM_STRUCT *RandomStructPointer;
extern int RandomStructInitialized;

/* homeDir points to a (char *) containing the name of the RIPEM home
     directory, which should be a malloced string.  homeDir is passed
     by reference so this can reallocate it if necessary to add an
     ending directory seperator as required by OpenRIPEMDatabase.
   If *homeDir is (char *)NULL, this will try to set it to a default
     value, such as ~/.ripemhome for Unix.  If a default directory is
     not listed for the running platform, this returns an error.
   This tries to open 'crls' for append in the home dir in order to
     test if the directory exists and can be written to.  If not, this
     returns an error.
   This assumes homeDir itself is not NULL.
   ripemInfo is used for the errMsgTxt buffer and debugStream.
   Returns NULL for success, otherwise error.
 */
char *EstablishRIPEMHomeDir (homeDir, ripemInfo)
char **homeDir;
RIPEMInfo *ripemInfo;
{
  BOOL createdHomeDir;
  FILE *crlsFile;
  char *crlsPath = (char *)NULL, *errorMessage = (char *)NULL;
  unsigned int homeDirLen;

  if (*homeDir == (char *)NULL) {
    /* home dir has not yet been specified. Try to find a default.
       GetDefaultHomeDir returns an error if there is no default.
     */
    if ((errorMessage = GetDefaultHomeDir (homeDir)) != (char *)NULL)
      return (errorMessage);
  }

  homeDirLen = strlen (*homeDir);
  if (homeDirLen == 0)
    return ("The specified RIPEM home directory is blank. You must supply a directory name.");

  /* Try to make sure there is the correct separator between the
       directory and the file name.  E.g. on UNIX, ensure an ending /
     If we don't recognize the machine type, then just hope the user
       already put the right separator.
     Assume only one of UNIX, MSDOS, MACTC, etc. are set.
     We know homeDirLen > 0, so we can check [homeDirLen - 1].
   */
#ifdef UNIX
  if ((*homeDir)[homeDirLen - 1] != '/') {
    if (StrConcatRealloc (homeDir, "/") == (char *)NULL)
      return (ERROR_MALLOC);
  }
#endif

#ifdef MSDOS
  if ((*homeDir)[homeDirLen - 1] != '\\' &&
      (*homeDir)[homeDirLen - 1] != ':') {
    if (StrConcatRealloc (homeDir, "\\") == (char *)NULL)
      return (ERROR_MALLOC);
  }
#endif

#ifdef MACTC
  if ((*homeDir)[homeDirLen - 1] != ':') {
    if (StrConcatRealloc (homeDir, ":") == (char *)NULL)
      return (ERROR_MALLOC);
  }
#endif

  /* For error, break to end of do while (0) block. */
  do {
    /* Recompute since it may have changed. */
    homeDirLen = strlen (*homeDir);

    /* Now test for the existence of the home dir by trying to open
         the crls file for append.  This will create the file
         (but not the directory) if it doesn't exist. */
    if ((crlsPath = (char *)malloc (homeDirLen + 5)) == (char *)NULL) {
      errorMessage = ERROR_MALLOC;
      break;
    }
    strcpy (crlsPath, *homeDir);
    strcat (crlsPath, "crls");

    if ((crlsFile = fopen (crlsPath, "a")) != (FILE *)NULL) {
      /* Successfully opened, so just close it and finish. */
      fclose (crlsFile);
      break;
    }

    /* Couldn't open the file.  Try to create the directory.
       Be sure to remove the separator that was added above (if needed)
         and put it back after creating the directory.
       We set createdHomeDir to TRUE on success and check it after
         trying to create it for each of the platforms below.
     */
    if (ripemInfo->debug > 1)
      fprintf (ripemInfo->debugStream,
               "Trying to create directory \"%s\"\n", *homeDir);
    createdHomeDir = FALSE;

#ifdef UNIX
    /* We know the directory path ends in a '/' so remove it and try
         to create the directory.
     */
    (*homeDir)[homeDirLen - 1] = '\0';

    /* Set mask to inherit all rights from parent directory. */
    if (mkdir (*homeDir, 0xffff) == 0) {
      createdHomeDir = TRUE;

      /* Put back the separator */
      (*homeDir)[homeDirLen - 1] = '/';
    }
#endif

#ifdef MSDOS
    /* If the path is a drive specification, don't bother trying
         to create it. */
    if ((*homeDir)[homeDirLen - 1] != ':') {
      /* We know the directory path ends in a '\\' so remove it and try
           to create the directory.
       */
      (*homeDir)[homeDirLen - 1] = '\0';

      if (mkdir (*homeDir) == 0) {
        createdHomeDir = TRUE;

        /* Put back the separator */
        (*homeDir)[homeDirLen - 1] = '\\';
      }
    }
#endif

#ifdef MACTC
    /* We know the directory path ends in a ':' so remove it and try
         to create the directory.
     */
    (*homeDir)[homeDirLen - 1] = '\0';

    // Note: this needs to be filled in with the correct call
    if (Mac-make-directory-function (*homeDir) == 0) {
      createdHomeDir = TRUE;

      /* Put back the separator */
      (*homeDir)[homeDirLen - 1] = ':';
    }
#endif

    if (!createdHomeDir) {
      sprintf (ripemInfo->errMsgTxt,
               "Can't create or write to RIPEM home directory \"%s\"",
               *homeDir);
      errorMessage = ripemInfo->errMsgTxt;
      break;
    }

    /* The directory has been created.  OpenRIPEMDatabase will take care
         of returning an error message if we cannot write to the directory. */
  } while (0);

  free (crlsPath);
  return (errorMessage);
}

/* Set *defaultHomeDir to an allocated string containing the name of the
     default RIPEM home directory.  The calling routine is responsible for
     freeing the allocated memory.
   If there is no default directory available for the running platform,
     this returns an error.
   This assumes defaultHomeDir itself is not NULL.
   Returns NULL for OK, otherwise error.
 */
static char *GetDefaultHomeDir (defaultHomeDir)
char **defaultHomeDir;
{
  /* Default result to NULL. */
  *defaultHomeDir = (char *)NULL;

#ifdef UNIX
  GetUserHome (defaultHomeDir);
  if (*defaultHomeDir == (char *)NULL)
    return (ERROR_MALLOC);
  if (StrConcatRealloc (defaultHomeDir, "/.ripemhome/") == (char *)NULL)
    return (ERROR_MALLOC);
#endif

#ifdef MSDOS
  if (StrCopyAlloc (defaultHomeDir, "C:\\RIPEMHOM\\") == (char *)NULL)
    return (ERROR_MALLOC);
#endif

#ifdef MACTC
  if (StrCopyAlloc (defaultHomeDir, need a folder named "RIPEM Home" in the
                    system preferences file) == (char *)NULL)
    return (ERROR_MALLOC);
#endif

  if (*defaultHomeDir == (char *)NULL)
    return
  ("This platform has no default RIPEM home directory. You must specify one.");

  /* Success */
  return ((char *)NULL);
}

/* Write the dn to the stream in the format
   "CN = User, OU = Persona Certificate ...".
   This uses a + instead of , for AVAs on the same level.
   This does not write a newline at the end.
 */
void WritePrintableName (stream, dn)
FILE *stream;
DistinguishedNameStruct *dn;
{
  int rdn, ava;

  for (rdn = MAX_RDN - 1; rdn >= 0; --rdn) {
    if (dn->RDNIndexStart[rdn] == -1)
      continue;

    for (ava = dn->RDNIndexStart[rdn]; ava <= dn->RDNIndexEnd[rdn]; ++ava) {
      /* Output the AVA.  AVA_TYPES[0] is "unknown" for bad types.
       */
      if ((dn->AVATypes[ava] & 0xff00) == PKCS9_ATTRIBUTE) {
        fputs ((dn->AVATypes[ava] & 0xff) >
               MAX_PKCS9_AVA_TYPE ?
               PKCS9_AVA_TYPES[0] : PKCS9_AVA_TYPES[(dn->AVATypes[ava])&0xff],
               stream);
      }
      else {
        fputs (dn->AVATypes[ava] >
               MAX_X520_AVA_TYPE ?
               X520_AVA_TYPES[0] : X520_AVA_TYPES[dn->AVATypes[ava]],
               stream);
      }
      fputs (" = ", stream);
      fputs (dn->AVAValues[ava], stream);

      if (ava == dn->RDNIndexEnd[rdn]) {
        /* This is the last AVA in the RDN, so put a comma.
           But don't put anything if it is the last RDN. */
        if (rdn != 0)
          fputs (", ", stream);
      }
      else
        /* Put a plus because there are more AVAs in this RDN. */
        fputs (" + ", stream);
    }
  }
}

/*--- function StrCopyAlloc -------------------------------------
 *
 *  Copy a string, allocating space for it.
 *
 *   Entry: target points to a pointer to a character.
 *        source points to z zero-terminated string that
 *       we want to copy.
 *
 *  Exit: target contains a pointer to a newly-allocated
 *               piece of memory that contains a copy of
 *             source.
 *        Returns NULL if alloc unsuccessful, else
 *          returns target.
 *  Note: this is a copy of strcpyalloc which is internal to
 *    the RIPEM library.
 */
char *StrCopyAlloc(target,source)
char **target;
char *source;
{
  *target = (char *) malloc(strlen(source)+1);
  if(*target) {
    strcpy(*target,source);
  }
  return *target;
}

/*--- function StrConcatRealloc ------------------------------
 *
 *  Append a string to another string, reallocating memory
 *  for the target string to ensure there's room.
 *
 *  Entry:  target points to a pointer to a string to
 *             be appended to.
 *        source points to a string to append.
 *
 *   Exit:  target now points to a possibly different address,
 *             a pointer to the combined string.
 *  Note: this is a copy of strcatrealloc which is internal to
 *    the RIPEM library.
 */
char *StrConcatRealloc (target,source)
char **target;
char *source;
{
  *target = (char *)R_realloc
    (*target, strlen (source) + strlen (*target) + 1);
  if (*target) {
    strcat (*target, source);
  }
  return *target;
}

/*  Determine whether two character prefix strings match.
 *  Case insensitive.
 *
 *  Entry:  str      is a string.
 *      pattern  is a pattern to which we are comparing.
 *      nchars   is the number of characters to compare.
 *
 *  Exit:   Returns TRUE iff the prefix strings match.
 */
int matchn(str,pattern,nchars)
char *str;
char *pattern;
int nchars;
{
  char ch1, ch2;
  
  do {
    ch1 = (char) (islower(*str) ? toupper(*str) : *str);
    ch2 = (char) (islower(*pattern) ? toupper(*pattern) : *pattern);
    if(ch1 != ch2) return FALSE;
    str++; pattern++; nchars--;
  } while(nchars);
  
  return TRUE;
}

/*--- function GetRandomBytes ----------------------------------------
 *
 *  Return an array of random bytes depending upon certain
 *  transient system-dependent information.
 *  Don't bet your life on the "randomness" of this information.
 *
 *  Entry    maxbytes is the maximum number of bytes to return.
 *           ripemInfo is used only for debug.
 *
 *  Exit     bytes    contains a number of bytes containing
 *                    such information as the time, process
 *                    resources used, and other information that
 *                    will change from time to time.
 *           Returns the number of bytes placed in "bytes".
 */
int
GetRandomBytes(bytes,maxbytes,ripemInfo)
unsigned char *bytes;
int maxbytes;
RIPEMInfo *ripemInfo;
{
#ifdef MAX_PORTABLE
  return 0;
#else
  int numbytes = 0, thissize;
#ifdef MACTC
  clock_t myclock;
  time_t mytime;
   
  /* Obtain the elapsed processor time */
  
  if( (thissize = sizeof(myclock)) <= maxbytes ) {
    myclock = clock();
    CopyRandomBytes
      (&myclock,thissize,bytes,&numbytes,&maxbytes,
       "elapsed processor time", ripemInfo);
  }
  
  /* Get the time of day.  */
  
  if( (thissize = sizeof(mytime)) <= maxbytes ) {
    time(&mytime);
    CopyRandomBytes
      (&mytime,thissize,bytes,&numbytes,&maxbytes, "time of day", ripemInfo); 
  }
  
  if((thissize=sizeof(long int)) <= maxbytes) {
    long int ncore;
    
    ncore = FreeMem();
    CopyRandomBytes(&ncore,thissize,bytes,&numbytes,&maxbytes,
                    "free heap space", ripemInfo);    
  }
#else
  
#ifdef MSDOS
  unsigned char buf[4];
  time_t myclock;
  time_t mytime;
#if 0
  size_t biggestfree;
#endif

  /* Obtain the elapsed processor time (not really too useful).
   */
  if((thissize=sizeof(myclock)) <= maxbytes) {
    myclock = clock();
    CopyRandomBytes(&myclock,thissize,bytes,&numbytes,&maxbytes,
                    "elapsed processor time", ripemInfo);     
  }

#if 0
  /* Get the size of the largest free memory block. */
  
  if((thissize=sizeof(size_t)) <= maxbytes) {
    biggestfree = _memmax();
    CopyRandomBytes(&biggestfree,thissize,bytes,&numbytes,&maxbytes,
                    "largest free mem block", ripemInfo);
  }
   
  if((thissize=sizeof(unsigned long int)) <= maxbytes) {
    unsigned long int ncore;
     
    ncore = coreleft();
    CopyRandomBytes(&ncore,thissize,bytes,&numbytes,&maxbytes,
                    "free heap space", ripemInfo);    
  }
#endif

#if !defined(WINNT) && !defined(__GNUC__) && !defined(__TURBOC__)
  {
    struct _diskfree_t diskspace;
    /* Get the amount of free space on the default DOS disk. 
     * Use DOS function 0x36.
     */

    if((thissize=sizeof(diskspace)) <= maxbytes) {
      _dos_getdiskfree(0,&diskspace);
      CopyRandomBytes(&diskspace,thissize,bytes,&numbytes,&maxbytes,
                      "free space on default drive", ripemInfo);        
    }
  }
#endif

#ifdef __TURBOC__           /*EWS*/
  {
    struct dfree diskspace;
    /* Get the amount of free space on the default DOS disk.
     * Use Turbo C function getdfree
     */
     
    if((thissize=sizeof(diskspace)) <= maxbytes) {
      getdfree(0,&diskspace);
      CopyRandomBytes(&diskspace,thissize,bytes,&numbytes,&maxbytes,
                      "free space on default drive", ripemInfo);
    }
  }
#endif
   
#ifdef __GNUCC__

  union REGS inregs, outregs;
  /* Get the amount of free space on the default DOS disk. */

  if((thissize=sizeof(outregs)) <= maxbytes) {
    inregs.h.ah = 0x36;  /* DOS function: Get disk free space */
    inregs.h.dl = 0;     /* Drive = default */
    intdos(&inregs,&outregs);
    CopyRandomBytes(&outregs,thissize,bytes,&numbytes,&maxbytes,
                    "free space on default drive", ripemInfo);
  }
  } /* Does this brace really belong? */
#endif

  /* Get the time of day.  */

  if((thissize=sizeof(mytime)) <= maxbytes) {
    time(&mytime);
    CopyRandomBytes(&mytime,thissize,bytes,&numbytes,&maxbytes,
                    "time of day", ripemInfo);
  }

   /* Get some arbitrary bytes from the timer. */
#if defined(TIMER_OK) || defined(__GNUC__)

  if((thissize=2*sizeof(buf[0])) <= maxbytes) {
#if defined(__GNUC__) || defined(__TURBOC__)
    buf[0] = (unsigned char)inportb(TIMER_PORT);
    buf[1] = (unsigned char)inportb(TIMER_PORT);
#else
    buf[0] = (unsigned char)_inp(TIMER_PORT);
    buf[1] = (unsigned char)_inp(TIMER_PORT);
#endif
    CopyRandomBytes(buf,thissize,bytes,&numbytes,&maxbytes,
                    "2 timer bytes", ripemInfo);
  }

#if defined(__GNUC__)
  /* Get bytes from screen */
  thissize = maxbytes;
  if(thissize > 0) {
    extern unsigned int ScreenPrimary[];
    
    CopyRandomBytes(ScreenPrimary,thissize,bytes,&numbytes,
                    &maxbytes,"Chars on screen", ripemInfo);
  }
#endif

#endif


#endif

#ifdef UNIX
  {
    struct timeval tm;
#ifndef SVR4
    struct timezone tz;
#endif
#ifdef SVR4
#ifndef SOLARIS
    int gettimeofday(struct timeval *);
#endif
#endif
    
    /* Get the time of day.  */

    if((thissize=sizeof(tm)) <= maxbytes) {
#ifdef SVR4
      gettimeofday(&tm);
#else
      gettimeofday(&tm,&tz);
#endif
      CopyRandomBytes(&tm,thissize,bytes,&numbytes,&maxbytes,
                      "time of day (gettimeofday)", ripemInfo);
    }
  }
#endif

#ifdef DOGETRUSAGE

#ifndef RUSAGE_SELF
#define RUSAGE_SELF 0
#endif
  {
    struct rusage myusage;

    /* Get the process resource utilization. */

    if((thissize=sizeof(myusage)) <= maxbytes) { 
      getrusage(RUSAGE_SELF,&myusage);
      CopyRandomBytes(&myusage,thissize,bytes,&numbytes,&maxbytes,
                      "process resource utilization", ripemInfo);
    }
  }
#endif

#ifdef SYSV
#define DOSTAT
#endif

#ifdef DOSTAT
  {
    struct statfs buf;
    char *path;
    
    /* Obtain information about the filesystem on which the user's
     * home directory resides.
     */

    if((thissize=sizeof(struct statfs)) <= maxbytes) {
      GetUserHome(&path);
      statfs(path, &buf, sizeof(struct statfs), 0);
      CopyRandomBytes(&buf,thissize,bytes,&numbytes,&maxbytes,
                      "file system stats on user's home device", ripemInfo);
    }
  }
#else

#ifdef USEBSD
  {
#if defined(_AIX370) || defined(ps2)
#define STATFS struct stat
#else
#ifdef ultrix
#define STATFS struct fs_data
#else
#define STATFS struct statfs
#endif
#endif /* _AIX370 | ps2 */
    STATFS buf;
    char *path;

    /* Obtain information about the filesystem on which the user's
     * home directory resides.  This is only slightly different
     * between SYSV and BSD.
     */

    if((thissize=sizeof(STATFS)) <= maxbytes) {
      GetUserHome(&path);
#if defined(_AIX370) || defined(ps2)
      stat(path, &buf);
#else
      statfs(path, &buf);
#endif /* _AIX370 | ps2 */
      CopyRandomBytes(&buf,thissize,bytes,&numbytes,&maxbytes,
                      "file system stats on user's home device", ripemInfo);
    }
  }
#endif
#endif

#ifdef WINNT
  /* Get info on the files in the current directory.
   */
  {
    long searchhand;
    struct _finddata_t filedata;
    
    searchhand = _findfirst("*.*",&filedata);
    if(searchhand >= 0) {
      do {
        /* The structure is >> 20 bytes, but usually most of it
         * does not contain useful info.  Therefore, we 
         * truncate it at this size, because our random byte
         * buffer is only so big.
         */
        thissize = 20;
        if(thissize <= maxbytes) {
          CopyRandomBytes(&filedata.time_write,thissize,bytes,
                          &numbytes,&maxbytes,"WinNT file info", ripemInfo);
        }
      } while(!_findnext(searchhand,&filedata));
      _findclose(searchhand);
    }
  }
#endif

#endif
/* #endif above is for ifdef MACTC */

  return (numbytes);
#endif
}

/*--- function CopyRandomBytes -------------------------------------
 *
 *  Copy system-derived data into the user's output buffer.
 *  Optionally report on what's going on.
 *
 *  Entry:      thisBuf         contains "random" bytes.
 *              thisSize        is the number of bytes in inBuf to add.
 *              userbuf  is the start of the user buffer.
 *              numbytes        is the current index into userbuf for where we
 *                              should add this data.
 *              maxbytes        is the number of bytes left in userbuf.
 *              message         is a text string to output for debugging.
 *              ripemInfo is used only for debug.
 *
 *       Exit:  numbytes has been updated.
 *              maxbytes has been updated.
 */
void
CopyRandomBytes(thisBuf,thisSize,userBuf,numBytes,maxBytes,message,ripemInfo)
void *thisBuf;
int thisSize;
unsigned char *userBuf;
int *numBytes;
int *maxBytes;
char *message;
RIPEMInfo *ripemInfo;
{
  int j, bytes_to_copy;

  bytes_to_copy = thisSize <= *maxBytes ? thisSize : *maxBytes;
  if(ripemInfo->debug>1) {
    fprintf(ripemInfo->debugStream,"%d bytes of %s obtained: ",bytes_to_copy,
            message);
    for(j=0; j<bytes_to_copy; j++) {
      if(j%36 == 0) fprintf(ripemInfo->debugStream,"\n ");
      fprintf(ripemInfo->debugStream,"%-2.2x",((unsigned char *)(thisBuf))[j]);
    }
    putc('\n',ripemInfo->debugStream);
  }
  memcpy((char *)userBuf+*numBytes,thisBuf,bytes_to_copy);
  *numBytes += bytes_to_copy;
  *maxBytes -= bytes_to_copy;
}

/*--- function ReportCPUTime ----------------------------------------
 *
 *  Print a report on debug output indicating current process
 *  CPU time consumption.
 *
 *  Entry:      msg     is a message to add to the report.
 *              ripemInfo is used only for debug.
 */
void
ReportCPUTime(msg, ripemInfo)
char *msg;
RIPEMInfo *ripemInfo;
{
#ifdef DOGETRUSAGE

#ifndef RUSAGE_SELF
#define RUSAGE_SELF 0
#endif
  struct rusage myusage;

  /* Get the process resource utilization. */

  getrusage(RUSAGE_SELF,&myusage);
  fprintf(ripemInfo->debugStream,"%s:\n",msg);
  fprintf(ripemInfo->debugStream,"Process CPU time = %ld.%-6.6ldu %ld.%-6.6lds\n",
          myusage.ru_utime.tv_sec,myusage.ru_utime.tv_usec,
          myusage.ru_stime.tv_sec,myusage.ru_stime.tv_usec);
#else
  msg = *(&msg);                                 /* silence compiler warning */
  ripemInfo = *(&ripemInfo);                     /* silence compiler warning */
#endif
}


/*--- function GetUserInput -----------------------------------------
 *
 *  Get a string of bytes from the user, intended for use as
 *  a seed to a pseudo-random number generator or something similar.
 *
 *  Return not only those bytes but also an array of timing
 *  information based on the inter-keystroke times.
 *  This maximizes the amount of "random" information we obtain
 *  from the user.
 *
 *    Entry *num_userbytes   is the maximum number of bytes we can
 *                              put in userbytes.
 *          *num_timebytes   is the maximum number of bytes we can
 *                              put in timebytes.
 *          echo             is TRUE iff we want to echo characters
 *                           typed by the user.  (Non-echoing is
 *                           implemented only for MS-DOS.)
 *
 *    Exit  userbytes        is an array of bytes entered by the
 *                           user, not including the newline.
 *          *num_userbytes   is the number of data bytes in this array.
 *          timebytes        is an array of bytes reflecting inter-
 *                           keystroke timings.  (Only for MS-DOS.)
 *          *num_timebytes   is the number of data bytes in this array.
 */
void
GetUserInput(userbytes,num_userbytes,timebytes,num_timebytes,echo)
unsigned char userbytes[];
int *num_userbytes;
unsigned char timebytes[];
int *num_timebytes;
int echo;
{
#ifdef USE_TERMIOS
  int tvbuf[1024]; int tvc; int ii;
  struct timeval rtm;
#ifndef SVR4
  struct timezone rtz;
#endif
#endif
  int max_user = *num_userbytes;
#if defined(TIMER_OK) || defined(MACTC)
  int max_time = *num_timebytes;
#endif
  int done = 0;
  unsigned char *userby = userbytes;
  unsigned char *timeby = timebytes;
  int ch;
#ifdef TIMER_OK
  unsigned int counter = 1;
  unsigned char byte1, byte2;
  int databyte;
#endif
  
#ifdef MACTC
  clock_t time0, time1, time2;
  int contty = 0;
  
  time0 = time1 = clock();
  if( contty = isatty(fileno(stdin)) ) {
    if( echo ) csetmode(C_CBREAK, stdin); 
    else csetmode(C_RAW, stdin);
  }
  
  while( !done ) {  
    if( contty ) while( (ch = fgetc(stdin)) == EOF );
    else ch = fgetc(stdin);
    
    done = ((ch == '\r') || (ch == '\n')) || (ch == EOF);
    if( !done && !echo ) putc('*', stderr);
    else if( done && !echo ) putc('\n', stderr);
    
    if( !done && (max_user > 0) ) {
      *userby++ = (unsigned char)ch;
      max_user--;                                     
    }
    
    if( max_time > 0 ) {
      time2 = clock();
      *timeby++ = (unsigned char)(time2 - time1);
      max_time--;
      time1 = time2;
    }
  }
  
  if( contty ) csetmode(C_ECHO, stdin);
  
  if( max_time > 0 ) {
    time1 = clock();
    *timeby++ = (unsigned char)(time1 - time0);
    max_time--;
  }
#else

#ifdef UNIX
#ifdef USE_TERMIOS
  struct termios mytty, origtty;
#else
  struct sgttyb mytty, origtty;
#endif
  FILE *userstream;
  int in_file_num;
#endif

#ifdef TIMER_OK
  /* Set the timer to its highest resolution.
   * This gives 65536*18.2 ticks/second--pretty high resolution.
   * There *are* some things
   * that a PC can do that a multiuser system can't!
   */

  databyte = (2<<TIMER_SHIFT_SELECT_COUNTER) |
    (3<<TIMER_SHIFT_READ_LOAD) |
    (3<<TIMER_SHIFT_MODE);
  outp(TIMER_PORT+TIMER_MODE_OFFSET,databyte);
  outp(TIMER_PORT+2,0xff&counter);
  outp(TIMER_PORT+2,counter>>8);
  byte1 = (unsigned char) inp(TIMER_PORT);
  byte2 = byte1; /* Get rid of "byte1 never used" warning */
  byte2 = (unsigned char) inp(TIMER_PORT);
  if(max_time > 0) {
    *(timeby++) = byte2;
    max_time--;
  }
#endif

#ifdef UNIX
  userstream = fopen("/dev/tty","r");
  if(!userstream) {
    fputs("Unable to read from terminal\n",stderr);
  }
  in_file_num = fileno(userstream);
#endif

#ifdef UNIX
#ifdef USE_TERMIOS
  /* set raw mode and turn of echo is requested */
  tcdrain(in_file_num);
  tcgetattr(in_file_num, &origtty);
  memcpy((char *)&mytty,(char *)&origtty,sizeof mytty);
  tvc = 0;
  if (!echo)
    mytty.c_lflag &= ~(ECHO | ICANON);
  else
    mytty.c_lflag &= ~(ICANON);
  mytty.c_cc[VMIN] = 1;
  mytty.c_cc[VTIME] = 0;
  tcsetattr(in_file_num, TCSANOW, &mytty);
#else
  if(!echo) {
    ioctl(in_file_num,TIOCGETP,&origtty);
    memcpy((char *)&mytty,(char *)&origtty,sizeof mytty);
    mytty.sg_flags &= (-1 - ECHO);
    ioctl(in_file_num,TIOCSETP,&mytty);
  }
#endif
/* USE_TERMIOS */
#endif
/* UNIX */

  while(!done) {
#ifdef MSDOS
    if(echo) {
#if defined(__GNUC__) || defined(__TURBOC__) 
      ch = getch();
      putc(ch,stderr);
    } else {
      ch = getch();
    }
#else
    ch = _getche();
  } else {
    ch = _getch();
  }
#endif
#ifdef TIMER_OK
  byte1 = (unsigned char)inp(TIMER_PORT);
  byte2 = (unsigned char)inp(TIMER_PORT);
#endif
#else
  ch = fgetc(userstream);
#ifdef USE_TERMIOS
#ifdef SVR4
  gettimeofday(&rtm);
#else
  gettimeofday(&rtm,&rtz);
#endif
  if (tvc < 1024)
    tvbuf[tvc++] = rtm.tv_usec;
/* SVR4 */
#endif
/* USE_TERMIOS */
#endif
/* MSDOS */
  done = (ch=='\r') || (ch=='\n');
  if(!done) {
    if(max_user > 0) {
      *(userby++) = (unsigned char)ch;
      max_user--;
    }
#ifdef TIMER_OK
    if(max_time > 0) {
      *(timeby++) = byte2;
      max_time--;
    }
#ifdef DEBUG
    printf("ch=%c byte=%d\n",ch,byte2);
#endif
#endif
  }
  } /* Does this brace really belong? */
#ifdef MSDOS
  fputc('\n',stderr);
#else
  if(!echo) fputc('\n',stderr);
#endif

#endif
  /* endif above is for MACTC */

  *num_userbytes = (int)(userby - userbytes);
  *num_timebytes = (int)(timeby - timebytes);

#ifdef UNIX
#ifdef USE_TERMIOS
  tcdrain(in_file_num);
  tcsetattr(in_file_num, TCSANOW, &origtty);
  if (RandomStructInitialized) {
    R_RandomUpdate(RandomStructPointer, (POINTER) &tvbuf[0],
                   (unsigned int)(sizeof(int)*tvc));
  }
#else
  if (!echo)
    ioctl(in_file_num,TIOCSETP,&origtty);
#endif

  fclose(userstream);
#endif
}


/*--- function GetUserName ------------------------------------------
 *
 *  Return the name of the user.
 *  Under Unix, get the user's name using time-honored techniques.
 *  Under MS-DOS, grab the value of an environment variable, or
 *  just use "me" if there's no such variable.
 *
 *  Entry:  name     is a pointer to a pointer.
 *
 *  Exit:   name     is the name of the user, zero-terminated.
 *          Returns non-zero if the username needs to have
 *            the hostname appended to it.
 */
int
GetUserName(name)
char **name;
{
  char *cptr=NULL;
  int need_host = 0;
   
#ifdef MACTC
  cptr = getlogin();
  GetEnvFileName(USER_NAME_ENV, USER_NAME_DEFAULT, name);
  if(cptr != NULL) {
    StrConcatRealloc(name, ",");
    StrConcatRealloc(name, cptr);
  }
#else 
   
#ifdef UNIX
  struct passwd *pwptr;
#endif
#if defined(ULTRIX) || defined(_AIX370) || defined(ps2)
  extern char *getlogin();
#endif

  cptr = getenv(USER_NAME_ENV);

#if defined(UNIX) && !defined(MAX_PORTABLE)

  if(!cptr) {
    cptr = getlogin();
    if(!cptr) {
      pwptr = getpwuid(getuid());
      if(pwptr) {
        cptr = pwptr->pw_name;
      } else {
        cptr = NULL;
      }
    }
      if(cptr) need_host = 1;
  }
#endif
  if(!cptr) cptr = USER_NAME_DEFAULT;
   
  StrCopyAlloc(name,cptr);
#endif
/* endif above is for MACTC */
  return need_host;
}

/*--- function GetPasswordFromUser ---------------------------------
 *
 *  Obtain a password, either from an environment variable
 *  or from the user at the keyboard.
 */
unsigned int
GetPasswordFromUser(prompt,verify,password,maxchars)
char *prompt;
BOOL verify;
unsigned char *password;
unsigned int maxchars;
{
  unsigned int num_userbytes = maxchars, num_timebytes=0;
  unsigned char timebytes[4];
  int echo=FALSE;
  BOOL pw_ok = FALSE;

  do {
    num_userbytes = maxchars;
    fputs(prompt,stderr);
    GetUserInput
      (password,(int *)&num_userbytes,timebytes,(int *)&num_timebytes,echo);
    if(verify) {
      unsigned char verifybytes[MAX_PASSWORD_SIZE];
      int num_verifybytes=(int)maxchars;
      
      fputs("Enter again to verify: ",stderr);
      num_timebytes = 0;
      GetUserInput
        (verifybytes,(int *)&num_verifybytes,timebytes,(int *)&num_timebytes,
         echo);
      if((int)num_userbytes != num_verifybytes ||
         strncmp((char *)password,(char *)verifybytes,num_userbytes)) {
        fputs("Passwords do not match.  Please enter them again.\n",stderr);
      } else {
        pw_ok = TRUE;
      }
    } else {
      pw_ok = TRUE;
    }
  } while(!pw_ok);

  return num_userbytes;
}


/*--- function GetUserAddress -------------------------------------------
 *
 *  Return the zero-terminated user's email address.
 *  For non-Unix hosts, it's just the user's name.
 *  For Unix, it's the name followed by @<hostname>.
 *
 *  Entry:  address  is a pointer to a pointer.
 *
 *  Exit:   address  contains the user's email address (as close
 *                   as we can figure it).
 */
void
GetUserAddress(address)
char **address;
{
#ifdef UNIX
#define HOSTSIZE 256
  char hostname[HOSTSIZE],domainname[HOSTSIZE];
#endif

  if(GetUserName(address)) {
#ifdef UNIX
#ifdef SVR4
#ifndef SOLARIS
    int gethostname(const char *, int);
#endif
    int getdomainname(const char *, int);
#endif

    /* Add "@hostname" to the username unless it's already there.  */
    if(!strchr(*address,'@')) {
      if(!gethostname(hostname,HOSTSIZE)) {
        StrConcatRealloc(address,"@");
        StrConcatRealloc(address,hostname);
#if !defined(IBMRT) && !defined(I386BSD) && !defined(linux) && !defined(SVRV32) && !defined(apollo)
        /* Now add the domain name, unless it's null. */
        if(!getdomainname(domainname,HOSTSIZE)) {
          if(domainname[0] && ! (strlen (domainname) == 6 &&
                                 matchn (domainname, "noname", 6))) {
            StrConcatRealloc(address,".");
            StrConcatRealloc(address,domainname);
          }
        }
#endif
      }
    }
#endif
  }
}

/*--- function GetUserHome --------------------------------------
 *
 *  Return the pathname of the user's home directory.
 *  Implemented only under Unix; for other systems, just returns
 *  a string of 0 length followed by a zero byte.
 *
 *  Entry:  home      points to a pointer which we desire to be
 *                    be updated to point to the user's home dir.
 *
 *  Exit:   home      contains the home pathname, followed by a
 *                    zero byte.
 */
void
GetUserHome(home)
char **home;
{
#if defined(UNIX) && !defined(MAX_PORTABLE)
  struct passwd *pwptr;

  pwptr = getpwuid(getuid());

  if(pwptr) {
    StrCopyAlloc(home,pwptr->pw_dir);
  } else {
    StrCopyAlloc(home,"");
  }
#else
  GetEnvFileName(HOME_DIR_ENV, "", home);
#endif
}

/*--- function ExpandFilename ----------------------------------------------
 *
 *  Expand a Unix filename that starts with ~ (indicating that the
 *  user's home directory should be prepended to the filename).
 * 
 *  Entry:  filename points to a filename.
 *
 *  Exit:   filename now points to the expanded file name if applicable,
 *                   else it is unchanged.
 *          Note: the pointer may have been changed.
 */
void
ExpandFilename(fileName)
char **fileName;
{
   char *homedir;
   if((*fileName)[0] == '~') {
      GetUserHome(&homedir);

      if( homedir && (*homedir != '\0') ) {
#ifdef UNIX
         if( homedir[strlen (homedir) - 1] != '/')
            StrConcatRealloc (&homedir, "/");
#elif defined(MSDOS)
         if( homedir[strlen (homedir) - 1] != '\\' &&
            homedir[strlen (homedir) - 1] != ':' )
            StrConcatRealloc (&homedir, "\\");
#else /* MACTC */
         if( homedir[strlen (homedir) - 1] != ':')
            StrConcatRealloc (&homedir, ":");
#endif
      }

      if( !homedir ) return;
      StrConcatRealloc(&homedir,*fileName+1);
      if( homedir ) *fileName = homedir;
   }

}

void Base64EncoderConstructor (encoder)
Base64Encoder *encoder;
{
UNUSED_ARG (encoder)
  /* Nothing to do for constructor. */
}

void Base64EncoderDestructor (encoder)
Base64Encoder *encoder;
{
  R_memset ((POINTER)encoder->buffer, 0, sizeof (encoder->buffer));
}

void Base64EncoderWriteInit (encoder)
Base64Encoder *encoder;
{
  encoder->bufferLen = 0;
}

/* Base64 encode the part and write to outStream.
   Must call Base64EncoderWriteFinal to flush the final output.
 */
void Base64EncoderWriteUpdate (encoder, part, partLen, outStream)
Base64Encoder *encoder;
unsigned char *part;
unsigned int partLen;
FILE *outStream;
{
  unsigned int tempLen, outputLineLen;
  char outputLine[(BASE64_CHUNK_SIZE * 4 / 3) + 1];

  tempLen = BASE64_CHUNK_SIZE - encoder->bufferLen;
  if (partLen < tempLen) {
    /* Just accumulate into buffer */
    R_memcpy
      ((POINTER)(encoder->buffer+encoder->bufferLen), (POINTER)part, partLen);
    encoder->bufferLen += partLen;
    return;
  }

  /* Fill the buffer and encode.
   */
  R_memcpy
    ((POINTER)(encoder->buffer + encoder->bufferLen), (POINTER)part,
     tempLen);
  R_EncodePEMBlock
    ((unsigned char *)outputLine, &outputLineLen, encoder->buffer,
     BASE64_CHUNK_SIZE);
  outputLine[outputLineLen] = '\0';
  fprintf (outStream, "%s\n", outputLine);

  part += tempLen;
  partLen -= tempLen;

  /* Encode as many chunks as possible without copying to the buffer.
   */
  while (partLen >= BASE64_CHUNK_SIZE) {
    R_EncodePEMBlock
      ((unsigned char *)outputLine, &outputLineLen, part, BASE64_CHUNK_SIZE);
    outputLine[outputLineLen] = '\0';
    fprintf (outStream, "%s\n", outputLine);

    part += BASE64_CHUNK_SIZE;
    partLen -= BASE64_CHUNK_SIZE;
  }

  /* Length is now less than the chunk size, so copy remainder to buffer.
   */
  R_memcpy ((POINTER)encoder->buffer, (POINTER)part, partLen);
  encoder->bufferLen = partLen;

  R_memset ((POINTER)outputLine, 0, sizeof (outputLine));
}

void Base64EncoderWriteFinal (encoder, outStream)
Base64Encoder *encoder;
FILE *outStream;
{
  unsigned int outputLineLen;
  char outputLine[(BASE64_CHUNK_SIZE * 4 / 3) + 1];

  R_EncodePEMBlock
    ((unsigned char *)outputLine, &outputLineLen, encoder->buffer,
     encoder->bufferLen);
  outputLine[outputLineLen] = '\0';
  fprintf (outStream, "%s\n", outputLine);

  encoder->bufferLen = 0;
  R_memset ((POINTER)outputLine, 0, sizeof (outputLine));
}

/* Return TRUE if strings are the same, ignoring case, otherwise FALSE.
   [Note, this is similar to the function "match" in the RIPEM library.]
 */
BOOL CaseIgnoreEqual (str,pattern)
char *str;
char *pattern;
{
  char ch1, ch2;

  do {
    ch1 = (char) (islower(*str) ? toupper(*str) : *str);
    ch2 = (char) (islower(*pattern) ? toupper(*pattern) : *pattern);
    if (ch1 != ch2)
      return FALSE;
    str++; pattern++;
  } while(ch1 == ch2 && ch1 && ch2);
  
  if(!ch1 && !ch2)
    return TRUE;
  else
    return FALSE;
}

/* Take the time which is in seconds since 1/1/70 GMT and put the
     date and time into the dateAndTime string of the form 08/24/94 15:45:01
     also in GMT.
   This assumes the date buffer is at least 18 bytes long.
 */
void GetDateAndTimeFromTime (dateAndTime, time)
char *dateAndTime;
UINT4 time;
{
  int year, month, day, hour, minute, second;
  unsigned long tempTime;

  /* Note: this code is taken from put_UTC inside the RIPEM library. */
  
  /* Count up seconds in the years starting from 1970 to bring the time
       down to the number of seconds in a year. */
  year = 70;
  while (time >= 
         (tempTime = year % 4 ?
          (SECONDS_IN_DAY * (UINT4)365) : (SECONDS_IN_DAY * (UINT4)366))) {
    time -= tempTime;
    year++;
  }

  /* Count up seconds in the months starting from 1 to bring the time
       down to the number of seconds in a month. */
  month = 1;
  while (time >=
         (tempTime = SECONDS_IN_DAY * (UINT4)LEN_OF_MONTH (year, month))) {
    time -= tempTime;
    month++;
  }
  
  day = (int)(time / SECONDS_IN_DAY) + 1;
  time -= (UINT4)(day - 1) * SECONDS_IN_DAY;

  hour = (int)(time / ((UINT4)3600));
  time -= (UINT4)hour * (UINT4)3600;

  minute = (int)(time / (UINT4)60);
  time -= (UINT4)minute * (UINT4)60;

  second = (int)time;

  if (year >= 100)
    /* Adjust year 2000 or more to encode as 00 and greater. */
    year -= 100;

  sprintf (dateAndTime, "%02d/%02d/%02d %02d:%02d:%02d",
           month, day, year, hour, minute, second);
}

#ifndef MACTC

/*--- function GetEnvFileName ------------------------------------------
 *
 *  Obtain a filename from an environment variable.
 *  Expand "~" Unix syntax.  Supply a default if the
 *  environment variable cannot be found.
 *
 *  Entry:
 *
 *       Exit:
 */
BOOL
GetEnvFileName(envName,defName,fileName)
char *envName;
char *defName;
char **fileName;
{
  char *cptr = getenv(envName);

  if (!cptr)
    cptr = defName;
#ifdef UNIX
  if(cptr[0] == '~') {
    GetUserHome(fileName);
    StrConcatRealloc(fileName,cptr+1);
  } else {
    StrCopyAlloc(fileName,cptr);
  }
#else
  StrCopyAlloc(fileName,cptr);
#endif
  return TRUE;
}

/*--- function GetEnvAlloc ---------------------------------------------------
 */
BOOL
GetEnvAlloc(envName,target)
char *envName;
char **target;
{
  char *cptr = getenv(envName);
  int found = FALSE;

  if(cptr) {
    StrCopyAlloc(target,cptr);
    found = TRUE;
  } else {
    *target = NULL;
  }
  return found;
}
#else

/*--- Macintosh versions of the above functions, by R. Outerbridge.  */

static char *getenvRsrc(short strnum, char **fname) {
  unsigned char **StrHandle;
  char *cp;

  StrHandle = GetString(strnum);
  if( StrHandle == NULL ) {
    *fname = NULL;
    return( (char *)NULL );
  }
  MoveHHi( (char **)StrHandle );
  HLock( (char **)StrHandle );
  cp = PtoCstr(*StrHandle);
  StrCopyAlloc(fname, cp); 
  CtoPstr(*StrHandle); 
  HUnlock ( (char **)StrHandle );
  return( *fname );
}

BOOL
GetEnvFileName(envName,defName,fileName)
short envName;
char *defName;
char **fileName;
{
  if( getenvRsrc(envName, fileName) == NULL )
    StrCopyAlloc(fileName,defName);
  return TRUE;
}

BOOL
GetEnvAlloc(envName,target)
short envName;
char **target;
{
  int found = FALSE;

  if( getenvRsrc(envName, target) != NULL ) found = TRUE;
  return found;
}

#endif

