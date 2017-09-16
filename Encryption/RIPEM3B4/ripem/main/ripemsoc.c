/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

/*--- file ripemsoc.c -- Socket-related routines for RIPEM
 *
 *  Mark Riordan   16 June 1992
 *  This code is hereby replaced in the public domain.
 */

#ifdef SOLARIS
#define _SVID_GETTOD  /* Use the SVID version of gettimeofday */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef SVR4
#include <unistd.h>
#ifndef SOLARIS
extern int gettimeofday(struct timeval *);
extern int gethostname(const char *, int);
#endif
#endif

#ifdef USE_SOCKETS
#include <sys/types.h>
#ifdef AIX
#include <sys/socketvar.h>
#endif

#ifdef SVR4
#include <ulimit.h>
#endif

#if defined(MSDOS) || defined(_MSDOS)
#include <4bsddefs.h>
/* #include <pctcp/pctcp.h> */
#include <arpa/inet.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#if 1
#include <arpa/inet.h>
#else
extern char *inet_ntoa();
#endif
#include <netdb.h>
#include <sys/time.h>
#ifdef AIX
#include <sys/select.h>
#endif
#endif

#include "global.h"
#include "rsaref.h"
#include "ripem.h"
#include "ripemsop.h"
#include "keyfield.h"
#include "protserv.h"
#include "strutilp.h"
#include "pubinfop.h"

#include "p.h"

#ifdef USE_SOCKETS
char *SetupGoodServer
  P((TypListEntry **, struct sockaddr_in *, int *, RIPEMInfo *));
char *SetupSocket
  P((char *, int, struct sockaddr_in *, int *, RIPEMInfo *));
#endif

#ifdef SYSV
#define bcopy(a, b, c) memcpy(b, a, c)
#endif

#ifdef mips
extern int errno;
#endif

/*--- function GetUserRecordFromServer ---------------------------------
 *
 *  Retrieve a user record (which principally contains the user's
 *  public key) from a server.
 *
 *  Entry:  user    is the name of the user whose record is being retrieved.
 *      source  is a struct containing the server address.
 *      bytes   is the place to put the result.
 *      maxBytes is the size of the "bytes" buffer;
 *      ripemInfo is used for debug and debugStream.
 *
 *  Exit: bytes   has the result of the query (if any), zero-terminated.
 *      serverOK is TRUE if the server seems to be working, else
 *            FALSE if we shouldn't even bother to contact it
 *            again during the execution of this program.
 *            Useful for avoiding multiple long timeouts.
 *      Returns NULL upon success, else error message.
 */
char *
GetUserRecordFromServer(user,source,bytes,maxBytes,serverOK,found,ripemInfo)
char *user;
TypKeySource *source;
char *bytes;
int maxBytes;
BOOL *serverOK;
BOOL *found;
RIPEMInfo *ripemInfo;
{
#define BUFSIZE 8192
#define LINELEN 128
#define MAX_REDIRECT  3
#define MAX_TRY_TIMEOUT 2
  BOOL sending=TRUE;
  char *err_msg = NULL;

#ifdef USE_SOCKETS
  struct sockaddr_in from_sock_name;
  static BOOL hostent_is_orig=FALSE;
  struct timeval timeout;
  fd_set readfds;
#ifdef __MACH__
  int sel_width = getdtablesize();
#elif defined(sun)
  int sel_width = (int) ulimit(4,0L);
#else
  int sel_width = FD_SETSIZE;
#endif
  int retval;
  int trynum = 1, timeout_sec=4;
  int sendsize, fromlen, flags=0, received_bytes;
  struct timeval begtime,endtime;
#ifndef SVR4
  struct timezone tzone;
  extern char *inet_ntoa();
#endif
  long int elapsed;

  static BOOL first_call = 1;
  static int sock;
  static struct sockaddr_in sockname;
  static char *buf, *reply;
  
  static TypListEntry *entry;
  
  TypServer *server_ent;
  char *cptr;
  BOOL right_user;
  char temp_buf[LINELEN];
  
  *found = FALSE;

  /* First time through, allocate some memory from the heap
   * (this saves room on the stack for those dumb DOS machines),
   * and find out the IP address of the server, to avoid name
   * lookups for each user.
   */
  if(first_call) {
    first_call = 0;
    
    buf = malloc(BUFSIZE);
    reply = malloc(BUFSIZE);

    sock = socket(AF_INET,SOCK_DGRAM,0);
    if(sock < 0) {
      sprintf(ripemInfo->errMsgTxt,"Error %d opening socket to key server.",
              errno);
      return  ripemInfo->errMsgTxt;
    }
  }
  if(!hostent_is_orig) {
    entry = source->serverlist.firstptr;
    if(!entry) {
      *serverOK = FALSE;
      return "No key server specified.";
    }
    err_msg = SetupGoodServer(&entry,&sockname,&sock,ripemInfo);
    if(err_msg) {
      *serverOK = FALSE;
      return err_msg;
    }
    hostent_is_orig = TRUE; 
  }
  
  sprintf(buf,"%s\n%s %s\n",CMD_LOOKUSER_TXT,USER_FIELD,user);
  sendsize = strlen(buf)+1;

  while(sending) {
    trynum++;
    if(ripemInfo->debug > 1) {
      fprintf(ripemInfo->debugStream,"Sending request: %s",buf);
    }
#ifdef SVR4
    if(ripemInfo->debug>1) gettimeofday(&begtime);
#else
    if(ripemInfo->debug>1) gettimeofday(&begtime,&tzone);
#endif
    
    /* Send the key request packet to the key server. */
    if(sendto(sock, buf, sendsize, 0, (struct sockaddr *)&sockname,
              sizeof(sockname)) < 0) {
      sprintf(ripemInfo->errMsgTxt,"Error %d sending datagram.",errno);
      return ripemInfo->errMsgTxt;
    }
    
    /* Wait for reply. */
    
    FD_ZERO(&readfds);
    FD_SET(sock,&readfds);
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    retval = select(sel_width,&readfds,NULL,NULL,&timeout);

    if(retval > 0) {
      /* This must be the reply we're waiting for.  Read it. */
      fromlen = sizeof(from_sock_name);
      received_bytes = recvfrom(sock, reply, BUFSIZE, flags,
                                (struct sockaddr *)&from_sock_name, &fromlen);
      if(received_bytes < 0) {
        perror("reading reply datagram socket");
        sending = FALSE;
      } else {
        /* Received a packet */
        if(strncmp(reply,RESP_USERINFO_TXT,strlen(RESP_USERINFO_TXT))==0) {
          /* Server says user info found. */
          /* Check to make sure it's for the right user */
          if ((err_msg = FindUserInRecord
               (&right_user, user, reply)) != (char *)NULL)
            return (err_msg);
          if(right_user) {
            int bytes_to_copy = received_bytes>maxBytes-1 ? 
              maxBytes-1 : received_bytes;
            /* Copy the result into the caller's buffer */
            R_memcpy((unsigned char *)bytes,(unsigned char *)reply, 
                     bytes_to_copy);
            bytes[bytes_to_copy] = '\0';  /* zero terminate buffer */
            sending = FALSE;
            *serverOK = TRUE;
            *found = TRUE;
          } else {
            /* Got reply, but it didn't have the user's key */
            goto check_trynum;
          }
        } else if(strncmp(reply, RESP_REDIRECT_TXT, 
                          strlen(RESP_REDIRECT_TXT))==0) {
          /* Server has asked that we redirect this request to
           * another server.
           */
          if(trynum > MAX_REDIRECT) {
            return "Too many key server redirects";
          }
          if(!CrackKeyField(reply,SERVER_FIELD,temp_buf,LINELEN)) {
            /* Reply from server is in bad format. */
            return "Bad REDIRECT from server.";
          } else {
            err_msg = SetupSocket(temp_buf,0, &sockname,&sock,ripemInfo);
            hostent_is_orig = FALSE;
            if(err_msg) {
              *serverOK = FALSE;
              return err_msg;
            }
          }
          if(ripemInfo->debug>1) {
            fprintf(ripemInfo->debugStream,"Redirected to server %s\n",
                    temp_buf);
          }
        } else {
          /* Server says something else, indicating error. */
          /* If the problem is simply that the server does not
           * have this key on file, try the next server in the list.
           */

          if(strncmp(reply,RESP_NOTFOUND_TXT,
                     strlen(RESP_NOTFOUND_TXT)) == 0) goto try_next_server;
          
          sending = FALSE;
          *found = FALSE;
          
          /* Construct error return. */
          for(cptr=reply; *cptr!='\n'; cptr++);
          *cptr = '\0';
          sprintf(ripemInfo->errMsgTxt,"Server could not find key: %s",reply);
          err_msg = ripemInfo->errMsgTxt;
        }

        if(ripemInfo->debug>1) {
          /* Do some instrumentation to see how long it took. */
#ifdef SVR4
          gettimeofday(&endtime);
#else
          gettimeofday(&endtime,&tzone);
#endif
          if(begtime.tv_usec > endtime.tv_usec) {
            endtime.tv_usec += 1000000L;
            endtime.tv_sec--;
          }
          elapsed = 1000*(endtime.tv_sec - begtime.tv_sec) +
            (endtime.tv_usec - begtime.tv_usec)/1000;
          fprintf(ripemInfo->debugStream,
                  " Key server responded in %ld milliseconds.\n",elapsed);
        }

      }
    } else if(retval == 0) {
      /* We have timed out waiting for a reply to this datagram.
       * Datagrams do get lost on the Internet, even on good quality
       * connections (from my benchmarks), so give it a few tries
       * before giving up.
       */
      if (ripemInfo->debug > 0)
        fprintf (ripemInfo->debugStream," %s\n",
                 "Timed out waiting for reply from key server.");
    check_trynum:
      if(trynum > MAX_TRY_TIMEOUT) {
        /* OK, we have sent several datagrams to this server with
         * no response.  So, move to the next server in the list,
         * if any.  
         */
      try_next_server:
        entry = entry->nextptr;
        if(entry) {
          server_ent = (TypServer *)entry->dataptr;
          err_msg = SetupGoodServer(&entry,&sockname,&sock,ripemInfo);
          if(err_msg) {
            *serverOK = FALSE;
            return err_msg;
          }
          trynum = 0;
        } else {
          /* No more servers in the list and all previous servers
           * have timed out with no response.
           */
          if(trynum > MAX_TRY_TIMEOUT) {
            err_msg = "Timed out waiting for reply from key server.";
          } else {
            err_msg = "Requested key not on server.";
          }
          sending=FALSE;
          *serverOK = FALSE;
        }
      }

    } else {
      /* We shouldn't ever get here... */
      perror("upon select:");
    }
  }
  
#else
  *serverOK = FALSE;
  err_msg = "Sockets not implemented in this build of RIPEM.";
#endif
  
  return err_msg;
}

#ifdef USE_SOCKETS

/*--- function SetupGoodServer -----------------------------------------
 *
 *  Set up a socket for the next available server in the list
 *  of servers.  Skip servers which cannot be looked up via
 *  name service, etc.
 *
 *  Entry:  entry   points to a pointer to a list entry for the
 *              next server.
 *      ripemInfo is used for debug and debugStream.
 *
 *  Exit: entry   points to this server; it may be different than
 *              upon entry if we had to skip some servers.
 *        sockName  describes the server/port with which we will
 *              be communicating.
 *        sock    is a socket bound to the desired address.
 *        Returns NULL if success, else a pointer to error message.
 */
char *
SetupGoodServer(entry,sockName,sock,ripemInfo)
TypListEntry **entry;
struct sockaddr_in *sockName;
int *sock;
RIPEMInfo *ripemInfo;
{
  TypServer *server_ent;
  BOOL need_server = TRUE;
  char *err_msg=NULL;

  while(need_server && *entry) {
    server_ent = (TypServer *)(*entry)->dataptr;
    err_msg = SetupSocket(server_ent->servername,server_ent->serverport,
                          sockName,sock,ripemInfo);
    if(err_msg) {
      if(ripemInfo->debug > 1) {
        fprintf(ripemInfo->debugStream,"%s\n",err_msg);
      }
      *entry = (*entry)->nextptr;
    } else {
      need_server = FALSE;
    }
  }
  if(!*entry) {
    err_msg = "No more key servers in list; giving up on key servers.";
  }
  return err_msg;
}

/*--- function SetupSocket ---------------------------------------------
 *
 *  Set up a socket.  
 *
 *  Entry:  serverName  is the name of a server to which the socket
 *                will be bound.
 *        port      is the port number on that server.
 *      ripemInfo is used for debug and debugStream.
 *
 *   Exit:  sockName    is a structure describing the server/port
 *                with which we will be communicating.
 *        sock      is a socket bound to the desired address.
 *        Returns NULL if all OK, else pointer to error message.
 */
char *
SetupSocket(serverName,port,sockName,sock,ripemInfo)
char *serverName;
int port;
struct sockaddr_in *sockName;
int *sock;
RIPEMInfo *ripemInfo;
{
  struct hostent *server_ent;
  int to_port = htons(SERVER_PORT);
  char *cptr;
#if defined(MSDOS) || defined(_MSDOS)
  int retval;
#endif
  
  if(serverName) {
    server_ent = gethostbyname(serverName);
  } else {
    return "No public key server was specified.";
  }
  if(server_ent == 0) {
    sprintf(ripemInfo->errMsgTxt,"Server host unknown: %s.",serverName);
    return  ripemInfo->errMsgTxt;
  }

  bcopy((char *)server_ent->h_addr, (char *) &sockName->sin_addr, 
        server_ent->h_length);
  sockName->sin_family = AF_INET;
  if(port) to_port = htons(port);
  sockName->sin_port = to_port;
  if(ripemInfo->debug > 2) {
    cptr = inet_ntoa(sockName->sin_addr);
    fprintf(ripemInfo->debugStream,"Key server %s's IP addr=%s port=%d\n",
            serverName,cptr,to_port);
  }
#if defined(MSDOS) || defined(_MSDOS)
  retval = bind(*sock, (struct sockaddr *)sockName, sizeof(*sockName));
  if(retval) {
    return "Error binding socket.";
  }
#endif
  return NULL;
}
#endif

/*--- function GetUserRecordFromFinger ---------------------------------
 *
 *  Retrieve a user record (which principally contains the user's
 *  public key) by accessing the "finger" server on the user's machine.
 *
 *  Entry:  user    is the name of the user whose record is being retrieved.
 *      bytes   is the place to put the result.
 *      maxBytes is the size of the "bytes" buffer;
 *      ripemInfo is used for debug and debugStream.
 *
 *  Exit: bytes   has the result of the query (if any).
 *        found    indicates whether something that looks like a
 *                public key has been obtained.
 *      Returns NULL upon success, else error message.
 */
char *
GetUserRecordFromFinger(user,bytes,maxBytes,found,ripemInfo)
char *user;
char *bytes;
int maxBytes;
int *found;
RIPEMInfo *ripemInfo;
{
  BOOL sending=TRUE;
  char *err_msg = NULL;
  char *reply = NULL;

#ifdef USE_SOCKETS
#define FINGER_PORT 79
  char username[LINELEN],hostname[LINELEN];
  struct hostent *server_ent;
  struct timeval timeout;
  fd_set readfds, writefds;
#ifdef __MACH__
  int sel_width = getdtablesize();
#elif defined(sun)
  int sel_width = (int) ulimit(4,0L);
#else
  int sel_width = FD_SETSIZE;
#endif
  int retval;
  int  timeout_sec=12;
  int to_port = htons(FINGER_PORT);
  int received_bytes;
  int bytes_so_far=0, bytes_free;
  struct timeval begtime,endtime;
#ifndef SVR4
  struct timezone tzone;
#endif
  long int elapsed;
  BOOL sent_request=FALSE;
  
  int sock = -1;
  struct sockaddr_in sockname;
  char *cptr;

  *found = FALSE;
  
  /* Allocate some memory from the heap for the reply
   * and find out the IP address of the server.
   */

  reply = malloc(BUFSIZE);
  if(!reply) return "Can't allocate memory";
  bytes_free = BUFSIZE;

  cptr = BreakUpEmailAddr(user,username,LINELEN-2,hostname,LINELEN);
  if(cptr) {
#ifdef UNIX
    strncpy(username,user,LINELEN-2);
    gethostname(hostname,LINELEN);
#else
    err_msg = cptr;
    goto endit;
#endif
  } 
  server_ent = gethostbyname(hostname);
  if(server_ent == 0) {
    sprintf(ripemInfo->errMsgTxt,"Server host unknown: %s.",hostname);
    err_msg = ripemInfo->errMsgTxt;
    goto endit;
  }

  bcopy((char *)server_ent->h_addr, (char *) &sockname.sin_addr, 
        server_ent->h_length);
  sockname.sin_family = AF_INET;
  sockname.sin_port = to_port;
  if(ripemInfo->debug > 2) {
    cptr = inet_ntoa(sockname.sin_addr);
    fprintf(ripemInfo->debugStream,
            "User's Finger server's IP address is %s  port %d\n",cptr,to_port);
  }

  sock = socket(AF_INET,SOCK_STREAM,0);
  if(sock < 0) {
    sprintf(ripemInfo->errMsgTxt,"Error %d opening socket to key server.",
            errno);
    err_msg = ripemInfo->errMsgTxt;
    goto endit;
  }

#if defined(MSDOS) || defined(_MSDOS)
  retval = bind(sock, (struct sockaddr *)&sockname, sizeof(sockname));
  if(retval) {
    err_msg = "Error binding socket.";
    goto endit;
  }
#endif

  if(ripemInfo->debug > 1) {
    fprintf(ripemInfo->debugStream,"Sending finger request to  %s\n",hostname);
  }
#ifdef SVR4
  if(ripemInfo->debug>1) gettimeofday(&begtime);
#else
  if(ripemInfo->debug>1) gettimeofday(&begtime,&tzone);
#endif
    
  /* Connect to the user's host. */
  if(connect(sock, (struct sockaddr *)&sockname, sizeof(sockname)) < 0) {
    sprintf(ripemInfo->errMsgTxt,"Error %d connecting to finger.",errno);
    err_msg = ripemInfo->errMsgTxt;
    goto endit;
  }
    
  while(sending) {
    /* Wait for reply. */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    if(sent_request) {
      FD_SET(sock,&readfds);
    } else {
      FD_SET(sock,&writefds);
    }
    
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    retval = select(sel_width,&readfds,&writefds,NULL,&timeout);
    if(ripemInfo->debug>3) {
      fprintf(ripemInfo->debugStream,
              "Accessing finger server; select returned %d\n",
              retval);
    }

    if(retval > 0) {
      if(sent_request) {
        /* This must be the reply we're waiting for.  Read it. */
        received_bytes = read(sock,reply+bytes_so_far,bytes_free);
        if(received_bytes < 0) {
          perror("reading reply from finger");
          sending = FALSE;
          err_msg = "Could not connect to finger";
        } else if(received_bytes == 0) {
          close(sock);
          sending = FALSE;
        } else {
          /* Received a response */
          bytes_free -= received_bytes;
          bytes_so_far += received_bytes;
        }
      } else {
        char buf[2*LINELEN+2];
        
        sprintf(buf, "/W %s\r\n", username);
        
        if(ripemInfo->debug > 1) {
          fprintf(ripemInfo->debugStream,"Sending request: %s",buf);
        }
        /* We just got connected to the finger server; send our request. */
        write(sock,buf,strlen(buf));
        sent_request = TRUE;
      }
        
    } else if(retval == 0) {
      err_msg = "Timed out waiting for reply from finger request.";
      if (ripemInfo->debug > 0)
        fprintf(ripemInfo->debugStream," %s\n",err_msg);
      sending = FALSE;
    } else {
      /* We shouldn't ever get here... */
      perror("Error reaching finger; select");
      sending = FALSE;
    }
  }
  
  reply[bytes_so_far] = '\0';
  
  if(ripemInfo->debug>1) {
    /* Do some instrumentation to see how long it took. */
#ifdef SVR4
    gettimeofday(&endtime);
#else
    gettimeofday(&endtime,&tzone);
#endif
    if(begtime.tv_usec > endtime.tv_usec) {
      endtime.tv_usec += 1000000L;
      endtime.tv_sec--;
    }
    elapsed = 1000*(endtime.tv_sec - begtime.tv_sec) +
      (endtime.tv_usec - begtime.tv_usec)/1000;
    fprintf(ripemInfo->debugStream,
            " Finger server responded in %ld milliseconds.\n",elapsed);
  }
  if(ripemInfo->debug>2) {
    fprintf(ripemInfo->debugStream,"Response from finger: \n%s\n",reply);
  }
  /* Check to see whether we got the response
   * to our query was positive.
   */
  
  /* Copy the result into the caller's buffer */
  *found = ExtractPublicKeyLines(reply,bytes,maxBytes);
#else
  err_msg = "Sockets not implemented in this build of RIPEM.";
#endif
  
endit:
  if(reply) free(reply);
#ifdef USE_SOCKETS
  close(sock);  /* May not be valid socket, but no harm done. */
#endif
  return err_msg;
}
