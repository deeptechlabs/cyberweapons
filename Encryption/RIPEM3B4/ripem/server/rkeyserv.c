/*--- RIPEM Key Server:
 *  Program to provide network access to a database of
 *  cryptographic public keys.
 *
 *  Credits to Sun's Network Programming Guide.
 *
 *  Mark Riordan   13 June 1992
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#ifndef __MACH__
#include <unistd.h>
#else
#include <sys/ioctl.h>
#endif
#ifdef AIX
#include <sys/socketvar.h>
#include <sys/select.h>
#endif

#define MAIN
#define TRUE   1
#define FALSE  0
#define BOOL int

#include "../main/keyfield.h"
#include "../main/strutilp.h"
#include "gdbm.h"
#include "rkeyserp.h"
#include "../main/protserv.h"
#include "srvfiles.h"
#include "opeclopr.h"

#define MYPORT 1611
#define LINESIZE 2000

static char *author =
"Written by Mark Riordan  1100 Parker  Lansing MI 48912  14 June 1992";

FILE *DStream = stderr;
int Debug = 0;
char *DBName = SERVER_KEY_DATABASE;
int DatabaseOpened = FALSE;
int PleaseClose = FALSE;
struct in_addr MyIPAddress;
GDBM_FILE dbf;
extern gdbm_error gdbm_errno;

int
main(argc,argv)
int argc;
char *argv[];
{
#define BUFSIZE 8192
	char *err_msg;
	int sock;
	struct sockaddr_in sockname;
	struct sockaddr_in from_sock_name;
	struct hostent *h_ent;
	int fromlen=sizeof(from_sock_name), flags=0, received_bytes, running=1;
	int replylen;
	int myport = MYPORT, fast=FALSE, ch, retval, selval;
   struct timeval timeout;
   fd_set readfds, writefds, exceptfds;
	char *pid_file = SERVER_PID_FILE;
	int pid_fd, pid;
	char buf[BUFSIZE], reply[BUFSIZE];
	char *sender_name_ch;
	char peer_name_dotted[20], time_ch[32];
	time_t cur_time;
	struct tm *tm;
	int timeout_sec=1, timeout_usec=0;
	float timeout_f = 3.0;
        int detach=1;
   extern char *optarg;

   while(-1 != (ch = getopt(argc,argv,"D:g:p:fP:Z:t:"))) {
      switch(ch) {
			case 'g':  /* GDBM key database */
				DBName = optarg;
				break;
         case 'f':
				fast = TRUE;
				break;
			case 'p':  /* Port # to listen on */
				myport = atoi(optarg);
				break;
                        case 'd':  /* don't detach */
                                detach = 0;
                                break;
			case 'D':  /* Debugging */
				Debug = atoi(optarg);
				break;
			case 't':
				timeout_f = atof(optarg);
				timeout_sec = timeout_f;
				timeout_usec = 1000000 * (timeout_f - (float)timeout_sec);
				break;
			case 'P':
				pid_file = optarg;
				break;
			case 'Z':
				DStream = fopen(optarg,"a");
				break;
			case '?':
				fputs("rkeyserv: Public key server for RIPEM.\n",stderr);
				fputs("Usage:  rkeyserv [-g dbname] [-p port#] [-f] [-D debug] [-t timeout]\n",stderr);
				fputs("  [-P pid_file] [-Z debug_file] [-d]\n",stderr);
                                fputs("   -d means don't detach from the controlling terminal.\n",stderr);
				fputs("   -f means fast; no unnecessary system calls.\n",stderr);
				fputs("   -t specifies the select timeout in seconds (floating point)\n",stderr);
				return 1;
		}
	}
	
   /* detach the process */
	if (detach) {
	  	if ((detach = fork()) < 0) {
                	fprintf(DStream,"fork() failed\n");
                        exit(1);
                }
		if (detach != 0) /* parent exits */
			exit(0);
#if   !defined(__MACH__)
		if (setsid() < 0)
        	fprintf(DStream,"setsid() failed\n");
#else
      setpgrp(0, getpid());
      if ((detach = open("/dev/tty", 2)) >= 0) {
          ioctl(detach, TIOCNOTTY, (char *)0);
          close(detach);
      }
#endif
	}

	/* Write our process ID to a file so others know who we are.  That
	 * way, they can signal us to close the database when they need
	 * to write to it.
	 * Lock the file before writing to it.
	 */
	 
    pid_fd = open(pid_file,O_CREAT | O_RDWR, 0644);
	if(pid_fd < 0) {
		perror("Error opening pid_file");
		return 1;
	}
#ifndef __MACH__
	/* This just doesn't work under NeXTOS 2.2.  I dunno why. */
	retval = lockf(pid_fd,F_TLOCK,0L);
	if(retval) {
		perror("Error locking pid_file");
		return 1;
	}
#endif
	pid = getpid();
	sprintf(buf,"%d\n",pid);
	write(pid_fd,buf,strlen(buf));

	/* Set up our signal handler. */
	signal(SIGUSR1,SigHandler);

   if(err_msg = OpenKeyDatabase(DBName,FALSE,&dbf)) {
		fprintf(DStream,"%s\n",err_msg);
		return 1;
	}
	DatabaseOpened = 1;


	sock = socket(AF_INET,SOCK_DGRAM,0);
	if(sock < 0) {
		perror("opening datagram socket");
		exit(1);
	}

	/* Create a number for the socket. */

	sockname.sin_family = AF_INET;
	sockname.sin_addr.s_addr = INADDR_ANY;
	sockname.sin_port = myport;

	if(bind(sock, (struct sockaddr *) &sockname, sizeof(sockname)) < 0) {
		perror("binding datagram socket");
		exit(1);
	}
	GetMyIPAddress(&MyIPAddress);
	if(Debug) {
		fprintf(DStream,"My IP address is %s\n",inet_ntoa(MyIPAddress));
	}

	while(running) {
      FD_ZERO(&readfds);
      FD_SET(sock,&readfds);
      timeout.tv_sec = timeout_sec;
      timeout.tv_usec = timeout_usec;
	selval = select(sock+1,&readfds,NULL,NULL,&timeout);

		if(selval > 0) {
			/* We received something on this socket. */
		   fromlen = sizeof(from_sock_name);
		   received_bytes = recvfrom(sock, buf, BUFSIZE, flags,
		    (struct sockaddr *)&from_sock_name, &fromlen);
		   if(received_bytes < 0) {
			   perror("reading datagram socket");
			   exit(1);
		   } else {
				/* Report on who is sending the request.  
				 * This code would be disabled, for privacy reasons,
				 * in a "production" version.
				 */
				if(Debug) {
					time(&cur_time);
					tm = localtime(&cur_time);
				   if(!fast) {
					   h_ent = gethostbyaddr((char *)&(from_sock_name.sin_addr),
					    sizeof(from_sock_name.sin_addr),AF_INET);
				   } else {
					   h_ent = NULL;
				   }
					if(h_ent) {
						sender_name_ch = h_ent->h_name;
					} else {
						sender_name_ch = inet_ntoa(from_sock_name.sin_addr);
					}
					fprintf(DStream,"On %-2.2d/%-2.2d at %-2.2d:%-2.2d:%-2.2d received request from %s\n",
					 tm->tm_mon+1,tm->tm_mday,
			 		 tm->tm_hour,tm->tm_min,tm->tm_sec,sender_name_ch);
				}
				
			   retval = ProcessRequest(sock,buf,received_bytes,&from_sock_name);
			   if(retval < 0) running = 0;
			}
		} else if(selval == 0) {
			/* We timed out on the "select" */
			if(PleaseClose) {
				CloseKeyDatabase(dbf);
  				DatabaseOpened = FALSE;
				PleaseClose = FALSE;
			}
		}
	}

	gdbm_close(dbf);

	return 0;
}

/*--- function ProcessRequest ----------------------------------------------
 */
int
ProcessRequest(sock,buf,receivedBytes,fromSockName)
int sock;
char *buf;
int receivedBytes;
struct sockaddr_in *fromSockName;
{
	int cmd, retval;
	char line[LINESIZE];
	char reply_buf[BUFSIZE];
	int reply_len;
	int found;
	int looking=TRUE;
	struct hostent *h_ent;
	datum dat,key;
	time_t cur_time;
	struct tm *tm;

	if(!DatabaseOpened) {
		OpenKeyDatabase(DBName,FALSE,&dbf);
		DatabaseOpened = 1;
	}

	buf[receivedBytes] = '\n';
	buf[receivedBytes+1] = '\0';

	if(Debug>1) {
		fprintf(DStream,"Request: %s",buf);
	}

   if(receivedBytes < 4) return 1;
	cmd = WhichCommand(buf);
	if(Debug>1) {
		fprintf(DStream,"Command was decoded as type #%d\n",cmd);
	}

	switch(cmd) {
		case CMD_LOOKUSER:
			found = GetKeyField(USER_FIELD,buf,line,LINESIZE);
			if(found) {
				do {
					LowerCaseString(line);
					key.dptr = line;
					key.dsize = strlen(line);
	         	dat = gdbm_fetch(dbf,key);
					if(dat.dptr) {
						/* If we got a "SameAs:" record, look again for the 
						 * real user. 
						 * This code is quick & dirty and I'm not proud of it.
						 * SameAs: records are now obsolete.
						 */
						found = GetKeyField("SameAs:",dat.dptr,line,LINESIZE);
						if(found) {
							key.dptr = LowerCaseString(line);
							key.dsize = strlen(line);
							dat = gdbm_fetch(dbf,key);
						}
						sprintf(reply_buf,"%s\n%s",RESP_USERINFO_TXT,
						 dat.dptr);
						free(dat.dptr);
						reply_len = strlen(reply_buf)+1;
						SendReply(sock,fromSockName,reply_buf,reply_len);
						looking = FALSE;
					} else if(EmailAddrUpALevel(line)) {
						continue;
					} else {
						sprintf(reply_buf,"%s\n%s %s",RESP_NOTFOUND_TXT,
						 USER_FIELD,line);
						SendReplyStr(sock,fromSockName,reply_buf);
						looking = FALSE;
					}
				} while(looking);
			} else {
				sprintf(reply_buf,"%s\n",RESP_BADFMT_TXT);
				SendReplyStr(sock,fromSockName,reply_buf);
			}
			break;

		case CMD_QUIT:
			if(fromSockName->sin_addr.s_addr == MyIPAddress.s_addr) {
				return -1;
			} else {
				h_ent = gethostbyaddr((char *)&(fromSockName->sin_addr),
				 sizeof(fromSockName->sin_addr),AF_INET);
				sprintf(reply_buf,"%s %s, you are not authorized.\n",
				 RESP_BADFMT_TXT,h_ent->h_name);
				SendReplyStr(sock,fromSockName,reply_buf);
			}
			break;

		case CMD_UNDEF:
		default:
			strcpy(reply_buf,"CMDUNREG\n");
			reply_len = strlen(reply_buf)+1;
			SendReply(sock,fromSockName,reply_buf,reply_len);
			break;
	}

	return 0;
}

/*--- function WhichCommand ------------------------------------------
 */
int
WhichCommand(char *cmd)
{
	int ic, looking=1;

	for(ic=0; Commands[ic].cmd_txt; ic++) {
		if(strncmp(Commands[ic].cmd_txt,cmd,Commands[ic].cmd_len)==0) {
			return Commands[ic].cmd_id;
		}
	}
	return CMD_UNDEF;
}

/*--- function GetUserPubInfo -----------------------------------------
 */
int
GetUserPubInfo(user,userInfo,maxInfoLen)
char *user;
char *userInfo;
int   maxInfoLen;
{ 

}

/*--- function GetKeyField --------------------------------------------
 */
int
GetKeyField(field,userInfo,line,maxLineLen)
char *field;
char *userInfo;
char *line;
int  maxLineLen;
{
	int fldlen = strlen(field);
   char *uptr=userInfo;
	int found=0, running=1;

	do {
		/* Check for a field name which matches. */
		if(strncmp(field,uptr,fldlen)==0) {
			/* Field name matches.  Copy the remainder of the line
  			 * in userInfo (past the field name) to "line".
			 */
			uptr += fldlen;
			while(WhiteSpace(*uptr)) uptr++;
			while(*uptr != '\n' && --maxLineLen) *(line++) = *(uptr++);
			*line = '\0';
			found = 1;
			running = 0;
		} else {
			/* Field name does not match.  Skip to the end of this
			 * line in userInfo.  If we have reached the end of
			 * userInfo, return failure.
			 */
			while(*uptr != '\n') uptr++;
			if(!*(++uptr)) {
				running = 0;
			}
		}
	} while(running);

	return found;
}

/*--- function SendReply ---------------------------------------------------
 */
int
SendReply(sock,sockName,buf,bufLen)
int sock;
struct sockaddr_in *sockName;
char *buf;
int bufLen;
{

	if(sendto(sock,buf,bufLen,0,(struct sockaddr *)sockName,
	 sizeof(*sockName)) < 0) {
		perror("sending reply datagram");
		exit(1);
	}
	if(Debug > 1) {
		fprintf(DStream,"Sent to %s: %s\n",inet_ntoa(sockName->sin_addr),buf);
	}
}

/*--- function SendReplyStr ------------------------------------------------
 */
int SendReplyStr(sock,sockName,buf)
int sock;
struct sockaddr_in *sockName;
char *buf;
{
	return SendReply(sock,sockName,buf,strlen(buf)+1);
}

/*--- function GetMyIPAddress ---------------------------------------------
 */
void
GetMyIPAddress(MyIPAddress)
struct in_addr *MyIPAddress;
{
#define MAXHOSTLEN 100
	char host[MAXHOSTLEN];
	struct hostent *h_ent;

	gethostname(host,MAXHOSTLEN);
	if(Debug > 2) {
		fprintf(DStream,"My host name is %s.\n",host);
	}
	h_ent = gethostbyname(host);
	if(h_ent) {
		memcpy(MyIPAddress,h_ent->h_addr_list[0],h_ent->h_length);
	}
}


/*--- function SigHandler -----------------------------------------
 *
 *  Handle the SIGUSR1 signal, which other processes send to us
 *  to ask that we close the database so they can update it.
 */
void
SigHandler(signo)
int signo;
{
	PleaseClose = TRUE;
	if(Debug) {
		fprintf(DStream,"Got signal to close database.\n");
	}
	fflush(DStream);
}
