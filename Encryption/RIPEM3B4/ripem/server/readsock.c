/*--- Program to read from a datagram socket (UDP)
 *
 *  Credits to Sun's Network Programming Guide.
 *
 *  Mark Riordan   30 May 1992
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MYPORT 2222
#define TRUE   1
#define FALSE  0

void SockNameToChar(struct sockaddr_in *sockname,char *ch_addr);

int
main(argc,argv)
int argc;
char *argv[];
{
#define BUFSIZE 8192
	int sock;
	struct sockaddr_in sockname;
	struct sockaddr_in from_sock_name;
	struct hostent *h_ent;
	int fromlen=sizeof(from_sock_name), flags=0, received_bytes, running=1;
	int replylen;
	int myport = MYPORT, fast=FALSE, ch;
	char buf[BUFSIZE], reply[BUFSIZE];
	char peer_name_dotted[20], time_ch[32];
	time_t cur_time;
	struct tm *tm;
   extern char *optarg;

   while(-1 != (ch = getopt(argc,argv,"p:f"))) {
      switch(ch) {
         case 'f':
				fast = TRUE;
				break;
			case 'p':
				myport = atoi(optarg);
				break;
			case '?':
				fputs("readsock: Waits for UDP datagram & replies to it.\n",stderr);
				fputs("Usage:  readsock [-p port#] [-f] \n",stderr);
				fputs("   -f means fast; no unnecessary system calls.\n",stderr);
				return 1;
		}
	}

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

	while(running) {
		fromlen = sizeof(from_sock_name);
		received_bytes = recvfrom(sock, buf, BUFSIZE, flags, 
		 (struct sockaddr *)&from_sock_name, &fromlen);
		if(received_bytes < 0) {
			perror("reading datagram socket");
			exit(1);
		} else {
			if(!fast) time(&cur_time);
			tm = localtime(&cur_time);
			sprintf(time_ch,"%2.2d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
			 tm->tm_year,tm->tm_mon+1,tm->tm_mday,tm->tm_hour,
			 tm->tm_min,tm->tm_sec);
			SockNameToChar(&from_sock_name,peer_name_dotted);
			printf("Received datagram from %s port %d at %s.\n",
			 peer_name_dotted,from_sock_name.sin_port,time_ch);
			if(!fast) {
				h_ent = gethostbyaddr(&(from_sock_name.sin_addr),
  				 sizeof(from_sock_name.sin_addr),AF_INET);
			} else {
				h_ent = NULL;
			}
			if(h_ent) {
				printf(" Sender's host name is %s\n",h_ent->h_name);
			} else {
				printf(" Cannot find sender's host name.\n");
			}
			printf(" %d bytes; Message is: %s\n",received_bytes,buf);

			/* Send reply */
			sprintf(reply,"Got your message:  \"%s\".",buf);
			replylen = strlen(reply)+1;
			if(sendto(sock,reply,replylen,0,(struct sockaddr *)&from_sock_name,
			 sizeof(from_sock_name)) < 0) {
				perror("sending reply datagram");
				exit(1);
			}
		}
	}
	return 0;
}

void
SockNameToChar(sockname, ch_addr)
struct sockaddr_in *sockname;
char *ch_addr;
{
	sprintf(ch_addr,"%d.%d.%d.%d",
	 sockname->sin_addr.S_un.S_un_b.s_b1,
	 sockname->sin_addr.S_un.S_un_b.s_b2,
	 sockname->sin_addr.S_un.S_un_b.s_b3,
	 sockname->sin_addr.S_un.S_un_b.s_b4);
}
