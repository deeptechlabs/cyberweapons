/*--- Program to send a datagram.
 *
 *  Credits to Sun's Network Programming Guide.
 *
 *  Mark Riordan   30 May 1992
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FALSE 0
#define TRUE  1
#define MYPORT 2222

void SockNameToChar(struct sockaddr_in *sockname,char *ch_addr);

int Debug=1;

int
main(argc,argv)
int argc;
char *argv[];
{
#define BUFSIZE 8192
#define MAXTRY  12
	int sock;
	struct sockaddr_in sockname;
	struct sockaddr *sockptr;
	struct sockaddr_in from_sock_name;
	struct hostent *h_ent;

	struct timeval timeout;
	fd_set readfds, writefds, exceptfds;
	int sel_width = FD_SETSIZE;
	int retval;
	int trynum = 1, timeout_sec=2, max_iter=1, iter=1;

	int fromlen, flags=0, received_bytes, sending=1;
	char *buf, *reply, *cptr;
	char *message=NULL; 
	int sendsize=0, fast=FALSE;
	int ch;
	struct hostent *hp, *gethostbyname();
	char *host_name_ch = "scss3.cl.msu.edu";
	int to_port = htons(MYPORT);
	struct timeval begtime,endtime;
	struct timezone tzone;
	double elapsed;
	extern char *optarg;

	while(-1 != (ch = getopt(argc,argv,"h:p:l:m:t:fn:D:"))) {
		switch(ch) {
			case 'h':
				host_name_ch = optarg;
				break;
			case 'p':
				to_port = atoi(optarg);
				break;
			case 'l':
				sendsize = atoi(optarg);
				break;
			case 'm':
				message = optarg;
				break;
			case 't':
				timeout_sec = atoi(optarg);
				break;
			case 'f':
				fast = TRUE;
				break;
			case 'n':
				max_iter = atoi(optarg);
				break;
			case 'D':
				Debug = atoi(optarg);
				break;
			case '?':
				fputs("sendsock: Sends a message to a UDP port.\n",stderr);
				fputs("Usage: sendsock [-h hostname] [-p port#] [-l msglen] [-m msgtxt]\n",stderr);
				fputs("      [-t timeout_secs] [-n num_iter]\n",stderr);
				return 1;
		}
	}

	buf = malloc(BUFSIZE);
	reply = malloc(BUFSIZE);
	sock = socket(AF_INET,SOCK_DGRAM,0);
	if(sock < 0) {
		perror("opening datagram socket");
		exit(1);
	}

	hp = gethostbyname(host_name_ch);
	if(hp == 0) {
		fprintf(stderr,"%s: unknown host.\n",host_name_ch);
		exit(1);
	}

	if(Debug) {
		cptr = inet_ntoa(*((struct in_addr *)(hp->h_addr)));
		if(!cptr) cptr = "(none)";
		fprintf(stderr,"dest host=%s (%s)\n",host_name_ch,cptr);
	}

	bcopy((char *)hp->h_addr, (char *) &sockname.sin_addr, hp->h_length);
	sockname.sin_family = AF_INET;
	sockname.sin_port = to_port;

#if defined(MSDOS) || defined(_MSDOS)
	retval = bind(sock, (struct sockaddr *)&sockname, sizeof(sockname));
	if(retval) {
		perror("Error binding socket");
	}
#endif

	while(sending) {
		gettimeofday(&begtime,&tzone);
		if(message) {
			strcpy(buf,message);
		} else {	
			sprintf(buf,"This is message #%d, try #%d.",iter,trynum);
		}
		if(!sendsize) sendsize = strlen(buf)+4;
		sockptr = (struct sockaddr *) &sockname;
		if(Debug) {
			fprintf(stderr,"sock=%d, sendsize=%d\n",sock,sendsize);
			fprintf(stderr,"sockname.sin_family=%d, .sin_port=%u\n",
			 sockname.sin_family, ntohs(sockname.sin_port));
			fprintf(stderr,"sockname.sin_addr = %s\n",
			 inet_ntoa(sockname.sin_addr));
		}
		if(sendto(sock, buf, sendsize, 0, (struct sockaddr *)&sockname,
		 sizeof(sockname)) < 0) {
			perror("sending datagram");
			exit(1);
		}
		printf("Sent message of %d bytes to %s at port %d.\n",
		 sendsize,host_name_ch,ntohs(to_port));

		/* Wait for reply. */

		FD_ZERO(&readfds);
		FD_SET(sock,&readfds);
		timeout.tv_sec = timeout_sec;
		timeout.tv_usec = 0;
		retval = select(sel_width,&readfds,NULL,NULL,&timeout);
			
		if(retval > 0) {
			fromlen = sizeof(from_sock_name);	
			received_bytes = recvfrom(sock, reply, BUFSIZE, flags, 
			  (struct sockaddr *)&from_sock_name, &fromlen);
			if(received_bytes < 0) {
				perror("reading reply datagram socket");
				sending = FALSE;
			} else {
				gettimeofday(&endtime,&tzone);
				if(!fast) {
					h_ent = gethostbyaddr((char *)&(from_sock_name.sin_addr),
					 sizeof(from_sock_name.sin_addr),AF_INET);
					if(h_ent) {
						printf(" Reply received from %s:\n",h_ent->h_name);
					} else {
						printf("Cannot find sender's host name.\n");
					}
				}
				printf(" %d bytes; Message is: %s\n",received_bytes,reply);
				if(begtime.tv_usec > endtime.tv_usec) {
					endtime.tv_usec += 1000000L;
					endtime.tv_sec--;
				}
				elapsed = endtime.tv_sec - begtime.tv_sec + 
				 ((double)(endtime.tv_usec - begtime.tv_usec))*1.0e-6;
				printf(" Elapsed time: %f secs\n",elapsed);
			}
			if(++iter > max_iter) sending = FALSE;
			trynum = 1;
		} else if(retval == 0) {
			printf(" Timed out waiting for reply.\n");
			if(++trynum > MAXTRY) sending=FALSE;
		} else {
			perror("upon select:");
		}
	}

	close(sock);

	return 0;

}
