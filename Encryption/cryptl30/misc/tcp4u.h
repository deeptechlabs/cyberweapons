/*
 * Tcp4u v3.30      creation date: may 93 modif: 27/02/1998
 *
 *===========================================================================
 *
 * Project: Tcp4u,      Library for tcp protocol
 * File:    tcp4u.h
 * Purpose: Common Unix-Windows Header file
 *
 *===========================================================================
 *
 * This software is Copyright (c) 1996-1998 by Philippe Jounin
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 *
 *
 *  If you make modifications to this software that you feel
 *  increases it usefulness for the rest of the community, please
 *  email the changes, enhancements, bug fixes as well as any and
 *  all ideas to me. This software is going to be maintained and
 *  enhanced as deemed necessary by the community.
 *
 *
 *             Philippe Jounin (ph.jounin@computer.org)
 */


#ifndef _TCP4UX_H_
#define _TCP4UX_H_

#ifndef TCP4UX_API

#ifdef __cplusplus  
extern "C" {            /* Assume C declarations for C++ */   
#endif  /* __cplusplus */   


/* ------------------ */
/* types declarations */
/* ------------------ */

/* ******************************************** */
/* Summary:                                     */
/*             BOOLEAN   -> int                 */
/*             DWORD     -> 4-bytes struct      */
/*             DWORD_PTR -> char[4]             */
/*             HFILE     -> int                 */
/*             LPCSTR    -> const char *        */
/*             LPSTR     -> char *              */
/*             SOCKET    -> unsigned int        */
/*             UINT      -> unsigned int        */
/* ******************************************** */



/* ------------------------------------------------------------- */
#if (!defined _WINDOWS_  &&  !defined WINVER  &&  !defined WIN32  &&  !defined _WINDOWS)

#ifndef INADDRSZ
#  define INADDRSZ 4
#endif
struct S_Tcp4uxDword { unsigned char a [INADDRSZ]; } ;

typedef struct S_Tcp4uxDword  DWORD;
typedef unsigned char DWORD_PTR [INADDRSZ]; /* a pointer on a 4 bytes integer */

#ifndef TYPE_HFILE_DEF
  typedef int HFILE;            /* file identifier   */
# define TYPE_HFILE_DEF
#endif /* def type HFILE */

#ifndef TYPE_SOCKET_DEF
  typedef   unsigned int SOCKET;
# define TYPE_SOCKET_DEF
#endif /* def type SOCKET */

#ifndef TYPE_BOOL_DEF
   typedef   int BOOL;
#  define TYPE_BOOL_DEF
#endif /* def type BOOL */

#ifndef TYPE_LPSTR_DEF
   typedef   char * LPSTR;
#  define TYPE_LPSTR_DEF
#endif /* def type LPSTR */

#ifndef TYPE_UINT_DEF
#  ifndef UINT
      typedef   unsigned int UINT;
#  endif  /* UINT */
#  define TYPE_UINT_DEF
#endif /* def type UINT */


#ifndef TYPE_LPCSTR_DEF
   typedef   const char * LPCSTR;
#  define TYPE_LPCSTR_DEF
#endif /* def type LPCSTR */

#ifndef  INVALID_SOCKET 
#  define INVALID_SOCKET    ((SOCKET) -1)
#endif /* INVALID_SOCKET */

#ifndef  SOCKET_ERROR
#  define  SOCKET_ERROR  -1
#endif /* SOCKET_ERROR */

#ifndef HFILE_ERROR
# define HFILE_ERROR  -1
#endif /* HFILE_ERROR */

#define API4U
#define CALLBACK
#define far

#else /* _WINDOWS_ defined */
#  include <winsock.h>
#  ifndef API4U
#    define API4U PASCAL FAR 
#  endif
#  if (defined WIN32  || defined _WIN32)
#    define far
#  endif
#endif /* _WINDOWS_ not defined */
/* ------------------------------------------------------------- */



/* ------------------------------- */
/* Return codes of TCP4W functions */
/* ------------------------------- */

#define  TCP4U_SUCCESS           1  /* >=1 function OK            */
#define  TCP4U_ERROR            -1  /* error                      */
#define  TCP4U_TIMEOUT          -2  /* timeout has occured        */
#define  TCP4U_BUFFERFREED      -3  /* the buffer has been freed  */
#define  TCP4U_HOSTUNKNOWN      -4  /* connect to unknown host    */
#define  TCP4U_NOMORESOCKET     -5  /* all socket has been used   */
#define  TCP4U_NOMORERESOURCE   -5  /* or no more free resource   */
#define  TCP4U_CONNECTFAILED    -6  /* connect function has failed*/
#define  TCP4U_UNMATCHEDLENGTH  -7  /* TcpPPRecv : Error in length*/
#define  TCP4U_BINDERROR        -8  /* bind failed (Task already started?) */
#define  TCP4U_OVERFLOW         -9  /* Overflow during TcpPPRecv  */
#define  TCP4U_EMPTYBUFFER     -10  /* TcpPPRecv receives 0 byte  */
#define  TCP4U_CANCELLED       -11  /* Call cancelled by signal   */
#define  TCP4U_INSMEMORY       -12  /* Not enough memory          */
#define  TCP4U_BADPORT         -13  /* Bad port number or alias   */
#define  TCP4U_SOCKETCLOSED      0  /* Host has closed connection */
#define  TCP4U_FILE_ERROR      -14  /* A file operation has failed*/


/* ------------------------------ */
/* Return codes of TN4W functions */
/* ------------------------------ */
#define  TN_SUCCESS        TCP4U_SUCCESS
#define  TN_ERROR          TCP4U_ERROR         
#define  TN_TIMEOUT        TCP4U_TIMEOUT       
#define  TN_BUFFERFREED    TCP4U_BUFFERFREED   
#define  TN_SOCKETCLOSED   TCP4U_SOCKETCLOSED
#define  TN_CANCELLED      TCP4U_CANCELLED
#define  TN_OVERFLOW       2
#define  TN_UNEXPECTED     -999 /* internal only */



/* ------------------------------- */
/* Different modes for TcpRecv     */
/* ------------------------------- */
#define TCP4U_WAITFOREVER    0
#define TCP4U_DONTWAIT      ((unsigned) -1)


/* ------------------------------ */
/* Log levels                     */
/* ------------------------------ */
#define   LOG4U_CALL    0x0001    /* log each tcp socket function    */
#define   LOG4U_DBCALL  0x0002    /* log db socket function          */
#define   LOG4U_INTERN  0x0008    /* log each app level call         */

#define   LOG4U_PROC    0x0010    /* log each Tcp4u/Tn4u APIs called */
#define   LOG4U_HIPROC  0x0020    /* log each app level call         */
#define   LOG4U_EXIT    0x0040    /* log each Tcp4u/Tn4u APIs called */
#define   LOG4U_HIEXIT  0x0080    /* log each app level call         */

#define   LOG4U_DUMP    0x4000    /* dump frames                     */
#define   LOG4U_ERROR   0x8000    /* log errors                      */
#define   LOG4U_ALL     0xFFFF    /* get all logs                    */


/* ------------------------------------------------- */
/* Registration functions                            */   
/* ------------------------------------------------- */
int   API4U Tcp4uInit (void);
int   API4U Tcp4uCleanup (void);
int   API4U Tcp4uVer (LPSTR szInfo, UINT uBufSize);
LPSTR API4U Tcp4uErrorString (int Rc);
void  API4U Tcp4uEnableLog (unsigned uMask);
void  API4U Tcp4uDump (LPCSTR cp, int nLen, LPCSTR szPrefix);


/* ------------------------------------------------- */
/* TCP functions                                     */   
/* ------------------------------------------------- */
int API4U TcpAbort (void);
int API4U TcpAccept (SOCKET *pCSock, SOCKET ListenSock, UINT nTO);
int API4U TcpConnect (SOCKET *pS, LPCSTR szServer, LPCSTR szService,
                      unsigned short *lpPort);
int API4U TcpClose (SOCKET *pS);
int API4U TcpFlush (SOCKET s);
int API4U TcpGetListenSocket (SOCKET *pS, LPCSTR szService,
                          unsigned short *lpPort, int nPendingConnection);
int API4U TcpRecv (SOCKET s, LPSTR szBuf, unsigned uBufSize, unsigned uTimeOut, HFILE hf);
int API4U TcpSend (SOCKET s, LPCSTR szBuf, unsigned uBufSize, BOOL bHighPriority, HFILE hf);

int API4U TcpGetLocalID (LPSTR szStrName, int uNameSize, DWORD *lpAddress);
int API4U TcpGetRemoteID (SOCKET s, LPSTR szStrName, int uNameSize, DWORD *lpAddress);
BOOL API4U TcpIsDataAvail (SOCKET s);
BOOL API4U TcpIsOOBDataAvail (SOCKET s);

/* PP protocole (2 first bytes contain length of data) */
int API4U TcpPPRecv (SOCKET s, LPSTR szBuf, unsigned uBufSize, unsigned uTimeOut, 
                     BOOL bExact, HFILE hLogFile);
int API4U TcpPPSend (SOCKET s, LPCSTR szBuf, unsigned uBufSize, HFILE hLogFile);

/* Recv Until family */
int API4U TcpRecvUntilStr (SOCKET s, LPSTR szBuf,unsigned *lpBufSize,
                          LPSTR szStop, unsigned uStopSize, BOOL bCaseSensitive,
                          unsigned uTimeOut, HFILE hLogFile);

typedef BOOL (CALLBACK far *TRANSFER_CBK) (
#ifdef NEED_PROTO
    long, long, long, LPSTR
#endif
);
int API4U TcpRecvUntilClosedEx (SOCKET       *pCSock,     LPCSTR szLocalFile, 
                                TRANSFER_CBK  CbkTransmit,
                                unsigned      uTimeout,   unsigned int  uBufSize, 
                                long          lUserValue, long          lTotalBytes);

   
/* ------------------------------------------------- */
/* Telnet functions                                  */   
/* ------------------------------------------------- */
int API4U TnReadMultiLine (SOCKET s, LPSTR szBuf, UINT BufSize, UINT uTimeOut, HFILE hf);
int API4U TnReadLine (SOCKET s, LPSTR szBuf, UINT BufSize, UINT uTimeOut, HFILE hf);
int API4U TnSendMultiLine (SOCKET s, LPCSTR szString, BOOL bEnd, HFILE hf);
int API4U TnSend (SOCKET s, LPCSTR szString, BOOL bHighPriority, HFILE hf);
int API4U TnGetAnswerCode(SOCKET s,LPSTR szInBuf,UINT uBufSize,UINT uTimeOut, HFILE hf);

/* ------------------------------------------------- */
/* Telnet_based protocol functions                   */   
/* ------------------------------------------------- */
struct S_TnProto 
{
   LPSTR  szString;
   int    iCode;
};

typedef int (CALLBACK far *TNPROTOEXCHG_CBK) (
#ifdef NEED_PROTO
    SOCKET, LPSTR, UINT, UINT, HFILE
#endif
);

int API4U TnProtoExchange (SOCKET s, 
                     LPCSTR szCommande,
                     LPSTR  szResponse, 
                      UINT uBufSize, 
                     TNPROTOEXCHG_CBK TnProtoRecv,
                     struct S_TnProto far *tTranslation, 
                     int    nTabSize,
                     BOOL   bCaseCmp,
                     UINT   uTimeout,
                     HFILE  hLogFile);


/* ------------------------------------------------- */
/* Old declarations, compatibility with version 1.5  */
/* ------------------------------------------------- */

#define  IP_SUCCESS           1  /* >=1 function OK            */
#define  IP_ERROR            -1  /* error                      */
#define  IP_TIMEOUT          -2  /* timeout has occured        */
#define  IP_BUFFERFREED      -3  /* the buffer has been freed  */
#define  IP_HOSTUNKNOWN      -4  /* connect to unknown host    */
#define  IP_NOMORESOCKET     -5  /* all socket has been used   */
#define  IP_NOMORERESOURCE   -5  /* or no more free resource   */
#define  IP_CONNECTFAILED    -6  /* connect function has failed*/
#define  IP_UNMATCHEDLENGTH  -7  /* TcpPPRecv : Error in length*/
#define  IP_BINDERROR        -8  /* bind failed (Task already started?) */
#define  IP_OVERFLOW         -9  /* Overflow during TcpPPRecv  */
#define  IP_EMPTYBUFFER     -10  /* TcpPPRecv receives 0 byte  */
#define  IP_CANCELLED       -11  /* Call cancelled by TcpAbort */
#define  IP_INSMEMORY       -12  /* Not enough memory          */
#define  IP_SOCKETCLOSED      0  /* Host has close connection  */


int   API4U Tcp4wInit (void);
int   API4U Tcp4wCleanup (void);
int   API4U Tcp4wVer (LPSTR szInfo, UINT uBufSize);
LPSTR API4U Tcp4wErrorString (int Rc);





#ifdef __cplusplus     
}  /* End of extern "C" */   
#endif /* ifdef __cplusplus */



#define TCPUX_API loaded
#endif /* ifndef TCP4UX_API */

#endif

