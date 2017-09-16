/****************************************************************************
*																			*
*					cryptlib Networking Interface Header File 				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#ifndef _NET_DEFINED

#define _NET_DEFINED

/* TCP/IP networking interface */

#ifdef NET_TCP

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "tcp4u.h"
  #include "http4u.h"
#else
  #include "misc/tcp4u.h"
  #include "misc/http4u.h"
#endif /* Compiler-specific includes */

/* Prototype for Tcp4U -> cryuptlib error mapping function */

int Tcp4MapError( int status );

#ifdef DYNAMIC_LOAD

/* Instance handle for dynamically-loaded library */

extern INSTANCE_HANDLE hTCP;

/* Prototypes for dynamically-loaded functions */

typedef int ( API4U *TCP4UCLEANUP )( void );
typedef LPSTR ( API4U *TCP4UERRORSTRING )( int Rc );
typedef int ( API4U *TCP4UINIT )( void );
typedef int ( API4U *TCPCLOSE )( SOCKET *pSock );
typedef int ( API4U *TCPCONNECT )( SOCKET *pS, LPCSTR szHost, 
								   LPCSTR szService, unsigned short *lpPort );
typedef int ( API4U *TCPRECV )( SOCKET s, LPSTR szBuf, unsigned uBufSize, 
								unsigned uTimeOut, HFILE hLogFile );
typedef int ( API4U *TCPSEND )( SOCKET s, LPCSTR szBuf, unsigned uBufSize, 
								BOOL bHighPriority, HFILE hLogFile );
typedef int ( API4U *HTTP4UGETFILEEX )( LPCSTR szURL, LPCSTR szProxyURl,
										LPCSTR szLocalFile, LPCSTR szHeaderFile,
										HTTP4U_CALLBACK CbkTransmit,
										long luserValue, LPSTR szResponse,
										int nResponseSize, LPSTR szHeaders,
										int nHeadersSize );
typedef int ( API4U *HTTP4USETTIMEOUT )( unsigned int uTimeout );

extern TCP4UCLEANUP pTcp4uCleanup;
extern TCP4UERRORSTRING pTcp4uErrorString;
extern TCP4UINIT pTcp4uInit;
extern TCPCLOSE pTcpClose;
extern TCPCONNECT pTcpConnect;
extern TCPRECV pTcpRecv;
extern TCPSEND pTcpSend;
extern HTTP4UGETFILEEX pHttp4uGetFileEx;
extern HTTP4USETTIMEOUT pHttp4uSetTimeout;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define Tcp4uCleanup		pTcp4uCleanup
#define Tcp4uErrorString	pTcp4uErrorString
#define Tcp4uInit			pTcp4uInit
#define TcpClose			pTcpClose
#define TcpConnect			pTcpConnect
#define TcpRecv				pTcpRecv
#define TcpSend				pTcpSend
#define Http4uGetFileEx		pHttp4uGetFileEx
#define Http4uSetTimeout	pHttp4uSetTimeout

#endif /* DYNAMIC_LOAD */

#endif /* NET_TCP */

#endif /* _NET_DEFINED */
