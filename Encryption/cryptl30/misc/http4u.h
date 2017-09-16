/*
 * Tcp4u v3.30      creation date: 29/05/1997 modif: 16/10/1997
 *
 *===========================================================================
 *
 * Project: Tcp4u,      Library for tcp protocol
 * File:    http4u.h
 * Purpose: Header for the Library Http4u (direct http protocol)
 *
 *===========================================================================
 *
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

#ifndef HTTP4UX_API

#ifdef __cplusplus  
extern "C" {            /* Assume C declarations for C++ */   
#endif  /* __cplusplus */


typedef BOOL (CALLBACK far *HTTP4U_CALLBACK)(
#ifdef NEED_PROTO
 long , long , long , LPCSTR, unsigned int 
#endif
);

/**************************
 * definition error code
 **************************/

enum HTTP4_RETURN_CODE {
  HTTP4U_BAD_URL         =-100, /*  */
  HTTP4U_TCP_FAILED      ,     /*  */
  HTTP4U_HOST_UNKNOWN    ,     /*  */
  HTTP4U_TCP_CONNECT     ,     /*  */
  HTTP4U_FILE_ERROR      ,     /*  */
  HTTP4U_INSMEMORY       ,     /*  */
  HTTP4U_BAD_PARAM       ,     /*  */
  HTTP4U_OVERFLOW        ,     /*  */
  HTTP4U_CANCELLED       ,     /*  */
  HTTP4U_NO_CONTENT      ,     /*  */
  HTTP4U_MOVED           ,     /*  */      
  HTTP4U_BAD_REQUEST     ,     /*  */
  HTTP4U_FORBIDDEN       ,     /*  */
  HTTP4U_NOT_FOUND       ,     /*  */
  HTTP4U_PROTOCOL_ERROR  ,     /*  */
  HTTP4U_UNDEFINED       ,     /*  */
  HTTP4U_TIMEOUT         ,     /*  */
  HTTP4U_SUCCESS         =1    /*  */
};

/**************************
 * Http4u default value
 **************************/

#ifndef KBYTES
#define KBYTES  1024
#endif
#define DFLT_TIMEOUT       60
#define DFLT_BUFFERSIZE    (4 * KBYTES)

/*=====================================================================
 *=====================================================================
 *                        FUNCTION PROTOTYPES
 *=====================================================================
 *===================================================================*/


BOOL API4U HttpIsValidURL (LPCSTR szURL, unsigned short far *lpPort, 
                           LPSTR  szService, int  uServiceSize,
                           LPSTR  szHost,    int  uHostSize,
                           LPSTR  szFile,    int  uFileSize );

/*######################################################################
 *## PURPOSE: Return body associate with the URL's parameter
 *####################################################################*/
int API4U HttpGetFile (LPCSTR szURL,           /* destination URL             */
                       LPCSTR szProxyURl,      /* proxy to be used (URL form) */
                       LPCSTR szLocalFile      /* user filename for save      */
               );

/*######################################################################
 *## PURPOSE:  Return headers and body of a http request
 *####################################################################*/
int API4U HttpGetFileEx (LPCSTR  szURL,           /* destination URL                 */
                         LPCSTR  szProxyURl,      /* proxy to be used (URL form)     */
                         LPCSTR  szLocalFile,     /* user filename for body save     */
                         LPCSTR  szHeaderFile,    /* user filename for headers save  */
                         HTTP4U_CALLBACK CbkTransmit, /* user callback function      */
                         long            luserValue,  /* user value                  */
                         LPSTR   szResponse,      /* user buffer for headers storage */
                         int     nResponseSize,   /* user buffer size                */
                         LPSTR   szHeaders,       /* user buffer for headers storage */
                         int     nHeadersSize     /* user buffer size                */
                 );
/*
long lBytesTransferred,
                  long  lTotalBytes,
                  long  lUserValue,
                  LPCSTR sBufRead,
                  unsigned int nb_bytes
*/
/*######################################################################
 *## PURPOSE:  Sets user preference of the buffer size
 *####################################################################*/
void  API4U Http4uSetBufferSize( unsigned int uBufferSize /* buffer size in bytes */
                         );

/*######################################################################
 *## PURPOSE: Sets user preference of the timeout value
 *####################################################################*/
void  API4U Http4uSetTimeout( unsigned int uTimeout /* timeout value in sec */
                      );

/*######################################################################
 *## PURPOSE: Writes a message explaining a function error
 *####################################################################*/
LPCSTR API4U Http4uErrorString( int msg_code  /* le code d'erreur de Http4U */
                        );


#ifdef __cplusplus     
}  /* End of extern "C" */   
#endif /* ifdef __cplusplus */


#define HTTP4UX_API loaded
#endif /* ifndef HTTP4UX_API */


