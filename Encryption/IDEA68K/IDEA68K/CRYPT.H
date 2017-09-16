/******************************************************************************/
/*                                                                            */
/*               C R Y P T O G R A P H I C - A L G O R I T H M S              */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ethz.ch)                   */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Last Edition: 23 April 1992                                                */
/* System:       SUN SPARCstation, SUN cc C-Compiler, SUN-OS 4.1.1            */
/******************************************************************************/
/* Change this type definitions to the representations in your computer.      */

typedef signed long    int32;           /* signed 32-bit integer              */
typedef unsigned long  u_int32;         /* unsigned 32-bit integer            */
typedef unsigned short u_int16;         /* unsigned 16-bit integer            */
typedef unsigned char  u_int8;          /* unsigned 8-bit integer             */

/* Do not change the lines below.                                             */

#define dataSize       8 /* bytes = 64 bits */
#define dataLen        4
#define keySize      104 /* bytes = 832 bits */
#define keyLen        52
#define userKeySize   16 /* bytes = 128 bits */
#define userKeyLen     8

#define DataT(v) u_int16 v [dataLen]
#define KeyT(v) u_int16 v [keyLen]
#define UserKeyT(v) u_int16 v [userKeyLen]

void Idea( DataT(dataIn), DataT(dataOut), KeyT(key) );
void InvertIdeaKey( KeyT(key), KeyT(invKey) );
void ExpandUserKey( UserKeyT(userKey), KeyT(key) );
