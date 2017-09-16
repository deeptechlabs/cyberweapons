/* def.h -- definitions of type names.
   This file is in the Public Domain.
*/

// Null pointer is probably already defined.

#if !defined(NULL)
#define NULL ((void *) 0L)
#endif

// Internal calling convention.
#ifdef UNIX
#define CALLTYPE 
#define PASCAL
#else
#define CALLTYPE _fastcall
#define PASCAL _pascal
#endif

#define false (0)
#define true (1)

typedef int boolean;
typedef int BOOL;
typedef unsigned char byte;
typedef unsigned char BYTE;
typedef unsigned int uint;
typedef unsigned int UINT;
typedef unsigned long int ulong;
typedef unsigned long int DWORD;

