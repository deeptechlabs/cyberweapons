/* des_local.h */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include <stdio.h>
#include "des.h"

#if defined(__STDC__) || defined(VMS) || defined(M_XENIX) || defined(MSDOS)
#include <string.h>
#define bcopy(b1,b2,len) memcpy(b2, b1, (size_t)(len))
#define bzero(b,len) memset(b, 0, (size_t)(len))
#define bcmp(b1,b2,len) memcmp(b1, b2, (size_t)(len))
#define index(s1,char) strchr(s1,char)
#endif

#ifdef MSDOS
#define getpid() 2
#define RAND
extern int errno;
#endif

#ifdef RAND
#define random() rand()
#define srandom(s) srand(s)
#endif

#ifndef _AIX
typedef unsigned char uchar;
typedef unsigned short ushort;
#ifndef _HPUX
typedef unsigned int uint;
typedef unsigned long ulong;
#endif
#endif

#define ITERATIONS 16
#define HALF_ITERATIONS 8

/* used in des_read and des_write */
#define MAXWRITE	(1024*16)
#define BSIZE		(MAXWRITE+4)

#define c2l(c,l)	(l =((ulong)(*((c)++)))    , \
			 l|=((ulong)(*((c)++)))<< 8, \
			 l|=((ulong)(*((c)++)))<<16, \
			 l|=((ulong)(*((c)++)))<<24)

/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 7: l2|=((ulong)(*(--(c))))<<16; \
			case 6: l2|=((ulong)(*(--(c))))<< 8; \
			case 5: l2|=((ulong)(*(--(c))));     \
			case 4: l1|=((ulong)(*(--(c))))<<24; \
			case 3: l1|=((ulong)(*(--(c))))<<16; \
			case 2: l1|=((ulong)(*(--(c))))<< 8; \
			case 1: l1|=((ulong)(*(--(c))));     \
				} \
			}

#define l2c(l,c)	(*((c)++)=(uchar)(((l)    )&0xff), \
			 *((c)++)=(uchar)(((l)>> 8)&0xff), \
			 *((c)++)=(uchar)(((l)>>16)&0xff), \
			 *((c)++)=(uchar)(((l)>>24)&0xff))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 7: *(--(c))=(uchar)(((l2)>>16)&0xff); \
			case 6: *(--(c))=(uchar)(((l2)>> 8)&0xff); \
			case 5: *(--(c))=(uchar)(((l2)    )&0xff); \
			case 4: *(--(c))=(uchar)(((l1)>>24)&0xff); \
			case 3: *(--(c))=(uchar)(((l1)>>16)&0xff); \
			case 2: *(--(c))=(uchar)(((l1)>> 8)&0xff); \
			case 1: *(--(c))=(uchar)(((l1)    )&0xff); \
				} \
			}

extern void des_set_odd_parity();
