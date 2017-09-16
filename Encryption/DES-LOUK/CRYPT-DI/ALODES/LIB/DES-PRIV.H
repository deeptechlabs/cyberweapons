#ifndef DES_PRIVATE
#define DES_PRIVATE 1

#include "des.h"

#if (!BIG_ENDIAN && !LITTLE_ENDIAN)
#ifdef i386
#define LITTLE_ENDIAN 1
#endif
#ifdef sun386
#define LITTLE_ENDIAN 1
#endif
#ifdef THINK_C			/* THINK C compiler for Mac */
#define BIG_ENDIAN 1
#endif
#ifdef mc68000
#define BIG_ENDIAN 1
#endif
#ifdef sparc
#define BIG_ENDIAN 1
#endif
#if defined(vax) || (defined(ultrix) && defined(mips))
#define LITTLE_ENDIAN 1
#endif
#endif
#if (!BIG_ENDIAN && !LITTLE_ENDIAN)
static int foobar=You_should_specify_endian_in_des_private_file;
#endif

extern const des_u_long	des_spe_table[];

extern des_u_long	des_unexpand();

#define copy_N(from,to,type) (*((type*)&(to)) = *((type*)&(from)))
#define copy8(from,to) copy_N(from,to,C_Block)
#define copy4(from,to) copy_N(from,to,des_u_long)
#define lval_N(from,type) (*((type*)&(from)))
#define val4(variable) lval_N(variable,des_u_long)

#endif
