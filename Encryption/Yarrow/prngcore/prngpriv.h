/*
	prngpriv.h

	Completely private header for the Counterpane PRNG. Should only be included by prng.c
*/

#ifndef YARROW_PRNG_PRIV_H
#define YARROW_PRNG_PRIV_H

#include "userdefines.h"
#include "yarrow.h"
#include "entropysources.h"
#include "usersources.h"
#include "comp.h"
#include "sha1mod.h"
#include "smf.h"

#define TOTAL_SOURCES ENTROPY_SOURCES+USER_SOURCES

#ifdef COMPRESSION_ON
#define COMP_SOURCES TOTAL_SOURCES
#else
#define COMP_SOURCES ENTROPY_SOURCES
#endif

/* Error numbers */
typedef enum prng_ready_status {
	PRNG_READY = 33,	/* Compiler will initialize to either 0 or random if allowed to */
	PRNG_NOT_READY = 0
} prng_ready_status;

/* Top level output state */
typedef struct{
	BYTE IV[20];
	BYTE out[20];
} GEN_CTX;

/* PRNG state structure */
typedef struct{
	/* Output State */
	GEN_CTX outstate;
	UINT index;
	UINT numout;

	/* Entropy Pools (somewhat unlike a gene pool) */
	SHA1_CTX pool;
	UINT poolSize[TOTAL_SOURCES];			/* Note that size is in bytes and est in bits */
	UINT poolEstBits[TOTAL_SOURCES];
	COMP_CTX comp_state[COMP_SOURCES];

	/* Status Flags */
	prng_ready_status ready;
} PRNG;


/* Utility functions forward declerations */
void prng_do_SHA1(GEN_CTX *ctx);
void prng_make_new_state(GEN_CTX *ctx,BYTE *state);
void prng_slow_init(void);
void trashMemory(void* mem,UINT len);
void bubbleSort(UINT* data,UINT len);

/* Test Macros */
#define CHECKSTATE(p) \
if(p==NULL) {return PRNG_ERR_NOT_READY;} /* Does the state exist? */	\
if(p->ready != PRNG_READY) {return PRNG_ERR_NOT_READY;}	/* Set error state and return */
/* To make sure that a pointer isn't NULL */
#define PCHECK(ptr)  if(ptr==NULL) {return PRNG_ERR_NULL_POINTER;}
/* To make sure that malloc returned a valid value */
#define MCHECK(ptr)  if(ptr==NULL) {return PRNG_ERR_LOW_MEMORY;}
/* To make sure that a given value is non-negative */
#define ZCHECK(val)  if(p<0) {return PRNG_ERR_OUT_OF_BOUNDS;}
/* To make sure that the generator state is valid */
#define GENCHECK(p) if(p->index>20) {return PRNG_ERR_OUT_OF_BOUNDS;} /* index is unsigned */
/* To make sure that the entropy pool is valid */
#define POOLCHECK(p) /* */


#endif