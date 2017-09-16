/*
	yarrow.h

	Main header file for Counterpane's Yarrow Pseudo-random number generator.
*/

#ifndef YARROW_H
#define YARROW_H

/* Error Codes */
typedef enum prng_error_status {
	PRNG_SUCCESS = 0,
	PRNG_ERR_REINIT,
	PRNG_ERR_WRONG_CALLER,
	PRNG_ERR_NOT_READY,
	PRNG_ERR_NULL_POINTER,
	PRNG_ERR_LOW_MEMORY,
	PRNG_ERR_OUT_OF_BOUNDS,
	PRNG_ERR_COMPRESSION,
	PRNG_ERR_NOT_ENOUGH_ENTROPY,
	PRNG_ERR_MUTEX,
	PRNG_ERR_TIMEOUT,
	PRNG_ERR_PROGRAM_FLOW
} prng_error_status;

/* Declare YARROWAPI as __declspec(dllexport) before
   including this file in the actual DLL */
#ifndef YARROWAPI 
#define YARROWAPI __declspec(dllimport)
#endif

/* Public function forward declarations */
YARROWAPI int prngOutput(BYTE *outbuf,UINT outbuflen);
YARROWAPI int prngStretch(BYTE *inbuf,UINT inbuflen,BYTE *outbuf,UINT outbuflen);
YARROWAPI int prngInput(BYTE *inbuf,UINT inbuflen,UINT poolnum,UINT estbits);
YARROWAPI int prngForceReseed(LONGLONG ticks);
YARROWAPI int prngAllowReseed(LONGLONG ticks);
YARROWAPI int prngProcessSeedBuffer(BYTE *buf,LONGLONG ticks);
YARROWAPI int prngSlowPoll(UINT pollsize);

#endif