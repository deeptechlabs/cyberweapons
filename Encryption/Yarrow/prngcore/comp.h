/* comp.h

   Header for the compression routines added to the Counterpane PRNG. 
*/

#ifndef YARROW_COMP_H
#define YARROW_COMP_H

#include "zlib.h"
#include "smf.h"

/* Top level compression context */
typedef struct{
	MMPTR buf;
	uInt spaceused;
} COMP_CTX;

typedef enum comp_error_status {
	COMP_SUCCESS = 0,
	COMP_ERR_NULL_POINTER,
	COMP_ERR_LOW_MEMORY,
	COMP_ERR_LIB
} comp_error_status;

/* Exported functions from compress.c */
comp_error_status comp_init(COMP_CTX* ctx);
comp_error_status comp_add_data(COMP_CTX* ctx,Bytef* inp,uInt inplen);
comp_error_status comp_end(COMP_CTX* ctx);
comp_error_status comp_get_ratio(COMP_CTX* ctx,float* out);

#endif