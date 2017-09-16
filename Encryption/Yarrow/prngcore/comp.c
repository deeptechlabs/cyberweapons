/*
	comp.c

	Updated routines connecting the core prng code to the Zlib library
*/
#include <windows.h>
#include <math.h>
#include "comp.h"

/* Check that the pointer is not NULL */
#define PCHECK(ptr)  if(ptr==NULL) {return COMP_ERR_NULL_POINTER;}
#define MMPCHECK(mmptr) if(mmptr==MM_NULL) {return COMP_ERR_NULL_POINTER;}
/* Check that the important parts of the context are ok */
#define CTXCHECK(ctx) \
PCHECK(ctx)				\
MMPCHECK(ctx->buf)

/* Might want to vary these by context */
#define BUFSIZE  16384 /* 16K */
#define OUTBUFSIZE 16800 /* = inbufsize*1.01 + 12 (See zlib docs) */
#define SHIFTSIZE 4096 /* BUFSIZE/4 */

#define _MIN(a,b) (((a)<(b))?(a):(b))


/* Initialize these routines */
comp_error_status comp_init(COMP_CTX* ctx)
{
	ctx->buf = mmMalloc(BUFSIZE);
	if(ctx->buf == MM_NULL) {goto cleanup_comp_init;}
	ctx->spaceused = 0;

	return COMP_SUCCESS;

cleanup_comp_init:
	mmFree(ctx->buf);

	return COMP_ERR_LOW_MEMORY;
}


comp_error_status comp_add_data(COMP_CTX* ctx,Bytef* inp,uInt inplen)
{
	uInt shifts;
	uInt blocksize;
	BYTE* buf;

	CTXCHECK(ctx);
	PCHECK(inp);

	buf = (BYTE*)mmGetPtr(ctx->buf);

	if(inplen+SHIFTSIZE>BUFSIZE)
	{
		blocksize = _MIN(inplen,BUFSIZE);
		memmove(buf,inp,blocksize);
		ctx->spaceused = blocksize;
	}
	else
	{
		if(inplen+ctx->spaceused>BUFSIZE) 
		{
			shifts = (uInt)ceil((inplen+ctx->spaceused-BUFSIZE)/(float)SHIFTSIZE);
			blocksize = _MIN(shifts*SHIFTSIZE,ctx->spaceused);
			memmove(buf,buf+blocksize,BUFSIZE-blocksize);
			ctx->spaceused = ctx->spaceused - blocksize;
		}
		memmove(buf+ctx->spaceused,inp,inplen);
		ctx->spaceused += inplen;
	}

	return COMP_SUCCESS;
}


comp_error_status comp_get_ratio(COMP_CTX* ctx,float* out)
{
	Bytef *inbuf,*outbuf;
	uLong insize,outsize;
	int resp;

	*out = 0;

	CTXCHECK(ctx);
	PCHECK(out);

	if(ctx->spaceused == 0) {return COMP_SUCCESS;}

	inbuf = (Bytef*)mmGetPtr(ctx->buf);
	outbuf = (Bytef*)malloc(OUTBUFSIZE);
	if(outbuf==NULL) {return COMP_ERR_LOW_MEMORY;}

	insize = ctx->spaceused;
	outsize = OUTBUFSIZE;

	resp = compress(outbuf,&outsize,inbuf,insize);
	if(resp==Z_MEM_ERROR) {return COMP_ERR_LOW_MEMORY;}
	if(resp==Z_BUF_ERROR) {return COMP_ERR_LIB;}

	*out = (float)outsize/(float)insize;

	/* Thrash the memory and free it */
	memset(outbuf,0x00,OUTBUFSIZE);
	memset(outbuf,0xFF,OUTBUFSIZE);
	memset(outbuf,0x00,OUTBUFSIZE);
	free(outbuf);

	return COMP_SUCCESS;
}


comp_error_status comp_end(COMP_CTX* ctx)
{
	if(ctx == NULL) {return COMP_SUCCESS;} /* Since nothing is left undone */

	mmFree(ctx->buf);
	ctx->buf = MM_NULL;

	return COMP_SUCCESS;
}
