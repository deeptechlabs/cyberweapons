/*
	prng.c

	Core routines for the Counterpane PRNG
*/
#include "userdefines.h"
#include <windows.h>
#include <stdio.h>
#include "assertverify.h"

#ifdef WIN_NT
#include "ntonly.h"
#endif
#ifdef WIN_95
#include "95only.h"
#endif
#include "smf.h"
#include "sha1mod.h"
#include "entropysources.h"
#include "usersources.h"
#include "comp.h"

/* DLL Headers */
#define YARROWAPI __declspec(dllexport) /* must be declared before yarrow.h  and prng.h */
#include "yarrow.h"
#include "prng.h"
#include "prngpriv.h"

#define _MAX(a,b) (((a)>(b))?(a):(b))
#define _MIN(a,b) (((a)<(b))?(a):(b))

#pragma data_seg(".sdata")
static MMPTR mmp = MM_NULL;
static HANDLE Statmutex = NULL;
static DWORD mutexCreatorId = 0;
#pragma data_seg()
#pragma comment(linker,"/section:.sdata,rws")

/* Process-specific pointers */
PRNG* p= NULL;
HANDLE mutex = NULL;


BOOL WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE caller;

	switch(ul_reason_for_call) 
	{
	case DLL_PROCESS_ATTACH:
		if(mmp != MM_NULL)
		{
			p = (PRNG*)mmGetPtr(mmp);
		}
		if(Statmutex!=NULL)
		{
			caller = OpenProcess(PROCESS_DUP_HANDLE,FALSE,mutexCreatorId);
			DuplicateHandle(caller,Statmutex,GetCurrentProcess(),&mutex,SYNCHRONIZE,FALSE,0);
			CloseHandle(caller);
		}
	break;

    case DLL_THREAD_ATTACH:
	break;

    case DLL_THREAD_DETACH:
	break;

    case DLL_PROCESS_DETACH:
		if(p!=NULL)
		{
			mmReturnPtr(mmp);			
			p = NULL;		
		}
		if(mutex!=NULL) {CloseHandle(mutex);}
	break;
	}
   
   return TRUE;
}  

/* Set up the PRNG */
int m_prngInitialize(void) 
{
	UINT i;
	comp_error_status resp;
	int retval = PRNG_ERR_LOW_MEMORY;

	/* Create the mutex */
	if(mutexCreatorId!=0) {return PRNG_ERR_REINIT;}
	Statmutex = CreateMutex(NULL,TRUE,NULL);
	if(Statmutex == NULL) {mutexCreatorId = 0; return PRNG_ERR_MUTEX;}
	DuplicateHandle(GetCurrentProcess(),Statmutex,GetCurrentProcess(),&mutex,SYNCHRONIZE,FALSE,0);
	mutexCreatorId = GetCurrentProcessId();

	/* Assign memory */
	mmp = mmMalloc(sizeof(PRNG));
	if(mmp==MM_NULL)
	{
		goto cleanup_init;
	}
	else
	{
		p = (PRNG*)mmGetPtr(mmp);
	}

	/* Initialize Variables */
	for(i=0;i<TOTAL_SOURCES;i++) 
	{
		p->poolSize[i] = 0;
		p->poolEstBits[i] = 0;
	}

#ifdef WIN_NT
	/* Setup security on the registry so that remote users cannot predict the slow pool */
	prng_set_NT_security();
#endif

	/* Initialize the secret state. */
	SHA1Init(&p->pool);
	prng_slow_init();	/* Does a slow poll and then calls prng_make_state(...) */

	/* Initialize compression routines */
	for(i=0;i<COMP_SOURCES;i++) 
	{
		resp = comp_init((p->comp_state)+i);
		if(resp!=COMP_SUCCESS) {retval = PRNG_ERR_COMPRESSION; goto cleanup_init;}
	}
	
	p->ready = PRNG_READY;

	return PRNG_SUCCESS;

cleanup_init:
	/* Program failed on one of the mmmallocs */
	mmFree(mmp);
	mmp = MM_NULL;
	CloseHandle(Statmutex);
	Statmutex = NULL;
	mutexCreatorId = 0;

	return retval; /* default PRNG_ERR_LOW_MEMORY */
}



/* Input a state into the PRNG */
int m_prngProcessSeedBuffer(BYTE *buf,LONGLONG ticks) 
{
	CHECKSTATE(p);
	GENCHECK(p);
	PCHECK(buf);

	/* Put the data into the entropy, add some data from the unknown state, reseed */
	SHA1Update(&p->pool,buf,20);				/* Put it into the entropy pool */
	prng_do_SHA1(&p->outstate);		/* Output 20 more bytes and     */
	SHA1Update(&p->pool,p->outstate.out,20);/* add it to the pool as well.  */
	prngForceReseed(ticks); /* Do a reseed */
	return prngOutput(buf,20); /* Return the first 20 bytes of output in buf */
}


/* Provide output */
int m_prngOutput(BYTE *outbuf,UINT outbuflen) 
{
	UINT i;

	CHECKSTATE(p);
	GENCHECK(p);
	PCHECK(outbuf);
	chASSERT(BACKTRACKLIMIT > 0);

	for(i=0;i<outbuflen;i++,p->index++,p->numout++) 
	{
		/* Check backtracklimit */
		if(p->numout > BACKTRACKLIMIT) 
		{
			prng_do_SHA1(&p->outstate);	
			prng_make_new_state(&p->outstate,p->outstate.out);
		}
		/* Check position in IV */
		if(p->index>=20) 
		{
			prng_do_SHA1(&p->outstate);
		}
		/* Output data */
		outbuf[i] = (p->outstate.out)[p->index];
	}

	return PRNG_SUCCESS;
}


/* Take some "random" data and make more "random-looking" data from it */
int prngStretch(BYTE *inbuf,UINT inbuflen,BYTE *outbuf,UINT outbuflen) {
	long int left,prev;
	SHA1_CTX ctx;
	BYTE dig[20];

	PCHECK(inbuf);
	PCHECK(outbuf);

	if(inbuflen >= outbuflen) 
	{
		memcpy(outbuf,inbuf,outbuflen);
		return PRNG_SUCCESS;
	}
	else  /* Extend using SHA1 hash of inbuf */
	{
		SHA1Init(&ctx);
		SHA1Update(&ctx,inbuf,inbuflen);
		SHA1Final(dig,&ctx);
		for(prev=0,left=outbuflen;left>0;prev+=20,left-=20) 
		{
			SHA1Update(&ctx,dig,20);
			SHA1Final(dig,&ctx);
			memcpy(outbuf+prev,dig,(left>20)?20:left);
		}
		trashMemory(dig,20*sizeof(BYTE));
		
		return PRNG_SUCCESS;
	}

	return PRNG_ERR_PROGRAM_FLOW;
}


/* Add entropy to the PRNG from a source */
int m_prngInput(BYTE *inbuf,UINT inbuflen,UINT poolnum,UINT estbits) 
{
	comp_error_status resp;

	CHECKSTATE(p);
	POOLCHECK(p);
	PCHECK(inbuf);
	if(poolnum >= TOTAL_SOURCES) {return PRNG_ERR_OUT_OF_BOUNDS;}

	/* Add to entropy pool */
	SHA1Update(&p->pool,inbuf,inbuflen);
	
	/* Update pool size, pool user estimate and pool compression context */
	p->poolSize[poolnum] += inbuflen;
	p->poolEstBits[poolnum] += estbits;
	if(poolnum<COMP_SOURCES)
	{
		resp = comp_add_data((p->comp_state)+poolnum,inbuf,inbuflen);
		if(resp!=COMP_SUCCESS) {return PRNG_ERR_COMPRESSION;}
	}

	return PRNG_SUCCESS;
}


/* Cause the PRNG to reseed now regardless of entropy pool */ /* Should this be public? */
int m_prngForceReseed(LONGLONG ticks) 
{
	int i;
	LONGLONG start;
	LONGLONG now;
#ifdef WIN_NT
	FILETIME a,b,c,usertime;
#endif
	BYTE buf[64];
	BYTE dig[20];

	CHECKSTATE(p);
	POOLCHECK(p);
	ZCHECK(ticks);

	/* Set up start */
#ifdef WIN_NT
	GetThreadTimes(GetCurrentThread(),&a,&b,&c,&usertime);
	start = (usertime.dwHighDateTime<<32 | usertime.dwLowDateTime) * 10000; /* To get # of ticks */
#endif
#ifdef WIN_95
	start = GetTickCount();
#endif
	do
	{
		/* Do a couple of iterations between time checks */
		prngOutput(buf,64);
		SHA1Update(&p->pool,buf,64);
		prngOutput(buf,64);
		SHA1Update(&p->pool,buf,64);
		prngOutput(buf,64);
		SHA1Update(&p->pool,buf,64);
		prngOutput(buf,64);
		SHA1Update(&p->pool,buf,64);
		prngOutput(buf,64);
		SHA1Update(&p->pool,buf,64);
		/* Set up now */
#ifdef WIN_NT
	GetThreadTimes(GetCurrentThread(),&a,&b,&c,&usertime);
	now = (usertime.dwHighDateTime<<32 | usertime.dwLowDateTime) * 10000; /* To get ticks */
#endif
#ifdef WIN_95
	now = GetTickCount();
#endif
	} while ( (now-start) < ticks) ;
	SHA1Final(dig,&p->pool);
	SHA1Update(&p->pool,dig,20); 
	SHA1Final(dig,&p->pool);

	/* Reset secret state */
	SHA1Init(&p->pool);
	prng_make_new_state(&p->outstate,dig);

	/* Clear counter variables */
	for(i=0;i<TOTAL_SOURCES;i++) 
	{
		p->poolSize[i] = 0;
		p->poolEstBits[i] = 0;
	}

	/* Cleanup memory */
	trashMemory(dig,20*sizeof(char));
	trashMemory(buf,64*sizeof(char));

	return PRNG_SUCCESS;
}


/* If we have enough entropy, allow a reseed of the system */
int m_prngAllowReseed(LONGLONG ticks) 
{
	UINT temp[TOTAL_SOURCES];
	UINT i,sum;
	float ratio;
	comp_error_status resp;


	CHECKSTATE(p);

	for(i=0;i<ENTROPY_SOURCES;i++)
	{
		/* Make sure that compression-based entropy estimates are current */
		resp = comp_get_ratio((p->comp_state)+i,&ratio);
		if(resp!=COMP_SUCCESS) {return PRNG_ERR_COMPRESSION;}
		/* Use 4 instead of 8 to half compression estimate */
		temp[i] = (int)(ratio*p->poolSize[i]*4); 
	}
	/* Use minumum of user and compression estimate for compressed sources */
	for(i=ENTROPY_SOURCES;i<COMP_SOURCES;i++)
	{
		/* Make sure that compression-based entropy estimates are current */
		resp = comp_get_ratio((p->comp_state)+i,&ratio);
		if(resp!=COMP_SUCCESS) {return PRNG_ERR_COMPRESSION;}
		/* Use 4 instead of 8 to half compression estimate */
		temp[i] = _MIN((int)(ratio*p->poolSize[i]*4),(int)p->poolEstBits[i]); 
	}
	/* Use user estimate for remaining sources */
	for(i=COMP_SOURCES;i<TOTAL_SOURCES;i++) {temp[i] = p->poolEstBits[i];}

	bubbleSort(temp,TOTAL_SOURCES);
	for(i=K,sum=0;i<TOTAL_SOURCES;sum+=temp[i++]); /* Stupid C trick */
	if(sum>THRESHOLD) 
		return prngForceReseed(ticks);
	else 
		return PRNG_ERR_NOT_ENOUGH_ENTROPY;

	return PRNG_ERR_PROGRAM_FLOW;
}

/* Call a slow poll and insert the data into the entropy pool */
int m_prngSlowPoll(UINT pollsize)
{
	BYTE *buf;
	DWORD len;
	prng_error_status retval;

	CHECKSTATE(p);

	buf = (BYTE*)malloc(pollsize);
	if(buf==NULL) {return PRNG_ERR_LOW_MEMORY;}
	len = prng_slow_poll(buf,pollsize);	/* OS specific call */
	retval = prngInputEntropy(buf,len,SLOWPOLLSOURCE);
	trashMemory(buf,pollsize);
	free(buf);

	return retval;
}


/* Delete the PRNG */
int m_prngDestroy(void) 
{
	UINT i;

	if(GetCurrentProcessId()!=mutexCreatorId) {return PRNG_ERR_WRONG_CALLER;}
	if(p==NULL) {return PRNG_SUCCESS;} /* Well, there is nothing to destroy... */

	p->ready = PRNG_NOT_READY;
	
	for(i=0;i<COMP_SOURCES;i++)
	{
		comp_end((p->comp_state)+i);
	}

	mmFree(mmp);
	mmp = MM_NULL;
	p = NULL;
	
	CloseHandle(Statmutex);
	Statmutex = NULL;
	mutexCreatorId = 0;

	return PRNG_SUCCESS;
}

#include "prng.mut" /* This file wraps the above functions for use with the mutex */

/* Utility functions  -  Cannot be called from outside*/
/* All error checking should be done in the function that calls these */
void prng_do_SHA1(GEN_CTX *ctx) 
{
	SHA1_CTX sha;

	SHA1Init(&sha);
	SHA1Update(&sha,ctx->IV,20);
	SHA1Update(&sha,ctx->out,20);
	SHA1Final(ctx->out,&sha);
	p->index = 0;
}

void prng_make_new_state(GEN_CTX *ctx,BYTE *state) 
{
	SHA1_CTX sha;

	memcpy(ctx->IV,state,20);
	SHA1Init(&sha);
	SHA1Update(&sha,ctx->IV,20);
	SHA1Final(ctx->out,&sha);
	p->numout = 0;
	p->index = 0;
}


/* Initialize the secret state with a slow poll */
#define SPLEN 65536  /* 64K */

void prng_slow_init(void)
/* This fails silently and must be fixed. */
{
	SHA1_CTX* ctx = NULL;
	MMPTR mmctx = MM_NULL;
	BYTE* bigbuf = NULL;
	MMPTR mmbigbuf = MM_NULL;
	BYTE* buf = NULL;
	MMPTR mmbuf = MM_NULL;
	DWORD polllength;

	mmbigbuf = mmMalloc(SPLEN);
	if(mmbigbuf == MM_NULL) {goto cleanup_slow_init;}
	bigbuf = (BYTE*)mmGetPtr(mmbigbuf);

	mmbuf = mmMalloc(20);
	if(mmbuf == MM_NULL) {goto cleanup_slow_init;}
	buf = (BYTE*)mmGetPtr(mmbuf);

	mmctx = mmMalloc(sizeof(SHA1_CTX));
	if(mmctx == MM_NULL) {goto cleanup_slow_init;}
	ctx = (SHA1_CTX*)mmGetPtr(mmctx);


	/* Initialize the secret state. */
	/* Init entropy pool */
	SHA1Init(&p->pool);
	/* Init output generator */
	polllength = prng_slow_poll(bigbuf,SPLEN);
	SHA1Init(ctx);
	SHA1Update(ctx,bigbuf,polllength);
	SHA1Final(buf,ctx);
	prng_make_new_state(&p->outstate,buf);

cleanup_slow_init:
	mmFree(mmctx);
	mmFree(mmbigbuf);
	mmFree(mmbuf);

	return;
}

void trashMemory(void* mem,UINT len)
/* This function should only be used on data in RAM */
{
	/* Cycle a bit just in case it is one of those weird memory units */
	/* No, I don't know which units those would be */
	memset(mem,0x00,len);
	memset(mem,0xFF,len);
	memset(mem,0x00,len);
}

/* In-place modifed bubble sort */
void bubbleSort(UINT *data,UINT len) 
{
	UINT i,last,newlast,temp;

	last = len-1; 
	while(last!=-1) 
	{
		newlast = -1;
		for(i=0;i<last;i++) 
		{
			if(data[i+1] > data[i]) 
			{
				newlast = i;
				temp = data[i];
				data[i] = data[i+1];
				data[i+1] = temp;
			}
		}
		last = newlast;
	}		
}



