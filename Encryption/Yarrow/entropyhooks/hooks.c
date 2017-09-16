/*
	hooks.c

	Code for the Counterpane PRNG entropy collection rountines DLL.
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "smf.h"
#include "entropysources.h"
#define HOOKSAPI __declspec(dllexport) /* must be declared before hooks.h */
#include "hooks.h"
#include "hookspriv.h"

/* Size of the associated data array */ /* Should be a multiple of 4 for CompressArray to work */
#define KEYTIMESIZE		1000
#define MOUSETIMESIZE	1000	
#define MOUSEMOVESIZE	1000

/* Length of the appropratie WaitForSingleObject wait */
#define KEYTIMEWAIT		100
#define MOUSETIMEWAIT	100
#define MOUSEMOVEWAIT	100

#define _MAX(a,b) (((a)>(b))?(a):(b))

/*Declare shared variables. These variable must be initialized or this will not work.
  Yeah, right, like I understand that. Just do it,'k?  */
#pragma data_seg(".sdata")
/*Instance pointer*/
static HINSTANCE ghInst = NULL;
/*Hook pointer storage*/
static HHOOK ghhookKB = NULL;
static HHOOK ghhookMS = NULL;
/*Entropy storage*/
#define KEYTIMETYPE WORD
#define MOUSETIMETYPE WORD
#define MOUSEMOVETYPE POINT
static MMPTR keytime = MM_NULL;
static MMPTR mousetime = MM_NULL;
static MMPTR mousemove = MM_NULL;
/*Storage indices*/
static int keytimeindex = 0;
static int mousetimeindex = 0;
static int mousemoveindex = 0;
/*Kernel objects and other related information*/
static DWORD CallerId = 0;
static MMPTR comm = MM_NULL;
static HANDLE StatDataReady = NULL;
static HANDLE StatWriteAllowed = NULL;
static HANDLE StatWriteMutex = NULL;
/*Timer stuff*/
static BOOL PerfCount = FALSE;
static DWORD timemask = 0;
/**/
#pragma data_seg()
#pragma comment(linker,"/section:.sdata,rws")

/*Data necessary for each process that attaches*/
static HANDLE dataReady = NULL;
static HANDLE writeAllowed = NULL;
static HANDLE writeMutex = NULL;

BOOL WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
   HANDLE caller;
   
   ghInst = hInst;

   switch(ul_reason_for_call) 
   {
    case DLL_PROCESS_ATTACH:
		if( (StatDataReady!=NULL) && (dataReady==NULL) ) /* Assume that these are indicative */
		{
			caller = OpenProcess(PROCESS_DUP_HANDLE,FALSE,CallerId);
			DuplicateHandle(caller,StatDataReady,GetCurrentProcess(),&dataReady,EVENT_MODIFY_STATE|SYNCHRONIZE,FALSE,0);
			DuplicateHandle(caller,StatWriteAllowed,GetCurrentProcess(),&writeAllowed,EVENT_MODIFY_STATE|SYNCHRONIZE,FALSE,0);
			DuplicateHandle(caller,StatWriteMutex,GetCurrentProcess(),&writeMutex,SYNCHRONIZE,FALSE,0);
			CloseHandle(caller);
		}
    break;

    case DLL_THREAD_ATTACH:
    break;

    case DLL_THREAD_DETACH:
    break;

    case DLL_PROCESS_DETACH:
		if(dataReady!=NULL) {CloseHandle(dataReady);}
		if(writeAllowed!=NULL) {CloseHandle(writeAllowed);}
		if(writeMutex!=NULL) {CloseHandle(writeMutex);}
		mmReturnPtr(keytime);
		mmReturnPtr(mousetime);
		mmReturnPtr(mousemove);
    break;
   }
   
   return TRUE;
}                 

hooks_error_status WINAPI SetHooks(void)
{
	hooks_error_status retval;

	/*Have we done this before?*/
	if(CallerId != 0) {return HOOKS_ERR_REINIT;}

	/*Collect caller information*/
	CallerId = GetCurrentProcessId();

	/*Setup mutex*/
	StatWriteMutex = CreateMutex(NULL,TRUE,NULL);
	if(StatWriteMutex == NULL) {return HOOKS_ERR_HANDLE;}
	DuplicateHandle(GetCurrentProcess(),StatWriteMutex,GetCurrentProcess(),&writeMutex,SYNCHRONIZE,FALSE,0);

	/*Setup Data memory*/
	keytime = mmMalloc(sizeof(KEYTIMETYPE)*KEYTIMESIZE);
	mousetime = mmMalloc(sizeof(MOUSETIMETYPE)*MOUSETIMESIZE);
	mousemove = mmMalloc(sizeof(MOUSEMOVETYPE)*MOUSEMOVESIZE);
	if((keytime==MM_NULL) || (mousemove==MM_NULL) || (mousetime==MM_NULL))
	{
		retval = HOOKS_ERR_LOW_MEMORY;
		goto cleanup_set_hooks;
	}

	/*Setup hooks*/
	ghhookKB = SetWindowsHookEx(WH_KEYBOARD, KeyboardHook, ghInst, 0);
	ghhookMS = SetWindowsHookEx(WH_MOUSE, MouseHook, ghInst, 0);
	if((ghhookKB==NULL)||(ghhookMS==NULL))
	{
		retval = HOOKS_ERR_SETUP;
		goto cleanup_set_hooks;
	}


	/*Setup counter details*/
	setupCounter();

	ReleaseMutex(writeMutex);

	return HOOKS_SUCCESS;

cleanup_set_hooks:
	mmFree(keytime); keytime = MM_NULL;
	mmFree(mousemove); mousemove = MM_NULL;
	mmFree(mousetime); mousetime = MM_NULL;
	ReleaseMutex(StatWriteMutex);
	CloseHandle(StatWriteMutex);
	CallerId = 0;

	return retval;
}

void setupCounter(void)
/* This function will set PerfCount if there is a performance counter and will set timemask
   such that only the mostly significantly random bits of the timing intervals are kept */
{
	LARGE_INTEGER li;

	PerfCount = QueryPerformanceFrequency(&li);
	if(PerfCount == TRUE) /* If there is a performance counter, check frequency */
	{
		if(li.HighPart != 0) /*Extremely high frequency counter*/
		{
			timemask = 0x0000FFFF;
		}
		else if(li.LowPart >= 1000000) /*Usual value appears to be 1193180*/
		{	
			timemask = 0x0000FFFF;
		}
		else if(li.LowPart >= 70000)
		{
			timemask = 0x00000FFF;
		}
		else if(li.LowPart >= 1000)
		{
			timemask = 0x000000FF;
		}
		else
		{
			PerfCount = FALSE; /* You are better off using the device timer at this point... */
		}
	}
	if(PerfCount==FALSE) /* If not, we have to use GetTickCount() */
	{
		timemask = 0x0000000F; /* Resolution of about 10ms */
	}
}

hooks_error_status WINAPI SetupMMComm(LPVOID* pComm, HANDLE* pDataReady, HANDLE* pWriteAllowed)
{
	DWORD request;
	hooks_error_status retval;

	if(GetCurrentProcessId() != CallerId) {return HOOKS_ERR_WRONG_CALLER;}
	if(StatDataReady != NULL) {return HOOKS_ERR_REINIT;}
	MCHECK(pComm);
	MCHECK(pDataReady);
	MCHECK(pWriteAllowed);

	*pComm = NULL;
	*pDataReady = NULL;
	*pWriteAllowed = NULL;

	request = _MAX(sizeof(WORD)*KEYTIMESIZE,sizeof(WORD)*MOUSETIMESIZE);
	request = _MAX(request,sizeof(POINT)*MOUSEMOVESIZE);
	request += 2*sizeof(int); /* Source number and data length information */

	comm = mmMalloc(request);
	if(comm == MM_NULL) {return HOOKS_ERR_LOW_MEMORY;}
	*pComm = mmGetPtr(comm);

	*pDataReady = StatDataReady = CreateEvent(NULL,FALSE,FALSE,NULL);
	if(StatDataReady == NULL) {retval = HOOKS_ERR_HANDLE; goto cleanup_setup_mm_comm;}
	*pWriteAllowed = StatWriteAllowed = CreateEvent(NULL,FALSE,TRUE,NULL);
	if(StatWriteAllowed == NULL) {retval = HOOKS_ERR_HANDLE; goto cleanup_setup_mm_comm;}

	/*Setup process specific handles etal*/
	DuplicateHandle(GetCurrentProcess(),StatDataReady,GetCurrentProcess(),&dataReady,EVENT_MODIFY_STATE|SYNCHRONIZE,FALSE,0);
	DuplicateHandle(GetCurrentProcess(),StatWriteAllowed,GetCurrentProcess(),&writeAllowed,EVENT_MODIFY_STATE|SYNCHRONIZE,FALSE,0);

	return HOOKS_SUCCESS;

cleanup_setup_mm_comm:
	if(StatWriteAllowed != NULL) {CloseHandle(StatWriteAllowed); StatWriteAllowed = NULL;}
	if(StatDataReady != NULL) {CloseHandle(StatDataReady); StatDataReady = NULL;}
	return retval;
}

hooks_error_status WINAPI CloseMMComm(void)
{
	int entropy_source = MSG_CLOSE_PIPE;

	if(GetCurrentProcessId() != CallerId) {return HOOKS_ERR_WRONG_CALLER;} 
	/* Destroy mutex - This thread captures the mutex but does not release it
		This causes the other threads waiting on the mutex to return WAIT_ABANDONED,
		and immediately return.
	*/
	/* Mutex is destroyed at this time to make sure that WriteData isn't running */
	while(WaitForSingleObject(StatWriteMutex,0) == WAIT_TIMEOUT)
	{
		Sleep(0); /* Give up the rest of your time slice */
	}
	CloseHandle(StatWriteMutex);	

	/* Sent break message to other side */
	WaitForSingleObject(StatWriteAllowed,INFINITE);
	memcpy(mmGetPtr(comm),&entropy_source,sizeof(int));
	SetEvent(StatDataReady);
	WaitForSingleObject(StatWriteAllowed,INFINITE); /* Make sure that the other end figured it out */

	/* Clean up */
	if(comm != MM_NULL)
	{
		mmFree(comm); 
		comm = MM_NULL;
	}

	if(StatDataReady != NULL)
	{
		CloseHandle(StatDataReady);
		StatDataReady = NULL;
	}
	
	if(StatWriteAllowed != NULL)
	{
		CloseHandle(StatWriteAllowed);
		StatWriteAllowed = NULL;
	}

	return HOOKS_SUCCESS;
}


hooks_error_status WINAPI RemoveHooks(void)
{
	if(GetCurrentProcessId() != CallerId) {return HOOKS_ERR_WRONG_CALLER;} 

	/*Unhook the hooks*/
	UnhookWindowsHookEx(ghhookKB);
	UnhookWindowsHookEx(ghhookMS);

	/*Clear the memory*/
	mmFree(keytime); keytime = MM_NULL;
	mmFree(mousemove); mousemove = MM_NULL;
	mmFree(mousetime); mousetime = MM_NULL;

	/* Clear the process identifier */
	CallerId = 0;

	return HOOKS_SUCCESS;
} 

LRESULT CALLBACK KeyboardHook(int nCode, WORD wParam, LONG lParam)
{
	static DWORD then = 0;
	static DWORD now = 0;
	WORD diff;
	LARGE_INTEGER time;
	DWORD waitret;
	static LONG running = FALSE;

	/*Do not process message if nCode <0 or ==HC_NOREMOVE 
	  or if this is a key up (as opposed to down) */
    if ( (nCode < 0)  || (nCode == HC_NOREMOVE) || (lParam & 0x80000000) )  
        return CallNextHookEx(ghhookKB, nCode,wParam, lParam); 

	/* Make sure that this thread is not already running this function */
	if(InterlockedExchange(&running,TRUE) == TRUE) 
        return CallNextHookEx(ghhookKB, nCode,wParam, lParam); /* It was already locked */

	/*Begin Mutex*/
	waitret = WaitForSingleObject(writeMutex,KEYTIMEWAIT);
	if(waitret != WAIT_OBJECT_0)
	{
	/* Could not capture the mutex for some reason, so abandon hook procedure */
		InterlockedExchange(&running,FALSE);
		return CallNextHookEx(ghhookKB, nCode, wParam, lParam); 
	}

	/*Check time*/
	if(PerfCount==TRUE)
	{
 		QueryPerformanceCounter(&time);
		now = time.LowPart;	/*Less than the last 32 bits will be significant anyway*/
	}
	else
	{
		now = GetTickCount();
	}
	/*Set timers and collect data*/
	diff = (now - then) & timemask;
	then = now;	
	((KEYTIMETYPE*)mmGetPtr(keytime))[keytimeindex++] = diff; 
	/*Dump data if necessary*/
	if(keytimeindex >= KEYTIMESIZE)
	{
		WriteKeyTime(KEYTIMESIZE); /* Return value is irrelevant */
		keytimeindex = 0;
	}

	/*End mutex*/
	ReleaseMutex(writeMutex);

	InterlockedExchange(&running,FALSE);

	//Return
    return CallNextHookEx(ghhookKB, nCode, wParam, lParam); 
} 


LRESULT CALLBACK MouseHook(int nCode, WORD wParam, LONG lParam)
{
	static DWORD then = 0;
	static DWORD now = 0;
	WORD diff;
	LARGE_INTEGER time;
	DWORD waitret;
	static LONG running = FALSE;


	/*Do not process message if nCode <0 or ==HC_NOREMOVE */
    if ( (nCode < 0)  || (nCode == HC_NOREMOVE) )  
        return CallNextHookEx(ghhookMS, nCode,wParam, lParam); 

	/* Make sure that this thread is not already running this function */
	if(InterlockedExchange(&running,TRUE) == TRUE) 
        return CallNextHookEx(ghhookKB, nCode,wParam, lParam); /* It was already locked */

	switch(wParam) /*Message type*/
	{
	case WM_LBUTTONDOWN:		/*Get timing from button clicks...*/
	case WM_RBUTTONDOWN:
	case WM_MBUTTONDOWN:	
	case WM_NCLBUTTONDOWN:
	case WM_NCRBUTTONDOWN:
	case WM_NCMBUTTONDOWN:	
		/*Start mutex*/
		waitret = WaitForSingleObject(writeMutex,MOUSETIMEWAIT);
		if(waitret != WAIT_OBJECT_0)
		{
		/* Could not capture the mutex for some reason, so abandon hook procedure */
			InterlockedExchange(&running,FALSE);
			return CallNextHookEx(ghhookKB, nCode, wParam, lParam); 
		}

		/*Check time*/
		if(PerfCount==TRUE)
		{
 			QueryPerformanceCounter(&time);
			now = time.LowPart;	/*Less than the last 32 bits will be significant anyway*/
		}
		else
		{
			now = GetTickCount();
		}
		/*Set timers and collect data*/
		diff = (now - then) & timemask;
		then = now;
		((MOUSETIMETYPE*)mmGetPtr(mousetime))[mousetimeindex++] = diff; 
		/*Dump data if necessary*/
		if(mousetimeindex >= MOUSETIMESIZE)
		{
			WriteMouseTime(MOUSETIMESIZE); /* Return value is irrelevant */
			mousetimeindex = 0;
		}

		/*End mutex*/
		ReleaseMutex(writeMutex);

		break;
	case WM_MOUSEMOVE:		/*Record the mouse location*/
	case WM_NCMOUSEMOVE:
		/*Start mutex*/
		waitret = WaitForSingleObject(writeMutex,MOUSEMOVEWAIT);
		if(waitret != WAIT_OBJECT_0)
		{
		/* Could not capture the mutex for some reason, so abandon hook procedure */
			InterlockedExchange(&running,FALSE);
			return CallNextHookEx(ghhookKB, nCode, wParam, lParam); 
		}

		((MOUSEMOVETYPE*)mmGetPtr(mousemove))[mousemoveindex++] = ((MOUSEHOOKSTRUCT*)lParam)->pt;

		/*Dump data if necessary*/
		if(mousemoveindex >= MOUSEMOVESIZE)
		{
			WriteMouseMove(MOUSEMOVESIZE);
			mousemoveindex = 0;
		}

		/*End mutex*/
		ReleaseMutex(writeMutex);

		break;
	}

	InterlockedExchange(&running,FALSE);

	/*Return*/
	return CallNextHookEx(ghhookMS, nCode, wParam, lParam); 
} 

/*Helper functions*/
void CompressArray(WORD* ptr,DWORD mask,int* size)
/* In-place compression of an array. New size returned in size */
{
	int i,j;

	if(mask == 0x00000FFF)
	{
		for(i=0,j=0;i<*size;i+=4,j+=3)
		{
			ptr[j+0] = ptr[i+0] << 4;
			ptr[j+0] |= ptr[i+1] >> 8;
			ptr[j+1] = ptr[i+1] << 8;
			ptr[j+1] |= ptr[i+2] >>4;
			ptr[j+2] = ptr[i+2] << 12;
			ptr[j+2] |= ptr[i+3];
		}
		*size = j;
	}
	else if(mask == 0x000000FF)
	{
		for(i=0,j=0;i<*size;i+=2,j++)
		{
			ptr[j] = ptr[i+0] << 8 | ptr[i+1];
		}
		*size = j;
	}
	else if(mask == 0x0000000F)
	{
		for(i=0,j=0;i<*size;i+=4,j++)
		{
			ptr[j] = ptr[i+0]<<12 | ptr[i+1]<<8 | ptr[i+2]<<4 | ptr[i+3];
		}
		*size = j;
	}

}

BOOL WriteMouseTime(int limit)
{
	CompressArray((WORD*)mmGetPtr(mousetime),timemask,&limit);
	return WriteData(MOUSETIMESOURCE,mmGetPtr(mousetime),sizeof(WORD)*limit);
}

BOOL WriteMouseMove(int limit)
{
	return WriteData(MOUSEMOVESOURCE,mmGetPtr(mousemove),sizeof(POINT)*limit);
}

BOOL WriteKeyTime(int limit)
{
	CompressArray((WORD*)mmGetPtr(keytime),timemask,&limit);
	return WriteData(KEYTIMESOURCE,mmGetPtr(keytime),sizeof(WORD)*limit);
}

BOOL WriteData(int entropy_source,LPVOID data,int size)
{
	WaitForSingleObject(writeAllowed,INFINITE);
	memcpy(mmGetPtr(comm),&entropy_source,sizeof(int));
	memcpy((BYTE*)mmGetPtr(comm)+sizeof(int),&size,sizeof(int));
	memcpy((BYTE*)mmGetPtr(comm)+2*sizeof(int),data,size);
	SetEvent(dataReady);

	return TRUE;
}