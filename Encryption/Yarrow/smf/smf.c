/* Smf.c 

   Secure malloc and free DLL routines 
*/

#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#define SMFAPI __declspec(dllexport)
#include "smf.h"
#include "smfpriv.h"

#define MAXBLOCKS	250				/* Watch out with the size of this value */
#define SMF_MUTEX	"smf_mutex.2341"/* No controlling process, so we need a named nutex */	

#pragma data_seg(".sdata")
static mminfo info[MAXBLOCKS] = {{33,0,0,0}};	/* Data from first allocator */
#pragma data_seg()
#pragma comment(linker,"/section:.sdata,rws")

/* Data for each allocator */
static LPVOID ptrs[MAXBLOCKS];
static HANDLE mutex;
/*	Note that the mutex is designed to protect the info array from corruption.
	Protection of memory contents assigned is left up to the user. */


BOOL WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	MMPTR i;

	switch(ul_reason_for_call) 
	{
	case DLL_PROCESS_ATTACH:
		/* Setup for whole DLL */
		if(info[0].OrgId == 33)
		{
			for(i=0;i<MAXBLOCKS;i++)
			{
				info[i].OrgId = 0;
				info[i].hand = NULL;
				info[i].count = 0;
				info[i].size = 0;
			}
		}
		/* Setup for this process */
		for(i=0;i<MAXBLOCKS;i++)
			{ptrs[i] = NULL;}
		mutex = OpenMutex(SYNCHRONIZE,FALSE,SMF_MUTEX);
		if(mutex == NULL)
		{
			mutex = CreateMutex(NULL,FALSE,SMF_MUTEX);
		}
	break;

    case DLL_THREAD_ATTACH:
	break;

    case DLL_THREAD_DETACH:
	break;

    case DLL_PROCESS_DETACH:
		/* Unmap any pointers */
		for(i=1;i<MAXBLOCKS;i++)
		{
			mmReturnPtr(i);
		}
		if(mutex!=NULL) {CloseHandle(mutex);}
    break;
   }
   
   return TRUE;
}  

MMPTR m_mmMalloc(DWORD request)
{
	MMPTR i;
	HANDLE hand;
	LPVOID loc;

	if(request < 0) {return MM_NULL;}

	for(i=1;i<MAXBLOCKS;i++)
	{
		if(info[i].OrgId == 0)
		{break;}
	}
	if(i>=MAXBLOCKS) {return MM_NULL;}

	hand = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,request,NULL);
	if(hand == NULL) {return MM_NULL;}

	loc = MapViewOfFile(hand,FILE_MAP_WRITE,0,0,0);
	if(loc == NULL) 
	{
		CloseHandle(hand);
		return MM_NULL;
	}

	info[i].OrgId = GetCurrentProcessId();
	info[i].hand = hand;
	info[i].count = 1;
	info[i].size = request;
	ptrs[i] = loc;

	return i;
}


#define WAIT_PERIOD  100  /* 1/10 second */

MMPTR mmMalloc(DWORD request)
{
	MMPTR retval;
	DWORD waitval;	
										
	waitval = WaitForSingleObject(mutex,WAIT_PERIOD);			
	if(waitval != WAIT_OBJECT_0) {return MM_NULL;}
	retval = m_mmMalloc(request);
	ReleaseMutex(mutex);
	return retval;
}


void mmFree(MMPTR ptrnum)
/*	Should really be called by the same process that calls mmMalloc, but whatever */
/*  Note that any other pointers to this data that are still out there will be invalid, 
	just as with the normal malloc */
{
	LPVOID temp;
	DWORD waitval;

	/* Null check */
	if(ptrnum == MM_NULL) {return;}

	/* Get pointer */
	temp = mmGetPtr(ptrnum);
	if(temp==NULL) {return;}

	/* Clean up data */
	SecureDelete(temp,info[ptrnum].size);
	UnmapViewOfFile(temp);

	/* Erase record */
	ptrs[ptrnum] = NULL;
	waitval = WaitForSingleObject(mutex,WAIT_PERIOD);
	if(waitval!=WAIT_OBJECT_0) {return;} /* No corruption, but the array is not properly cleared */
	info[ptrnum].OrgId = 0;
	if(GetCurrentProcessId() == info[ptrnum].OrgId) {CloseHandle(info[ptrnum].hand);}
	info[ptrnum].hand = NULL;
	info[ptrnum].count = 0;
	info[ptrnum].size = 0;
	ReleaseMutex(mutex);
} 

LPVOID mmGetPtr(MMPTR ptrnum)
{
	HANDLE dup;
	HANDLE orgprocess;
	LPVOID tempptr;

	/* Null check */
	if(ptrnum == MM_NULL) {return NULL;}

	/* If this has already been setup for this process, just return */
	if(ptrs[ptrnum]!=NULL) {return ptrs[ptrnum];}

	/* Otherwise, does the pointer exist? */
	if(info[ptrnum].OrgId == 0)
	{return NULL;}
	else	/* Yes, so copy it into our address space */
	{
		orgprocess = OpenProcess(PROCESS_DUP_HANDLE,FALSE,info[ptrnum].OrgId);

		DuplicateHandle(orgprocess,info[ptrnum].hand,GetCurrentProcess(),&dup,FILE_MAP_ALL_ACCESS,FALSE,0);
		tempptr = MapViewOfFile(dup,FILE_MAP_ALL_ACCESS,0,0,0);

		CloseHandle(dup);
		CloseHandle(orgprocess);

		if(tempptr == NULL)
		{return NULL;}
		else
		{
			ptrs[ptrnum] = tempptr;
			info[ptrnum].count++;
			return tempptr;
		}
	}

}

void mmReturnPtr(MMPTR ptrnum)
{
	/* Null check */
	if(ptrnum == MM_NULL) {return;}

	if(ptrs[ptrnum]!=NULL)
	{
		if(--info[ptrnum].count == 0)
		{mmFree(ptrnum);}	/* If this is the last reference, free block */
		else
		{
			UnmapViewOfFile(ptrs[ptrnum]);
			ptrs[ptrnum] = NULL;
		}
	}
}

/* Utility Functions */
void SecureDelete(BYTE* start, DWORD size)
/* Functions assumes that start is the value returned from MapViewOfFile */
/* Last value written should persist in RAM and should therefore erase the data there */
{
	DWORD i,j,offset;

	for(i=0;i<NUMITER;i++)
	{
		for(offset=0;offset<size-3;offset+=3)
		{
			memset(start+offset+0,ovr[i][0],1);
			memset(start+offset+1,ovr[i][1],1);
			memset(start+offset+2,ovr[i][2],1);
		}
		offset -= 3;
		for(j=0;j<size%3;j++)
		{
			memset(start+offset+j,ovr[i][j],1);
		}
		FlushViewOfFile(start,0); /* Force write to disk */
	}
}
