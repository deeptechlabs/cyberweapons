/*
	95only.c

	Source code for Win95 specific routines.
*/

#include "userdefines.h"

#ifdef WIN_95

#include <windows.h>
#include "95only.h"

/* TODO: Code needs to be refined to collect only the more useful (<--- very relative term) data */
DWORD prng_slow_poll(BYTE* buf,UINT bufsize)
/* Copy all the possible data from a ToolHelp32 snapshot and copy it to a buffer */
/* Will copy a maximum of SPLEN bytes into buf. Returns the number of bytes copied */
/* Portions of this code are copied from an example in the Microsoft Systems Journal
   and are thus: Copyright <1995>, Microsoft Systems Journal */
{
	BYTE* pos;
	BYTE* end;
	HANDLE hSnapshot,hSubSnapshot;
	PROCESSENTRY32 pe32;
	THREADENTRY32 te32;
	MODULEENTRY32 me32;
	HEAPLIST32 hl32;
	BOOL fOK;

	pos = buf;
	end = buf+bufsize;
	hSnapshot = NULL;
	hSubSnapshot = NULL;

	/* Get process data */
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (hSnapshot == NULL) {goto cleanup_slow_poll;}

    pe32.dwSize = sizeof(PROCESSENTRY32);
	fOK = Process32First(hSnapshot,&pe32);
    while(fOK==TRUE)
    {
		if(pos+pe32.dwSize-sizeof(DWORD) > end) {goto cleanup_slow_poll;}
		memcpy(pos,(BYTE*)&pe32 + sizeof(DWORD),pe32.dwSize-sizeof(DWORD));
		pos += pe32.dwSize-sizeof(DWORD);

		/* Get Heap info */
		hSubSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST,pe32.th32ProcessID);
	    if (hSubSnapshot == NULL) {goto cleanup_slow_poll;}

		hl32.dwSize = sizeof(HEAPLIST32);
		fOK = Heap32ListFirst(hSubSnapshot,&hl32);
		while(fOK==TRUE)
		{
			if(pos+hl32.dwSize-sizeof(DWORD) > end) {goto cleanup_slow_poll;}
			memcpy(pos,(BYTE*)&hl32 + sizeof(DWORD),hl32.dwSize-sizeof(DWORD));
			pos += hl32.dwSize-sizeof(DWORD);

		    hl32.dwSize = sizeof(HEAPLIST32);
			fOK = Heap32ListNext(hSubSnapshot,&hl32);
		}

		CloseHandle(hSubSnapshot);
		hSubSnapshot = NULL;
		/* End Get Heap info */

		/* Get Module Info */ /* This data is highly repetative */
		hSubSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pe32.th32ProcessID);
		if (hSubSnapshot == NULL) {goto cleanup_slow_poll;}

		me32.dwSize = sizeof(MODULEENTRY32);
		fOK = Module32First(hSubSnapshot,&me32);
		while(fOK==TRUE)
		{
			if(pos+me32.dwSize-sizeof(DWORD) > end) {goto cleanup_slow_poll;}
			memcpy(pos,(BYTE*)&me32 + sizeof(DWORD),me32.dwSize-sizeof(DWORD));
			pos += me32.dwSize-sizeof(DWORD);

			me32.dwSize = sizeof(MODULEENTRY32);
			fOK = Module32Next(hSubSnapshot,&me32);
		}
    
		CloseHandle(hSubSnapshot);
		hSubSnapshot = NULL;
		/* End Get Module Info */
		
		pe32.dwSize = sizeof(PROCESSENTRY32);
		fOK = Process32Next(hSnapshot,&pe32);
	}

    CloseHandle(hSnapshot); 
	hSnapshot = NULL;
	/* End Get Process Info */


	/* Get thread data */ /* May want to collect this data first */
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (hSnapshot == NULL) {goto cleanup_slow_poll;}

    te32.dwSize = sizeof(THREADENTRY32);
	fOK = Thread32First(hSnapshot,&te32);
    while(fOK==TRUE)
    {
		if(pos+te32.dwSize-sizeof(DWORD) > end) {goto cleanup_slow_poll;}
		memcpy(pos,(BYTE*)&te32 + sizeof(DWORD),te32.dwSize-sizeof(DWORD));
		pos += te32.dwSize-sizeof(DWORD);

	    te32.dwSize = sizeof(THREADENTRY32);
		fOK = Thread32Next(hSnapshot,&te32);
	}
    
    CloseHandle(hSnapshot);
	hSnapshot = NULL;
	/* End Get Thread Info */

cleanup_slow_poll:
	if(hSnapshot!=NULL) {CloseHandle(hSnapshot);}
	if(hSubSnapshot!=NULL) {CloseHandle(hSubSnapshot);}

	return pos-buf;
}



#endif