/* smf.h */

	/*  
	Header file for secure malloc and free routines used by the Counterpane
	PRNG. Use this code to set up a memory-mapped file out of the system 
	paging file, allocate and free memory from it, and then return
	the memory to the system registry after having securely overwritten it.
	Details of the secure overwrite can be found in Gutmann 1996 (Usenix).
	Trying to explain it here will cause my head to begin to hurt.
	Ari Benbasat (pigsfly@unixg.ubc.ca)
	*/

#ifndef YARROW_SMF_H
#define YARROW_SMF_H

#define MMPTR	BYTE
#define MM_NULL	0


/* Declare HOOKSAPI as __declspec(dllexport) before
   including this file in the actual DLL */
#ifndef SMFAPI 
#define SMFAPI __declspec(dllimport)
#endif

/* Function forward declerations */
SMFAPI MMPTR mmMalloc(DWORD request);
SMFAPI void mmFree(MMPTR ptrnum);
SMFAPI LPVOID mmGetPtr(MMPTR ptrnum);
SMFAPI void mmReturnPtr(MMPTR ptrnum);

#endif