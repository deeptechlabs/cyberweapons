/*
	95only.h

	Header file for Win95 specific routines for the core prng routines.
*/

#ifndef YARROW_95_ONLY_H
#define YARROW_95_ONLY_H

/* Link to the ToolHelp32 library */
#include <tlhelp32.h>
#pragma comment(lib,"th32") 

/* Forward declerations */
DWORD prng_slow_poll(BYTE *buf,UINT bufsize);

#endif