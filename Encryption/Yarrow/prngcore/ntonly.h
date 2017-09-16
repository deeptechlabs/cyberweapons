/*
	ntonly.h

	Header file for NT specific routines for the core prng routines.
*/

#ifndef YARROW_NT_ONLY_H
#define YARROW_NT_ONLY_H

/* Forward declerations */
BOOL prng_set_NT_security(void);
DWORD prng_slow_poll(BYTE *buf,UINT bufsize);

#endif