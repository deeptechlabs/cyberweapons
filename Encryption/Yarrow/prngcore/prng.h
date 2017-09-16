/*
	prng.h

	Main private header for the Counterpane PRNG. Use this to be able access the
	initialization and destruction routines from the DLL.
*/

#ifndef YARROW_PRNG_H
#define YARROW_PRNG_H

/* Declare YARROWAPI as __declspec(dllexport) before
   including this file in the actual DLL */
#ifndef YARROWAPI 
#define YARROWAPI __declspec(dllimport)
#endif

/* Private function forward declarations */
YARROWAPI int prngInitialize(void);
YARROWAPI int prngDestroy(void);
YARROWAPI int prngInputEntropy(BYTE *inbuf,UINT inbuflen,UINT poolnum);

#endif