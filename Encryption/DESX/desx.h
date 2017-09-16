/* desx.h
 * Graven Imagery, 1994
 *
 * "DESX" is a trademark of RSA Data Security, Inc.
 *
 * THIS SOFTWARE PLACED IN THE PUBLIC DOMAIN BY THE AUTHOR.
 *
 * (c) 1994 by Richard Outerbridge (CI$ : [71755,204])
 */

struct DESXKey {
	unsigned char DESKey64[8];
	unsigned char Whitening64[8];
	};

struct DESContext {
	unsigned long dxkenc[32];
	unsigned long dxkdec[32];
	};

struct DESXContext {
	struct DESContext Context;
	unsigned long PreWhitening64[2];
	unsigned long PostWhitening64[2];
	};

extern void DESXKeySetup(
	struct DESXContext *output,
	struct DESXKey *input	);
	
extern void DESXEncryptBlock(
	struct DESXContext *using,
	unsigned char *OutData64,
	unsigned char *InData64	);
	
extern void DESXDecryptBlock(
	struct DESXContext *using,
	unsigned char *OutData64,
	unsigned char *InData64	);
	
/* desx.h V1.00 rwo 94/03/02 00:04:23 EST Graven Imagery
 ********************************************************************/


