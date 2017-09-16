/*
 * The HAVAL hashing function
 *
 * Public domain implementation by Paulo S.L.M. Barreto <pbarreto@uninet.com.br>
 *
 * Version 1.1 (1997.04.07)
 *
 * =============================================================================
 *
 * Differences from version 1.0 (1997.04.03):
 *
 * - Replaced function F5 by an optimized version (saving a boolean operation).
 *   Thanks to Wei Dai <weidai@eskimo.com> for this improvement.
 *
 * =============================================================================
 *
 * Reference: Zheng, Y., Pieprzyk, J., Seberry, J.:
 * "HAVAL - a one-way hashing algorithm with variable length of output",
 * Advances in Cryptology (AusCrypt'92), LNCS 718 (1993), 83-104, Springer-Verlag.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "haval.h"

#define HAVAL_VERSION	1

/*#define F1(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X4) ^ (X2) & (X5) ^ (X3) & (X6) ^ (X0) & (X1) ^ (X0))*/
#define F1(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & ((X4) ^ (X0)) ^ (X2) & (X5) ^ (X3) & (X6) ^ (X0))

/*#define F2(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X2) & (X3) ^ (X2) & (X4) & (X5) ^ \
	(X1) & (X2) ^ (X1) & (X4) ^ (X2) & (X6) ^ (X3) & (X5) ^ \
	(X4) & (X5) ^ (X0) & (X2) ^ (X0))*/
#define F2(X6, X5, X4, X3, X2, X1, X0) \
	((X2) & ((X1) & (~(X3)) ^ (X4) & (X5) ^ (X6) ^ (X0)) ^ \
	(X4) & ((X1) ^ (X5)) ^ (X3) & (X5) ^ (X0))

/*#define F3(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X2) & (X3) ^ (X1) & (X4) ^ (X2) & (X5) ^ (X3) & (X6) ^ (X0) & (X3) ^ (X0))*/
#define F3(X6, X5, X4, X3, X2, X1, X0) \
	((X3) & ((X1) & (X2) ^ (X6) ^ (X0)) ^ (X1) & (X4) ^ (X2) & (X5) ^ (X0))

/*#define F4(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X2) & (X3) ^ (X2) & (X4) & (X5) ^ (X3) & (X4) & (X6) ^ \
	(X1) & (X4) ^ (X2) & (X6) ^ (X3) & (X4) ^ (X3) & (X5) ^ \
	(X3) & (X6) ^ (X4) & (X5) ^ (X4) & (X6) ^ (X0) & (X4) ^(X0))*/
#define F4(X6, X5, X4, X3, X2, X1, X0) \
	((X4) & ((~(X2)) & (X5) ^ ((X3) | (X6)) ^ (X1) ^ (X0)) ^ \
	(X3) & ((X1) & (X2) ^ (X5) ^ (X6)) ^ (X2) & (X6) ^ (X0))

/*#define F5(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & (X4) ^ (X2) & (X5) ^ (X3) & (X6) ^ \
	(X0) & (X1) & (X2) & (X3) ^ (X0) & (X5) ^ (X0))*/
#define F5(X6, X5, X4, X3, X2, X1, X0) \
	((X1) & ((X4) ^ (X0) & (X2) & (X3)) ^ ((X2) ^ (X0)) & (X5) ^ (X3) & (X6) ^ (X0))

#ifdef HARDWARE_ROTATIONS
#define ROTR(v, n) (_lrotr ((v), (n)))
#else  /* !HARDWARE_ROTATIONS */
#define ROTR(v, n) (rot_tmp = (v), rot_tmp >> (n) | rot_tmp << (32 - (n)))
#endif /* ?HARDWARE_ROTATIONS */


static void havalTransform3 (word32 E[8], const byte D[128], word32 T[8])
{
#ifndef HARDWARE_ROTATIONS
	register word32 rot_tmp;
#endif /* ?HARDWARE_ROTATIONS */

#ifdef LITTLE_ENDIAN
	word32 *W = (word32 *)D;
#else  /* !LITTLE_ENDIAN */
	word32 W[32]; int i;
	for (i = 0; i < 32; i++) {
		W[i] = ROTR (((word32 *)D)[i], 16);
		W[i] = ((W[i] & 0xFF00FF00UL) >> 8) | ((W[i] & 0x00FF00FFUL) << 8);
	}
#endif /* ?LITTLE_ENDIAN */

	/* PASS 1: */

	T[7] = ROTR (F1 (E[1], E[0], E[3], E[5], E[6], E[2], E[4]), 7) + ROTR (E[7], 11) + W[ 0];
	T[6] = ROTR (F1 (E[0], T[7], E[2], E[4], E[5], E[1], E[3]), 7) + ROTR (E[6], 11) + W[ 1];
	T[5] = ROTR (F1 (T[7], T[6], E[1], E[3], E[4], E[0], E[2]), 7) + ROTR (E[5], 11) + W[ 2];
	T[4] = ROTR (F1 (T[6], T[5], E[0], E[2], E[3], T[7], E[1]), 7) + ROTR (E[4], 11) + W[ 3];
	T[3] = ROTR (F1 (T[5], T[4], T[7], E[1], E[2], T[6], E[0]), 7) + ROTR (E[3], 11) + W[ 4];
	T[2] = ROTR (F1 (T[4], T[3], T[6], E[0], E[1], T[5], T[7]), 7) + ROTR (E[2], 11) + W[ 5];
	T[1] = ROTR (F1 (T[3], T[2], T[5], T[7], E[0], T[4], T[6]), 7) + ROTR (E[1], 11) + W[ 6];
	T[0] = ROTR (F1 (T[2], T[1], T[4], T[6], T[7], T[3], T[5]), 7) + ROTR (E[0], 11) + W[ 7];


	T[7] = ROTR (F1 (T[1], T[0], T[3], T[5], T[6], T[2], T[4]), 7) + ROTR (T[7], 11) + W[ 8];
	T[6] = ROTR (F1 (T[0], T[7], T[2], T[4], T[5], T[1], T[3]), 7) + ROTR (T[6], 11) + W[ 9];
	T[5] = ROTR (F1 (T[7], T[6], T[1], T[3], T[4], T[0], T[2]), 7) + ROTR (T[5], 11) + W[10];
	T[4] = ROTR (F1 (T[6], T[5], T[0], T[2], T[3], T[7], T[1]), 7) + ROTR (T[4], 11) + W[11];
	T[3] = ROTR (F1 (T[5], T[4], T[7], T[1], T[2], T[6], T[0]), 7) + ROTR (T[3], 11) + W[12];
	T[2] = ROTR (F1 (T[4], T[3], T[6], T[0], T[1], T[5], T[7]), 7) + ROTR (T[2], 11) + W[13];
	T[1] = ROTR (F1 (T[3], T[2], T[5], T[7], T[0], T[4], T[6]), 7) + ROTR (T[1], 11) + W[14];
	T[0] = ROTR (F1 (T[2], T[1], T[4], T[6], T[7], T[3], T[5]), 7) + ROTR (T[0], 11) + W[15];

	T[7] = ROTR (F1 (T[1], T[0], T[3], T[5], T[6], T[2], T[4]), 7) + ROTR (T[7], 11) + W[16];
	T[6] = ROTR (F1 (T[0], T[7], T[2], T[4], T[5], T[1], T[3]), 7) + ROTR (T[6], 11) + W[17];
	T[5] = ROTR (F1 (T[7], T[6], T[1], T[3], T[4], T[0], T[2]), 7) + ROTR (T[5], 11) + W[18];
	T[4] = ROTR (F1 (T[6], T[5], T[0], T[2], T[3], T[7], T[1]), 7) + ROTR (T[4], 11) + W[19];
	T[3] = ROTR (F1 (T[5], T[4], T[7], T[1], T[2], T[6], T[0]), 7) + ROTR (T[3], 11) + W[20];
	T[2] = ROTR (F1 (T[4], T[3], T[6], T[0], T[1], T[5], T[7]), 7) + ROTR (T[2], 11) + W[21];
	T[1] = ROTR (F1 (T[3], T[2], T[5], T[7], T[0], T[4], T[6]), 7) + ROTR (T[1], 11) + W[22];
	T[0] = ROTR (F1 (T[2], T[1], T[4], T[6], T[7], T[3], T[5]), 7) + ROTR (T[0], 11) + W[23];

	T[7] = ROTR (F1 (T[1], T[0], T[3], T[5], T[6], T[2], T[4]), 7) + ROTR (T[7], 11) + W[24];
	T[6] = ROTR (F1 (T[0], T[7], T[2], T[4], T[5], T[1], T[3]), 7) + ROTR (T[6], 11) + W[25];
	T[5] = ROTR (F1 (T[7], T[6], T[1], T[3], T[4], T[0], T[2]), 7) + ROTR (T[5], 11) + W[26];
	T[4] = ROTR (F1 (T[6], T[5], T[0], T[2], T[3], T[7], T[1]), 7) + ROTR (T[4], 11) + W[27];
	T[3] = ROTR (F1 (T[5], T[4], T[7], T[1], T[2], T[6], T[0]), 7) + ROTR (T[3], 11) + W[28];
	T[2] = ROTR (F1 (T[4], T[3], T[6], T[0], T[1], T[5], T[7]), 7) + ROTR (T[2], 11) + W[29];
	T[1] = ROTR (F1 (T[3], T[2], T[5], T[7], T[0], T[4], T[6]), 7) + ROTR (T[1], 11) + W[30];
	T[0] = ROTR (F1 (T[2], T[1], T[4], T[6], T[7], T[3], T[5]), 7) + ROTR (T[0], 11) + W[31];

	/* PASS 2: */

	T[7] = ROTR (F2 (T[4], T[2], T[1], T[0], T[5], T[3], T[6]), 7) + ROTR (T[7], 11) + W[ 5] + 0x452821E6UL;
	T[6] = ROTR (F2 (T[3], T[1], T[0], T[7], T[4], T[2], T[5]), 7) + ROTR (T[6], 11) + W[14] + 0x38D01377UL;
	T[5] = ROTR (F2 (T[2], T[0], T[7], T[6], T[3], T[1], T[4]), 7) + ROTR (T[5], 11) + W[26] + 0xBE5466CFUL;
	T[4] = ROTR (F2 (T[1], T[7], T[6], T[5], T[2], T[0], T[3]), 7) + ROTR (T[4], 11) + W[18] + 0x34E90C6CUL;
	T[3] = ROTR (F2 (T[0], T[6], T[5], T[4], T[1], T[7], T[2]), 7) + ROTR (T[3], 11) + W[11] + 0xC0AC29B7UL;
	T[2] = ROTR (F2 (T[7], T[5], T[4], T[3], T[0], T[6], T[1]), 7) + ROTR (T[2], 11) + W[28] + 0xC97C50DDUL;
	T[1] = ROTR (F2 (T[6], T[4], T[3], T[2], T[7], T[5], T[0]), 7) + ROTR (T[1], 11) + W[ 7] + 0x3F84D5B5UL;
	T[0] = ROTR (F2 (T[5], T[3], T[2], T[1], T[6], T[4], T[7]), 7) + ROTR (T[0], 11) + W[16] + 0xB5470917UL;

	T[7] = ROTR (F2 (T[4], T[2], T[1], T[0], T[5], T[3], T[6]), 7) + ROTR (T[7], 11) + W[ 0] + 0x9216D5D9UL;
	T[6] = ROTR (F2 (T[3], T[1], T[0], T[7], T[4], T[2], T[5]), 7) + ROTR (T[6], 11) + W[23] + 0x8979FB1BUL;
	T[5] = ROTR (F2 (T[2], T[0], T[7], T[6], T[3], T[1], T[4]), 7) + ROTR (T[5], 11) + W[20] + 0xD1310BA6UL;
	T[4] = ROTR (F2 (T[1], T[7], T[6], T[5], T[2], T[0], T[3]), 7) + ROTR (T[4], 11) + W[22] + 0x98DFB5ACUL;
	T[3] = ROTR (F2 (T[0], T[6], T[5], T[4], T[1], T[7], T[2]), 7) + ROTR (T[3], 11) + W[ 1] + 0x2FFD72DBUL;
	T[2] = ROTR (F2 (T[7], T[5], T[4], T[3], T[0], T[6], T[1]), 7) + ROTR (T[2], 11) + W[10] + 0xD01ADFB7UL;
	T[1] = ROTR (F2 (T[6], T[4], T[3], T[2], T[7], T[5], T[0]), 7) + ROTR (T[1], 11) + W[ 4] + 0xB8E1AFEDUL;
	T[0] = ROTR (F2 (T[5], T[3], T[2], T[1], T[6], T[4], T[7]), 7) + ROTR (T[0], 11) + W[ 8] + 0x6A267E96UL;

	T[7] = ROTR (F2 (T[4], T[2], T[1], T[0], T[5], T[3], T[6]), 7) + ROTR (T[7], 11) + W[30] + 0xBA7C9045UL;
	T[6] = ROTR (F2 (T[3], T[1], T[0], T[7], T[4], T[2], T[5]), 7) + ROTR (T[6], 11) + W[ 3] + 0xF12C7F99UL;
	T[5] = ROTR (F2 (T[2], T[0], T[7], T[6], T[3], T[1], T[4]), 7) + ROTR (T[5], 11) + W[21] + 0x24A19947UL;
	T[4] = ROTR (F2 (T[1], T[7], T[6], T[5], T[2], T[0], T[3]), 7) + ROTR (T[4], 11) + W[ 9] + 0xB3916CF7UL;
	T[3] = ROTR (F2 (T[0], T[6], T[5], T[4], T[1], T[7], T[2]), 7) + ROTR (T[3], 11) + W[17] + 0x0801F2E2UL;
	T[2] = ROTR (F2 (T[7], T[5], T[4], T[3], T[0], T[6], T[1]), 7) + ROTR (T[2], 11) + W[24] + 0x858EFC16UL;
	T[1] = ROTR (F2 (T[6], T[4], T[3], T[2], T[7], T[5], T[0]), 7) + ROTR (T[1], 11) + W[29] + 0x636920D8UL;
	T[0] = ROTR (F2 (T[5], T[3], T[2], T[1], T[6], T[4], T[7]), 7) + ROTR (T[0], 11) + W[ 6] + 0x71574E69UL;

	T[7] = ROTR (F2 (T[4], T[2], T[1], T[0], T[5], T[3], T[6]), 7) + ROTR (T[7], 11) + W[19] + 0xA458FEA3UL;
	T[6] = ROTR (F2 (T[3], T[1], T[0], T[7], T[4], T[2], T[5]), 7) + ROTR (T[6], 11) + W[12] + 0xF4933D7EUL;
	T[5] = ROTR (F2 (T[2], T[0], T[7], T[6], T[3], T[1], T[4]), 7) + ROTR (T[5], 11) + W[15] + 0x0D95748FUL;
	T[4] = ROTR (F2 (T[1], T[7], T[6], T[5], T[2], T[0], T[3]), 7) + ROTR (T[4], 11) + W[13] + 0x728EB658UL;
	T[3] = ROTR (F2 (T[0], T[6], T[5], T[4], T[1], T[7], T[2]), 7) + ROTR (T[3], 11) + W[ 2] + 0x718BCD58UL;
	T[2] = ROTR (F2 (T[7], T[5], T[4], T[3], T[0], T[6], T[1]), 7) + ROTR (T[2], 11) + W[25] + 0x82154AEEUL;
	T[1] = ROTR (F2 (T[6], T[4], T[3], T[2], T[7], T[5], T[0]), 7) + ROTR (T[1], 11) + W[31] + 0x7B54A41DUL;
	T[0] = ROTR (F2 (T[5], T[3], T[2], T[1], T[6], T[4], T[7]), 7) + ROTR (T[0], 11) + W[27] + 0xC25A59B5UL;

	/* PASS 3: */

	T[7] = ROTR (F3 (T[6], T[1], T[2], T[3], T[4], T[5], T[0]), 7) + ROTR (T[7], 11) + W[19] + 0x9C30D539UL;
	T[6] = ROTR (F3 (T[5], T[0], T[1], T[2], T[3], T[4], T[7]), 7) + ROTR (T[6], 11) + W[ 9] + 0x2AF26013UL;
	T[5] = ROTR (F3 (T[4], T[7], T[0], T[1], T[2], T[3], T[6]), 7) + ROTR (T[5], 11) + W[ 4] + 0xC5D1B023UL;
	T[4] = ROTR (F3 (T[3], T[6], T[7], T[0], T[1], T[2], T[5]), 7) + ROTR (T[4], 11) + W[20] + 0x286085F0UL;
	T[3] = ROTR (F3 (T[2], T[5], T[6], T[7], T[0], T[1], T[4]), 7) + ROTR (T[3], 11) + W[28] + 0xCA417918UL;
	T[2] = ROTR (F3 (T[1], T[4], T[5], T[6], T[7], T[0], T[3]), 7) + ROTR (T[2], 11) + W[17] + 0xB8DB38EFUL;
	T[1] = ROTR (F3 (T[0], T[3], T[4], T[5], T[6], T[7], T[2]), 7) + ROTR (T[1], 11) + W[ 8] + 0x8E79DCB0UL;
	T[0] = ROTR (F3 (T[7], T[2], T[3], T[4], T[5], T[6], T[1]), 7) + ROTR (T[0], 11) + W[22] + 0x603A180EUL;

	T[7] = ROTR (F3 (T[6], T[1], T[2], T[3], T[4], T[5], T[0]), 7) + ROTR (T[7], 11) + W[29] + 0x6C9E0E8BUL;
	T[6] = ROTR (F3 (T[5], T[0], T[1], T[2], T[3], T[4], T[7]), 7) + ROTR (T[6], 11) + W[14] + 0xB01E8A3EUL;
	T[5] = ROTR (F3 (T[4], T[7], T[0], T[1], T[2], T[3], T[6]), 7) + ROTR (T[5], 11) + W[25] + 0xD71577C1UL;
	T[4] = ROTR (F3 (T[3], T[6], T[7], T[0], T[1], T[2], T[5]), 7) + ROTR (T[4], 11) + W[12] + 0xBD314B27UL;
	T[3] = ROTR (F3 (T[2], T[5], T[6], T[7], T[0], T[1], T[4]), 7) + ROTR (T[3], 11) + W[24] + 0x78AF2FDAUL;
	T[2] = ROTR (F3 (T[1], T[4], T[5], T[6], T[7], T[0], T[3]), 7) + ROTR (T[2], 11) + W[30] + 0x55605C60UL;
	T[1] = ROTR (F3 (T[0], T[3], T[4], T[5], T[6], T[7], T[2]), 7) + ROTR (T[1], 11) + W[16] + 0xE65525F3UL;
	T[0] = ROTR (F3 (T[7], T[2], T[3], T[4], T[5], T[6], T[1]), 7) + ROTR (T[0], 11) + W[26] + 0xAA55AB94UL;

	T[7] = ROTR (F3 (T[6], T[1], T[2], T[3], T[4], T[5], T[0]), 7) + ROTR (T[7], 11) + W[31] + 0x57489862UL;
	T[6] = ROTR (F3 (T[5], T[0], T[1], T[2], T[3], T[4], T[7]), 7) + ROTR (T[6], 11) + W[15] + 0x63E81440UL;
	T[5] = ROTR (F3 (T[4], T[7], T[0], T[1], T[2], T[3], T[6]), 7) + ROTR (T[5], 11) + W[ 7] + 0x55CA396AUL;
	T[4] = ROTR (F3 (T[3], T[6], T[7], T[0], T[1], T[2], T[5]), 7) + ROTR (T[4], 11) + W[ 3] + 0x2AAB10B6UL;
	T[3] = ROTR (F3 (T[2], T[5], T[6], T[7], T[0], T[1], T[4]), 7) + ROTR (T[3], 11) + W[ 1] + 0xB4CC5C34UL;
	T[2] = ROTR (F3 (T[1], T[4], T[5], T[6], T[7], T[0], T[3]), 7) + ROTR (T[2], 11) + W[ 0] + 0x1141E8CEUL;
	T[1] = ROTR (F3 (T[0], T[3], T[4], T[5], T[6], T[7], T[2]), 7) + ROTR (T[1], 11) + W[18] + 0xA15486AFUL;
	T[0] = ROTR (F3 (T[7], T[2], T[3], T[4], T[5], T[6], T[1]), 7) + ROTR (T[0], 11) + W[27] + 0x7C72E993UL;

	E[7] += T[7] = ROTR (F3 (T[6], T[1], T[2], T[3], T[4], T[5], T[0]), 7) + ROTR (T[7], 11) + W[13] + 0xB3EE1411UL;
	E[6] += T[6] = ROTR (F3 (T[5], T[0], T[1], T[2], T[3], T[4], T[7]), 7) + ROTR (T[6], 11) + W[ 6] + 0x636FBC2AUL;
	E[5] += T[5] = ROTR (F3 (T[4], T[7], T[0], T[1], T[2], T[3], T[6]), 7) + ROTR (T[5], 11) + W[21] + 0x2BA9C55DUL;
	E[4] += T[4] = ROTR (F3 (T[3], T[6], T[7], T[0], T[1], T[2], T[5]), 7) + ROTR (T[4], 11) + W[10] + 0x741831F6UL;
	E[3] += T[3] = ROTR (F3 (T[2], T[5], T[6], T[7], T[0], T[1], T[4]), 7) + ROTR (T[3], 11) + W[23] + 0xCE5C3E16UL;
	E[2] += T[2] = ROTR (F3 (T[1], T[4], T[5], T[6], T[7], T[0], T[3]), 7) + ROTR (T[2], 11) + W[11] + 0x9B87931EUL;
	E[1] += T[1] = ROTR (F3 (T[0], T[3], T[4], T[5], T[6], T[7], T[2]), 7) + ROTR (T[1], 11) + W[ 5] + 0xAFD6BA33UL;
	E[0] += T[0] = ROTR (F3 (T[7], T[2], T[3], T[4], T[5], T[6], T[1]), 7) + ROTR (T[0], 11) + W[ 2] + 0x6C24CF5CUL;

#ifndef LITTLE_ENDIAN
	memset (W, 0, sizeof (W));
#endif /* ?LITTLE_ENDIAN */
} /* havalTransform3 */


static void havalTransform4 (word32 E[8], const byte D[128], word32 T[8])
{
#ifndef HARDWARE_ROTATIONS
	register word32 rot_tmp;
#endif /* ?HARDWARE_ROTATIONS */

#ifdef LITTLE_ENDIAN
	word32 *W = (word32 *)D;
#else  /* !LITTLE_ENDIAN */
	word32 W[32]; int i;
	for (i = 0; i < 32; i++) {
		W[i] = ROTR (((word32 *)D)[i], 16);
		W[i] = ((W[i] & 0xFF00FF00UL) >> 8) | ((W[i] & 0x00FF00FFUL) << 8);
	}
#endif /* ?LITTLE_ENDIAN */

	/* PASS 1: */

	T[7] = ROTR (F1 (E[2], E[6], E[1], E[4], E[5], E[3], E[0]), 7) + ROTR (E[7], 11) + W[ 0];
	T[6] = ROTR (F1 (E[1], E[5], E[0], E[3], E[4], E[2], T[7]), 7) + ROTR (E[6], 11) + W[ 1];
	T[5] = ROTR (F1 (E[0], E[4], T[7], E[2], E[3], E[1], T[6]), 7) + ROTR (E[5], 11) + W[ 2];
	T[4] = ROTR (F1 (T[7], E[3], T[6], E[1], E[2], E[0], T[5]), 7) + ROTR (E[4], 11) + W[ 3];
	T[3] = ROTR (F1 (T[6], E[2], T[5], E[0], E[1], T[7], T[4]), 7) + ROTR (E[3], 11) + W[ 4];
	T[2] = ROTR (F1 (T[5], E[1], T[4], T[7], E[0], T[6], T[3]), 7) + ROTR (E[2], 11) + W[ 5];
	T[1] = ROTR (F1 (T[4], E[0], T[3], T[6], T[7], T[5], T[2]), 7) + ROTR (E[1], 11) + W[ 6];
	T[0] = ROTR (F1 (T[3], T[7], T[2], T[5], T[6], T[4], T[1]), 7) + ROTR (E[0], 11) + W[ 7];

	T[7] = ROTR (F1 (T[2], T[6], T[1], T[4], T[5], T[3], T[0]), 7) + ROTR (T[7], 11) + W[ 8];
	T[6] = ROTR (F1 (T[1], T[5], T[0], T[3], T[4], T[2], T[7]), 7) + ROTR (T[6], 11) + W[ 9];
	T[5] = ROTR (F1 (T[0], T[4], T[7], T[2], T[3], T[1], T[6]), 7) + ROTR (T[5], 11) + W[10];
	T[4] = ROTR (F1 (T[7], T[3], T[6], T[1], T[2], T[0], T[5]), 7) + ROTR (T[4], 11) + W[11];
	T[3] = ROTR (F1 (T[6], T[2], T[5], T[0], T[1], T[7], T[4]), 7) + ROTR (T[3], 11) + W[12];
	T[2] = ROTR (F1 (T[5], T[1], T[4], T[7], T[0], T[6], T[3]), 7) + ROTR (T[2], 11) + W[13];
	T[1] = ROTR (F1 (T[4], T[0], T[3], T[6], T[7], T[5], T[2]), 7) + ROTR (T[1], 11) + W[14];
	T[0] = ROTR (F1 (T[3], T[7], T[2], T[5], T[6], T[4], T[1]), 7) + ROTR (T[0], 11) + W[15];

	T[7] = ROTR (F1 (T[2], T[6], T[1], T[4], T[5], T[3], T[0]), 7) + ROTR (T[7], 11) + W[16];
	T[6] = ROTR (F1 (T[1], T[5], T[0], T[3], T[4], T[2], T[7]), 7) + ROTR (T[6], 11) + W[17];
	T[5] = ROTR (F1 (T[0], T[4], T[7], T[2], T[3], T[1], T[6]), 7) + ROTR (T[5], 11) + W[18];
	T[4] = ROTR (F1 (T[7], T[3], T[6], T[1], T[2], T[0], T[5]), 7) + ROTR (T[4], 11) + W[19];
	T[3] = ROTR (F1 (T[6], T[2], T[5], T[0], T[1], T[7], T[4]), 7) + ROTR (T[3], 11) + W[20];
	T[2] = ROTR (F1 (T[5], T[1], T[4], T[7], T[0], T[6], T[3]), 7) + ROTR (T[2], 11) + W[21];
	T[1] = ROTR (F1 (T[4], T[0], T[3], T[6], T[7], T[5], T[2]), 7) + ROTR (T[1], 11) + W[22];
	T[0] = ROTR (F1 (T[3], T[7], T[2], T[5], T[6], T[4], T[1]), 7) + ROTR (T[0], 11) + W[23];

	T[7] = ROTR (F1 (T[2], T[6], T[1], T[4], T[5], T[3], T[0]), 7) + ROTR (T[7], 11) + W[24];
	T[6] = ROTR (F1 (T[1], T[5], T[0], T[3], T[4], T[2], T[7]), 7) + ROTR (T[6], 11) + W[25];
	T[5] = ROTR (F1 (T[0], T[4], T[7], T[2], T[3], T[1], T[6]), 7) + ROTR (T[5], 11) + W[26];
	T[4] = ROTR (F1 (T[7], T[3], T[6], T[1], T[2], T[0], T[5]), 7) + ROTR (T[4], 11) + W[27];
	T[3] = ROTR (F1 (T[6], T[2], T[5], T[0], T[1], T[7], T[4]), 7) + ROTR (T[3], 11) + W[28];
	T[2] = ROTR (F1 (T[5], T[1], T[4], T[7], T[0], T[6], T[3]), 7) + ROTR (T[2], 11) + W[29];
	T[1] = ROTR (F1 (T[4], T[0], T[3], T[6], T[7], T[5], T[2]), 7) + ROTR (T[1], 11) + W[30];
	T[0] = ROTR (F1 (T[3], T[7], T[2], T[5], T[6], T[4], T[1]), 7) + ROTR (T[0], 11) + W[31];

	/* PASS 2: */

	T[7] = ROTR (F2 (T[3], T[5], T[2], T[0], T[1], T[6], T[4]), 7) + ROTR (T[7], 11) + W[ 5] + 0x452821E6UL;
	T[6] = ROTR (F2 (T[2], T[4], T[1], T[7], T[0], T[5], T[3]), 7) + ROTR (T[6], 11) + W[14] + 0x38D01377UL;
	T[5] = ROTR (F2 (T[1], T[3], T[0], T[6], T[7], T[4], T[2]), 7) + ROTR (T[5], 11) + W[26] + 0xBE5466CFUL;
	T[4] = ROTR (F2 (T[0], T[2], T[7], T[5], T[6], T[3], T[1]), 7) + ROTR (T[4], 11) + W[18] + 0x34E90C6CUL;
	T[3] = ROTR (F2 (T[7], T[1], T[6], T[4], T[5], T[2], T[0]), 7) + ROTR (T[3], 11) + W[11] + 0xC0AC29B7UL;
	T[2] = ROTR (F2 (T[6], T[0], T[5], T[3], T[4], T[1], T[7]), 7) + ROTR (T[2], 11) + W[28] + 0xC97C50DDUL;
	T[1] = ROTR (F2 (T[5], T[7], T[4], T[2], T[3], T[0], T[6]), 7) + ROTR (T[1], 11) + W[ 7] + 0x3F84D5B5UL;
	T[0] = ROTR (F2 (T[4], T[6], T[3], T[1], T[2], T[7], T[5]), 7) + ROTR (T[0], 11) + W[16] + 0xB5470917UL;

	T[7] = ROTR (F2 (T[3], T[5], T[2], T[0], T[1], T[6], T[4]), 7) + ROTR (T[7], 11) + W[ 0] + 0x9216D5D9UL;
	T[6] = ROTR (F2 (T[2], T[4], T[1], T[7], T[0], T[5], T[3]), 7) + ROTR (T[6], 11) + W[23] + 0x8979FB1BUL;
	T[5] = ROTR (F2 (T[1], T[3], T[0], T[6], T[7], T[4], T[2]), 7) + ROTR (T[5], 11) + W[20] + 0xD1310BA6UL;
	T[4] = ROTR (F2 (T[0], T[2], T[7], T[5], T[6], T[3], T[1]), 7) + ROTR (T[4], 11) + W[22] + 0x98DFB5ACUL;
	T[3] = ROTR (F2 (T[7], T[1], T[6], T[4], T[5], T[2], T[0]), 7) + ROTR (T[3], 11) + W[ 1] + 0x2FFD72DBUL;
	T[2] = ROTR (F2 (T[6], T[0], T[5], T[3], T[4], T[1], T[7]), 7) + ROTR (T[2], 11) + W[10] + 0xD01ADFB7UL;
	T[1] = ROTR (F2 (T[5], T[7], T[4], T[2], T[3], T[0], T[6]), 7) + ROTR (T[1], 11) + W[ 4] + 0xB8E1AFEDUL;
	T[0] = ROTR (F2 (T[4], T[6], T[3], T[1], T[2], T[7], T[5]), 7) + ROTR (T[0], 11) + W[ 8] + 0x6A267E96UL;

	T[7] = ROTR (F2 (T[3], T[5], T[2], T[0], T[1], T[6], T[4]), 7) + ROTR (T[7], 11) + W[30] + 0xBA7C9045UL;
	T[6] = ROTR (F2 (T[2], T[4], T[1], T[7], T[0], T[5], T[3]), 7) + ROTR (T[6], 11) + W[ 3] + 0xF12C7F99UL;
	T[5] = ROTR (F2 (T[1], T[3], T[0], T[6], T[7], T[4], T[2]), 7) + ROTR (T[5], 11) + W[21] + 0x24A19947UL;
	T[4] = ROTR (F2 (T[0], T[2], T[7], T[5], T[6], T[3], T[1]), 7) + ROTR (T[4], 11) + W[ 9] + 0xB3916CF7UL;
	T[3] = ROTR (F2 (T[7], T[1], T[6], T[4], T[5], T[2], T[0]), 7) + ROTR (T[3], 11) + W[17] + 0x0801F2E2UL;
	T[2] = ROTR (F2 (T[6], T[0], T[5], T[3], T[4], T[1], T[7]), 7) + ROTR (T[2], 11) + W[24] + 0x858EFC16UL;
	T[1] = ROTR (F2 (T[5], T[7], T[4], T[2], T[3], T[0], T[6]), 7) + ROTR (T[1], 11) + W[29] + 0x636920D8UL;
	T[0] = ROTR (F2 (T[4], T[6], T[3], T[1], T[2], T[7], T[5]), 7) + ROTR (T[0], 11) + W[ 6] + 0x71574E69UL;

	T[7] = ROTR (F2 (T[3], T[5], T[2], T[0], T[1], T[6], T[4]), 7) + ROTR (T[7], 11) + W[19] + 0xA458FEA3UL;
	T[6] = ROTR (F2 (T[2], T[4], T[1], T[7], T[0], T[5], T[3]), 7) + ROTR (T[6], 11) + W[12] + 0xF4933D7EUL;
	T[5] = ROTR (F2 (T[1], T[3], T[0], T[6], T[7], T[4], T[2]), 7) + ROTR (T[5], 11) + W[15] + 0x0D95748FUL;
	T[4] = ROTR (F2 (T[0], T[2], T[7], T[5], T[6], T[3], T[1]), 7) + ROTR (T[4], 11) + W[13] + 0x728EB658UL;
	T[3] = ROTR (F2 (T[7], T[1], T[6], T[4], T[5], T[2], T[0]), 7) + ROTR (T[3], 11) + W[ 2] + 0x718BCD58UL;
	T[2] = ROTR (F2 (T[6], T[0], T[5], T[3], T[4], T[1], T[7]), 7) + ROTR (T[2], 11) + W[25] + 0x82154AEEUL;
	T[1] = ROTR (F2 (T[5], T[7], T[4], T[2], T[3], T[0], T[6]), 7) + ROTR (T[1], 11) + W[31] + 0x7B54A41DUL;
	T[0] = ROTR (F2 (T[4], T[6], T[3], T[1], T[2], T[7], T[5]), 7) + ROTR (T[0], 11) + W[27] + 0xC25A59B5UL;

	/* PASS 3: */

	T[7] = ROTR (F3 (T[1], T[4], T[3], T[6], T[0], T[2], T[5]), 7) + ROTR (T[7], 11) + W[19] + 0x9C30D539UL;
	T[6] = ROTR (F3 (T[0], T[3], T[2], T[5], T[7], T[1], T[4]), 7) + ROTR (T[6], 11) + W[ 9] + 0x2AF26013UL;
	T[5] = ROTR (F3 (T[7], T[2], T[1], T[4], T[6], T[0], T[3]), 7) + ROTR (T[5], 11) + W[ 4] + 0xC5D1B023UL;
	T[4] = ROTR (F3 (T[6], T[1], T[0], T[3], T[5], T[7], T[2]), 7) + ROTR (T[4], 11) + W[20] + 0x286085F0UL;
	T[3] = ROTR (F3 (T[5], T[0], T[7], T[2], T[4], T[6], T[1]), 7) + ROTR (T[3], 11) + W[28] + 0xCA417918UL;
	T[2] = ROTR (F3 (T[4], T[7], T[6], T[1], T[3], T[5], T[0]), 7) + ROTR (T[2], 11) + W[17] + 0xB8DB38EFUL;
	T[1] = ROTR (F3 (T[3], T[6], T[5], T[0], T[2], T[4], T[7]), 7) + ROTR (T[1], 11) + W[ 8] + 0x8E79DCB0UL;
	T[0] = ROTR (F3 (T[2], T[5], T[4], T[7], T[1], T[3], T[6]), 7) + ROTR (T[0], 11) + W[22] + 0x603A180EUL;

	T[7] = ROTR (F3 (T[1], T[4], T[3], T[6], T[0], T[2], T[5]), 7) + ROTR (T[7], 11) + W[29] + 0x6C9E0E8BUL;
	T[6] = ROTR (F3 (T[0], T[3], T[2], T[5], T[7], T[1], T[4]), 7) + ROTR (T[6], 11) + W[14] + 0xB01E8A3EUL;
	T[5] = ROTR (F3 (T[7], T[2], T[1], T[4], T[6], T[0], T[3]), 7) + ROTR (T[5], 11) + W[25] + 0xD71577C1UL;
	T[4] = ROTR (F3 (T[6], T[1], T[0], T[3], T[5], T[7], T[2]), 7) + ROTR (T[4], 11) + W[12] + 0xBD314B27UL;
	T[3] = ROTR (F3 (T[5], T[0], T[7], T[2], T[4], T[6], T[1]), 7) + ROTR (T[3], 11) + W[24] + 0x78AF2FDAUL;
	T[2] = ROTR (F3 (T[4], T[7], T[6], T[1], T[3], T[5], T[0]), 7) + ROTR (T[2], 11) + W[30] + 0x55605C60UL;
	T[1] = ROTR (F3 (T[3], T[6], T[5], T[0], T[2], T[4], T[7]), 7) + ROTR (T[1], 11) + W[16] + 0xE65525F3UL;
	T[0] = ROTR (F3 (T[2], T[5], T[4], T[7], T[1], T[3], T[6]), 7) + ROTR (T[0], 11) + W[26] + 0xAA55AB94UL;

	T[7] = ROTR (F3 (T[1], T[4], T[3], T[6], T[0], T[2], T[5]), 7) + ROTR (T[7], 11) + W[31] + 0x57489862UL;
	T[6] = ROTR (F3 (T[0], T[3], T[2], T[5], T[7], T[1], T[4]), 7) + ROTR (T[6], 11) + W[15] + 0x63E81440UL;
	T[5] = ROTR (F3 (T[7], T[2], T[1], T[4], T[6], T[0], T[3]), 7) + ROTR (T[5], 11) + W[ 7] + 0x55CA396AUL;
	T[4] = ROTR (F3 (T[6], T[1], T[0], T[3], T[5], T[7], T[2]), 7) + ROTR (T[4], 11) + W[ 3] + 0x2AAB10B6UL;
	T[3] = ROTR (F3 (T[5], T[0], T[7], T[2], T[4], T[6], T[1]), 7) + ROTR (T[3], 11) + W[ 1] + 0xB4CC5C34UL;
	T[2] = ROTR (F3 (T[4], T[7], T[6], T[1], T[3], T[5], T[0]), 7) + ROTR (T[2], 11) + W[ 0] + 0x1141E8CEUL;
	T[1] = ROTR (F3 (T[3], T[6], T[5], T[0], T[2], T[4], T[7]), 7) + ROTR (T[1], 11) + W[18] + 0xA15486AFUL;
	T[0] = ROTR (F3 (T[2], T[5], T[4], T[7], T[1], T[3], T[6]), 7) + ROTR (T[0], 11) + W[27] + 0x7C72E993UL;

	T[7] = ROTR (F3 (T[1], T[4], T[3], T[6], T[0], T[2], T[5]), 7) + ROTR (T[7], 11) + W[13] + 0xB3EE1411UL;
	T[6] = ROTR (F3 (T[0], T[3], T[2], T[5], T[7], T[1], T[4]), 7) + ROTR (T[6], 11) + W[ 6] + 0x636FBC2AUL;
	T[5] = ROTR (F3 (T[7], T[2], T[1], T[4], T[6], T[0], T[3]), 7) + ROTR (T[5], 11) + W[21] + 0x2BA9C55DUL;
	T[4] = ROTR (F3 (T[6], T[1], T[0], T[3], T[5], T[7], T[2]), 7) + ROTR (T[4], 11) + W[10] + 0x741831F6UL;
	T[3] = ROTR (F3 (T[5], T[0], T[7], T[2], T[4], T[6], T[1]), 7) + ROTR (T[3], 11) + W[23] + 0xCE5C3E16UL;
	T[2] = ROTR (F3 (T[4], T[7], T[6], T[1], T[3], T[5], T[0]), 7) + ROTR (T[2], 11) + W[11] + 0x9B87931EUL;
	T[1] = ROTR (F3 (T[3], T[6], T[5], T[0], T[2], T[4], T[7]), 7) + ROTR (T[1], 11) + W[ 5] + 0xAFD6BA33UL;
	T[0] = ROTR (F3 (T[2], T[5], T[4], T[7], T[1], T[3], T[6]), 7) + ROTR (T[0], 11) + W[ 2] + 0x6C24CF5CUL;

	/* PASS 4: */

	T[7] = ROTR (F4 (T[6], T[4], T[0], T[5], T[2], T[1], T[3]), 7) + ROTR (T[7], 11) + W[24] + 0x7A325381UL;
	T[6] = ROTR (F4 (T[5], T[3], T[7], T[4], T[1], T[0], T[2]), 7) + ROTR (T[6], 11) + W[ 4] + 0x28958677UL;
	T[5] = ROTR (F4 (T[4], T[2], T[6], T[3], T[0], T[7], T[1]), 7) + ROTR (T[5], 11) + W[ 0] + 0x3B8F4898UL;
	T[4] = ROTR (F4 (T[3], T[1], T[5], T[2], T[7], T[6], T[0]), 7) + ROTR (T[4], 11) + W[14] + 0x6B4BB9AFUL;
	T[3] = ROTR (F4 (T[2], T[0], T[4], T[1], T[6], T[5], T[7]), 7) + ROTR (T[3], 11) + W[ 2] + 0xC4BFE81BUL;
	T[2] = ROTR (F4 (T[1], T[7], T[3], T[0], T[5], T[4], T[6]), 7) + ROTR (T[2], 11) + W[ 7] + 0x66282193UL;
	T[1] = ROTR (F4 (T[0], T[6], T[2], T[7], T[4], T[3], T[5]), 7) + ROTR (T[1], 11) + W[28] + 0x61D809CCUL;
	T[0] = ROTR (F4 (T[7], T[5], T[1], T[6], T[3], T[2], T[4]), 7) + ROTR (T[0], 11) + W[23] + 0xFB21A991UL;

	T[7] = ROTR (F4 (T[6], T[4], T[0], T[5], T[2], T[1], T[3]), 7) + ROTR (T[7], 11) + W[26] + 0x487CAC60UL;
	T[6] = ROTR (F4 (T[5], T[3], T[7], T[4], T[1], T[0], T[2]), 7) + ROTR (T[6], 11) + W[ 6] + 0x5DEC8032UL;
	T[5] = ROTR (F4 (T[4], T[2], T[6], T[3], T[0], T[7], T[1]), 7) + ROTR (T[5], 11) + W[30] + 0xEF845D5DUL;
	T[4] = ROTR (F4 (T[3], T[1], T[5], T[2], T[7], T[6], T[0]), 7) + ROTR (T[4], 11) + W[20] + 0xE98575B1UL;
	T[3] = ROTR (F4 (T[2], T[0], T[4], T[1], T[6], T[5], T[7]), 7) + ROTR (T[3], 11) + W[18] + 0xDC262302UL;
	T[2] = ROTR (F4 (T[1], T[7], T[3], T[0], T[5], T[4], T[6]), 7) + ROTR (T[2], 11) + W[25] + 0xEB651B88UL;
	T[1] = ROTR (F4 (T[0], T[6], T[2], T[7], T[4], T[3], T[5]), 7) + ROTR (T[1], 11) + W[19] + 0x23893E81UL;
	T[0] = ROTR (F4 (T[7], T[5], T[1], T[6], T[3], T[2], T[4]), 7) + ROTR (T[0], 11) + W[ 3] + 0xD396ACC5UL;

	T[7] = ROTR (F4 (T[6], T[4], T[0], T[5], T[2], T[1], T[3]), 7) + ROTR (T[7], 11) + W[22] + 0x0F6D6FF3UL;
	T[6] = ROTR (F4 (T[5], T[3], T[7], T[4], T[1], T[0], T[2]), 7) + ROTR (T[6], 11) + W[11] + 0x83F44239UL;
	T[5] = ROTR (F4 (T[4], T[2], T[6], T[3], T[0], T[7], T[1]), 7) + ROTR (T[5], 11) + W[31] + 0x2E0B4482UL;
	T[4] = ROTR (F4 (T[3], T[1], T[5], T[2], T[7], T[6], T[0]), 7) + ROTR (T[4], 11) + W[21] + 0xA4842004UL;
	T[3] = ROTR (F4 (T[2], T[0], T[4], T[1], T[6], T[5], T[7]), 7) + ROTR (T[3], 11) + W[ 8] + 0x69C8F04AUL;
	T[2] = ROTR (F4 (T[1], T[7], T[3], T[0], T[5], T[4], T[6]), 7) + ROTR (T[2], 11) + W[27] + 0x9E1F9B5EUL;
	T[1] = ROTR (F4 (T[0], T[6], T[2], T[7], T[4], T[3], T[5]), 7) + ROTR (T[1], 11) + W[12] + 0x21C66842UL;
	T[0] = ROTR (F4 (T[7], T[5], T[1], T[6], T[3], T[2], T[4]), 7) + ROTR (T[0], 11) + W[ 9] + 0xF6E96C9AUL;

	E[7] += T[7] = ROTR (F4 (T[6], T[4], T[0], T[5], T[2], T[1], T[3]), 7) + ROTR (T[7], 11) + W[ 1] + 0x670C9C61UL;
	E[6] += T[6] = ROTR (F4 (T[5], T[3], T[7], T[4], T[1], T[0], T[2]), 7) + ROTR (T[6], 11) + W[29] + 0xABD388F0UL;
	E[5] += T[5] = ROTR (F4 (T[4], T[2], T[6], T[3], T[0], T[7], T[1]), 7) + ROTR (T[5], 11) + W[ 5] + 0x6A51A0D2UL;
	E[4] += T[4] = ROTR (F4 (T[3], T[1], T[5], T[2], T[7], T[6], T[0]), 7) + ROTR (T[4], 11) + W[15] + 0xD8542F68UL;
	E[3] += T[3] = ROTR (F4 (T[2], T[0], T[4], T[1], T[6], T[5], T[7]), 7) + ROTR (T[3], 11) + W[17] + 0x960FA728UL;
	E[2] += T[2] = ROTR (F4 (T[1], T[7], T[3], T[0], T[5], T[4], T[6]), 7) + ROTR (T[2], 11) + W[10] + 0xAB5133A3UL;
	E[1] += T[1] = ROTR (F4 (T[0], T[6], T[2], T[7], T[4], T[3], T[5]), 7) + ROTR (T[1], 11) + W[16] + 0x6EEF0B6CUL;
	E[0] += T[0] = ROTR (F4 (T[7], T[5], T[1], T[6], T[3], T[2], T[4]), 7) + ROTR (T[0], 11) + W[13] + 0x137A3BE4UL;

#ifndef LITTLE_ENDIAN
	memset (W, 0, sizeof (W));
#endif /* ?LITTLE_ENDIAN */
} /* havalTransform4 */


static void havalTransform5 (word32 E[8], const byte D[128], word32 T[8])
{
#ifndef HARDWARE_ROTATIONS
	register word32 rot_tmp;
#endif /* ?HARDWARE_ROTATIONS */

#ifdef LITTLE_ENDIAN
	word32 *W = (word32 *)D;
#else  /* !LITTLE_ENDIAN */
	word32 W[32]; int i;
	for (i = 0; i < 32; i++) {
		W[i] = ROTR (((word32 *)D)[i], 16);
		W[i] = ((W[i] & 0xFF00FF00UL) >> 8) | ((W[i] & 0x00FF00FFUL) << 8);
	}
#endif /* ?LITTLE_ENDIAN */

	/* PASS 1: */

	T[7] = ROTR (F1 (E[3], E[4], E[1], E[0], E[5], E[2], E[6]), 7) + ROTR (E[7], 11) + W[ 0];
	T[6] = ROTR (F1 (E[2], E[3], E[0], T[7], E[4], E[1], E[5]), 7) + ROTR (E[6], 11) + W[ 1];
	T[5] = ROTR (F1 (E[1], E[2], T[7], T[6], E[3], E[0], E[4]), 7) + ROTR (E[5], 11) + W[ 2];
	T[4] = ROTR (F1 (E[0], E[1], T[6], T[5], E[2], T[7], E[3]), 7) + ROTR (E[4], 11) + W[ 3];
	T[3] = ROTR (F1 (T[7], E[0], T[5], T[4], E[1], T[6], E[2]), 7) + ROTR (E[3], 11) + W[ 4];
	T[2] = ROTR (F1 (T[6], T[7], T[4], T[3], E[0], T[5], E[1]), 7) + ROTR (E[2], 11) + W[ 5];
	T[1] = ROTR (F1 (T[5], T[6], T[3], T[2], T[7], T[4], E[0]), 7) + ROTR (E[1], 11) + W[ 6];
	T[0] = ROTR (F1 (T[4], T[5], T[2], T[1], T[6], T[3], T[7]), 7) + ROTR (E[0], 11) + W[ 7];

	T[7] = ROTR (F1 (T[3], T[4], T[1], T[0], T[5], T[2], T[6]), 7) + ROTR (T[7], 11) + W[ 8];
	T[6] = ROTR (F1 (T[2], T[3], T[0], T[7], T[4], T[1], T[5]), 7) + ROTR (T[6], 11) + W[ 9];
	T[5] = ROTR (F1 (T[1], T[2], T[7], T[6], T[3], T[0], T[4]), 7) + ROTR (T[5], 11) + W[10];
	T[4] = ROTR (F1 (T[0], T[1], T[6], T[5], T[2], T[7], T[3]), 7) + ROTR (T[4], 11) + W[11];
	T[3] = ROTR (F1 (T[7], T[0], T[5], T[4], T[1], T[6], T[2]), 7) + ROTR (T[3], 11) + W[12];
	T[2] = ROTR (F1 (T[6], T[7], T[4], T[3], T[0], T[5], T[1]), 7) + ROTR (T[2], 11) + W[13];
	T[1] = ROTR (F1 (T[5], T[6], T[3], T[2], T[7], T[4], T[0]), 7) + ROTR (T[1], 11) + W[14];
	T[0] = ROTR (F1 (T[4], T[5], T[2], T[1], T[6], T[3], T[7]), 7) + ROTR (T[0], 11) + W[15];

	T[7] = ROTR (F1 (T[3], T[4], T[1], T[0], T[5], T[2], T[6]), 7) + ROTR (T[7], 11) + W[16];
	T[6] = ROTR (F1 (T[2], T[3], T[0], T[7], T[4], T[1], T[5]), 7) + ROTR (T[6], 11) + W[17];
	T[5] = ROTR (F1 (T[1], T[2], T[7], T[6], T[3], T[0], T[4]), 7) + ROTR (T[5], 11) + W[18];
	T[4] = ROTR (F1 (T[0], T[1], T[6], T[5], T[2], T[7], T[3]), 7) + ROTR (T[4], 11) + W[19];
	T[3] = ROTR (F1 (T[7], T[0], T[5], T[4], T[1], T[6], T[2]), 7) + ROTR (T[3], 11) + W[20];
	T[2] = ROTR (F1 (T[6], T[7], T[4], T[3], T[0], T[5], T[1]), 7) + ROTR (T[2], 11) + W[21];
	T[1] = ROTR (F1 (T[5], T[6], T[3], T[2], T[7], T[4], T[0]), 7) + ROTR (T[1], 11) + W[22];
	T[0] = ROTR (F1 (T[4], T[5], T[2], T[1], T[6], T[3], T[7]), 7) + ROTR (T[0], 11) + W[23];

	T[7] = ROTR (F1 (T[3], T[4], T[1], T[0], T[5], T[2], T[6]), 7) + ROTR (T[7], 11) + W[24];
	T[6] = ROTR (F1 (T[2], T[3], T[0], T[7], T[4], T[1], T[5]), 7) + ROTR (T[6], 11) + W[25];
	T[5] = ROTR (F1 (T[1], T[2], T[7], T[6], T[3], T[0], T[4]), 7) + ROTR (T[5], 11) + W[26];
	T[4] = ROTR (F1 (T[0], T[1], T[6], T[5], T[2], T[7], T[3]), 7) + ROTR (T[4], 11) + W[27];
	T[3] = ROTR (F1 (T[7], T[0], T[5], T[4], T[1], T[6], T[2]), 7) + ROTR (T[3], 11) + W[28];
	T[2] = ROTR (F1 (T[6], T[7], T[4], T[3], T[0], T[5], T[1]), 7) + ROTR (T[2], 11) + W[29];
	T[1] = ROTR (F1 (T[5], T[6], T[3], T[2], T[7], T[4], T[0]), 7) + ROTR (T[1], 11) + W[30];
	T[0] = ROTR (F1 (T[4], T[5], T[2], T[1], T[6], T[3], T[7]), 7) + ROTR (T[0], 11) + W[31];

	/* PASS 2: */

	T[7] = ROTR (F2 (T[6], T[2], T[1], T[0], T[3], T[4], T[5]), 7) + ROTR (T[7], 11) + W[ 5] + 0x452821E6UL;
	T[6] = ROTR (F2 (T[5], T[1], T[0], T[7], T[2], T[3], T[4]), 7) + ROTR (T[6], 11) + W[14] + 0x38D01377UL;
	T[5] = ROTR (F2 (T[4], T[0], T[7], T[6], T[1], T[2], T[3]), 7) + ROTR (T[5], 11) + W[26] + 0xBE5466CFUL;
	T[4] = ROTR (F2 (T[3], T[7], T[6], T[5], T[0], T[1], T[2]), 7) + ROTR (T[4], 11) + W[18] + 0x34E90C6CUL;
	T[3] = ROTR (F2 (T[2], T[6], T[5], T[4], T[7], T[0], T[1]), 7) + ROTR (T[3], 11) + W[11] + 0xC0AC29B7UL;
	T[2] = ROTR (F2 (T[1], T[5], T[4], T[3], T[6], T[7], T[0]), 7) + ROTR (T[2], 11) + W[28] + 0xC97C50DDUL;
	T[1] = ROTR (F2 (T[0], T[4], T[3], T[2], T[5], T[6], T[7]), 7) + ROTR (T[1], 11) + W[ 7] + 0x3F84D5B5UL;
	T[0] = ROTR (F2 (T[7], T[3], T[2], T[1], T[4], T[5], T[6]), 7) + ROTR (T[0], 11) + W[16] + 0xB5470917UL;

	T[7] = ROTR (F2 (T[6], T[2], T[1], T[0], T[3], T[4], T[5]), 7) + ROTR (T[7], 11) + W[ 0] + 0x9216D5D9UL;
	T[6] = ROTR (F2 (T[5], T[1], T[0], T[7], T[2], T[3], T[4]), 7) + ROTR (T[6], 11) + W[23] + 0x8979FB1BUL;
	T[5] = ROTR (F2 (T[4], T[0], T[7], T[6], T[1], T[2], T[3]), 7) + ROTR (T[5], 11) + W[20] + 0xD1310BA6UL;
	T[4] = ROTR (F2 (T[3], T[7], T[6], T[5], T[0], T[1], T[2]), 7) + ROTR (T[4], 11) + W[22] + 0x98DFB5ACUL;
	T[3] = ROTR (F2 (T[2], T[6], T[5], T[4], T[7], T[0], T[1]), 7) + ROTR (T[3], 11) + W[ 1] + 0x2FFD72DBUL;
	T[2] = ROTR (F2 (T[1], T[5], T[4], T[3], T[6], T[7], T[0]), 7) + ROTR (T[2], 11) + W[10] + 0xD01ADFB7UL;
	T[1] = ROTR (F2 (T[0], T[4], T[3], T[2], T[5], T[6], T[7]), 7) + ROTR (T[1], 11) + W[ 4] + 0xB8E1AFEDUL;
	T[0] = ROTR (F2 (T[7], T[3], T[2], T[1], T[4], T[5], T[6]), 7) + ROTR (T[0], 11) + W[ 8] + 0x6A267E96UL;

	T[7] = ROTR (F2 (T[6], T[2], T[1], T[0], T[3], T[4], T[5]), 7) + ROTR (T[7], 11) + W[30] + 0xBA7C9045UL;
	T[6] = ROTR (F2 (T[5], T[1], T[0], T[7], T[2], T[3], T[4]), 7) + ROTR (T[6], 11) + W[ 3] + 0xF12C7F99UL;
	T[5] = ROTR (F2 (T[4], T[0], T[7], T[6], T[1], T[2], T[3]), 7) + ROTR (T[5], 11) + W[21] + 0x24A19947UL;
	T[4] = ROTR (F2 (T[3], T[7], T[6], T[5], T[0], T[1], T[2]), 7) + ROTR (T[4], 11) + W[ 9] + 0xB3916CF7UL;
	T[3] = ROTR (F2 (T[2], T[6], T[5], T[4], T[7], T[0], T[1]), 7) + ROTR (T[3], 11) + W[17] + 0x0801F2E2UL;
	T[2] = ROTR (F2 (T[1], T[5], T[4], T[3], T[6], T[7], T[0]), 7) + ROTR (T[2], 11) + W[24] + 0x858EFC16UL;
	T[1] = ROTR (F2 (T[0], T[4], T[3], T[2], T[5], T[6], T[7]), 7) + ROTR (T[1], 11) + W[29] + 0x636920D8UL;
	T[0] = ROTR (F2 (T[7], T[3], T[2], T[1], T[4], T[5], T[6]), 7) + ROTR (T[0], 11) + W[ 6] + 0x71574E69UL;

	T[7] = ROTR (F2 (T[6], T[2], T[1], T[0], T[3], T[4], T[5]), 7) + ROTR (T[7], 11) + W[19] + 0xA458FEA3UL;
	T[6] = ROTR (F2 (T[5], T[1], T[0], T[7], T[2], T[3], T[4]), 7) + ROTR (T[6], 11) + W[12] + 0xF4933D7EUL;
	T[5] = ROTR (F2 (T[4], T[0], T[7], T[6], T[1], T[2], T[3]), 7) + ROTR (T[5], 11) + W[15] + 0x0D95748FUL;
	T[4] = ROTR (F2 (T[3], T[7], T[6], T[5], T[0], T[1], T[2]), 7) + ROTR (T[4], 11) + W[13] + 0x728EB658UL;
	T[3] = ROTR (F2 (T[2], T[6], T[5], T[4], T[7], T[0], T[1]), 7) + ROTR (T[3], 11) + W[ 2] + 0x718BCD58UL;
	T[2] = ROTR (F2 (T[1], T[5], T[4], T[3], T[6], T[7], T[0]), 7) + ROTR (T[2], 11) + W[25] + 0x82154AEEUL;
	T[1] = ROTR (F2 (T[0], T[4], T[3], T[2], T[5], T[6], T[7]), 7) + ROTR (T[1], 11) + W[31] + 0x7B54A41DUL;
	T[0] = ROTR (F2 (T[7], T[3], T[2], T[1], T[4], T[5], T[6]), 7) + ROTR (T[0], 11) + W[27] + 0xC25A59B5UL;

	/* PASS 3: */

	T[7] = ROTR (F3 (T[2], T[6], T[0], T[4], T[3], T[1], T[5]), 7) + ROTR (T[7], 11) + W[19] + 0x9C30D539UL;
	T[6] = ROTR (F3 (T[1], T[5], T[7], T[3], T[2], T[0], T[4]), 7) + ROTR (T[6], 11) + W[ 9] + 0x2AF26013UL;
	T[5] = ROTR (F3 (T[0], T[4], T[6], T[2], T[1], T[7], T[3]), 7) + ROTR (T[5], 11) + W[ 4] + 0xC5D1B023UL;
	T[4] = ROTR (F3 (T[7], T[3], T[5], T[1], T[0], T[6], T[2]), 7) + ROTR (T[4], 11) + W[20] + 0x286085F0UL;
	T[3] = ROTR (F3 (T[6], T[2], T[4], T[0], T[7], T[5], T[1]), 7) + ROTR (T[3], 11) + W[28] + 0xCA417918UL;
	T[2] = ROTR (F3 (T[5], T[1], T[3], T[7], T[6], T[4], T[0]), 7) + ROTR (T[2], 11) + W[17] + 0xB8DB38EFUL;
	T[1] = ROTR (F3 (T[4], T[0], T[2], T[6], T[5], T[3], T[7]), 7) + ROTR (T[1], 11) + W[ 8] + 0x8E79DCB0UL;
	T[0] = ROTR (F3 (T[3], T[7], T[1], T[5], T[4], T[2], T[6]), 7) + ROTR (T[0], 11) + W[22] + 0x603A180EUL;

	T[7] = ROTR (F3 (T[2], T[6], T[0], T[4], T[3], T[1], T[5]), 7) + ROTR (T[7], 11) + W[29] + 0x6C9E0E8BUL;
	T[6] = ROTR (F3 (T[1], T[5], T[7], T[3], T[2], T[0], T[4]), 7) + ROTR (T[6], 11) + W[14] + 0xB01E8A3EUL;
	T[5] = ROTR (F3 (T[0], T[4], T[6], T[2], T[1], T[7], T[3]), 7) + ROTR (T[5], 11) + W[25] + 0xD71577C1UL;
	T[4] = ROTR (F3 (T[7], T[3], T[5], T[1], T[0], T[6], T[2]), 7) + ROTR (T[4], 11) + W[12] + 0xBD314B27UL;
	T[3] = ROTR (F3 (T[6], T[2], T[4], T[0], T[7], T[5], T[1]), 7) + ROTR (T[3], 11) + W[24] + 0x78AF2FDAUL;
	T[2] = ROTR (F3 (T[5], T[1], T[3], T[7], T[6], T[4], T[0]), 7) + ROTR (T[2], 11) + W[30] + 0x55605C60UL;
	T[1] = ROTR (F3 (T[4], T[0], T[2], T[6], T[5], T[3], T[7]), 7) + ROTR (T[1], 11) + W[16] + 0xE65525F3UL;
	T[0] = ROTR (F3 (T[3], T[7], T[1], T[5], T[4], T[2], T[6]), 7) + ROTR (T[0], 11) + W[26] + 0xAA55AB94UL;

	T[7] = ROTR (F3 (T[2], T[6], T[0], T[4], T[3], T[1], T[5]), 7) + ROTR (T[7], 11) + W[31] + 0x57489862UL;
	T[6] = ROTR (F3 (T[1], T[5], T[7], T[3], T[2], T[0], T[4]), 7) + ROTR (T[6], 11) + W[15] + 0x63E81440UL;
	T[5] = ROTR (F3 (T[0], T[4], T[6], T[2], T[1], T[7], T[3]), 7) + ROTR (T[5], 11) + W[ 7] + 0x55CA396AUL;
	T[4] = ROTR (F3 (T[7], T[3], T[5], T[1], T[0], T[6], T[2]), 7) + ROTR (T[4], 11) + W[ 3] + 0x2AAB10B6UL;
	T[3] = ROTR (F3 (T[6], T[2], T[4], T[0], T[7], T[5], T[1]), 7) + ROTR (T[3], 11) + W[ 1] + 0xB4CC5C34UL;
	T[2] = ROTR (F3 (T[5], T[1], T[3], T[7], T[6], T[4], T[0]), 7) + ROTR (T[2], 11) + W[ 0] + 0x1141E8CEUL;
	T[1] = ROTR (F3 (T[4], T[0], T[2], T[6], T[5], T[3], T[7]), 7) + ROTR (T[1], 11) + W[18] + 0xA15486AFUL;
	T[0] = ROTR (F3 (T[3], T[7], T[1], T[5], T[4], T[2], T[6]), 7) + ROTR (T[0], 11) + W[27] + 0x7C72E993UL;

	T[7] = ROTR (F3 (T[2], T[6], T[0], T[4], T[3], T[1], T[5]), 7) + ROTR (T[7], 11) + W[13] + 0xB3EE1411UL;
	T[6] = ROTR (F3 (T[1], T[5], T[7], T[3], T[2], T[0], T[4]), 7) + ROTR (T[6], 11) + W[ 6] + 0x636FBC2AUL;
	T[5] = ROTR (F3 (T[0], T[4], T[6], T[2], T[1], T[7], T[3]), 7) + ROTR (T[5], 11) + W[21] + 0x2BA9C55DUL;
	T[4] = ROTR (F3 (T[7], T[3], T[5], T[1], T[0], T[6], T[2]), 7) + ROTR (T[4], 11) + W[10] + 0x741831F6UL;
	T[3] = ROTR (F3 (T[6], T[2], T[4], T[0], T[7], T[5], T[1]), 7) + ROTR (T[3], 11) + W[23] + 0xCE5C3E16UL;
	T[2] = ROTR (F3 (T[5], T[1], T[3], T[7], T[6], T[4], T[0]), 7) + ROTR (T[2], 11) + W[11] + 0x9B87931EUL;
	T[1] = ROTR (F3 (T[4], T[0], T[2], T[6], T[5], T[3], T[7]), 7) + ROTR (T[1], 11) + W[ 5] + 0xAFD6BA33UL;
	T[0] = ROTR (F3 (T[3], T[7], T[1], T[5], T[4], T[2], T[6]), 7) + ROTR (T[0], 11) + W[ 2] + 0x6C24CF5CUL;

	/* PASS 4: */

	T[7] = ROTR (F4 (T[1], T[5], T[3], T[2], T[0], T[4], T[6]), 7) + ROTR (T[7], 11) + W[24] + 0x7A325381UL;
	T[6] = ROTR (F4 (T[0], T[4], T[2], T[1], T[7], T[3], T[5]), 7) + ROTR (T[6], 11) + W[ 4] + 0x28958677UL;
	T[5] = ROTR (F4 (T[7], T[3], T[1], T[0], T[6], T[2], T[4]), 7) + ROTR (T[5], 11) + W[ 0] + 0x3B8F4898UL;
	T[4] = ROTR (F4 (T[6], T[2], T[0], T[7], T[5], T[1], T[3]), 7) + ROTR (T[4], 11) + W[14] + 0x6B4BB9AFUL;
	T[3] = ROTR (F4 (T[5], T[1], T[7], T[6], T[4], T[0], T[2]), 7) + ROTR (T[3], 11) + W[ 2] + 0xC4BFE81BUL;
	T[2] = ROTR (F4 (T[4], T[0], T[6], T[5], T[3], T[7], T[1]), 7) + ROTR (T[2], 11) + W[ 7] + 0x66282193UL;
	T[1] = ROTR (F4 (T[3], T[7], T[5], T[4], T[2], T[6], T[0]), 7) + ROTR (T[1], 11) + W[28] + 0x61D809CCUL;
	T[0] = ROTR (F4 (T[2], T[6], T[4], T[3], T[1], T[5], T[7]), 7) + ROTR (T[0], 11) + W[23] + 0xFB21A991UL;

	T[7] = ROTR (F4 (T[1], T[5], T[3], T[2], T[0], T[4], T[6]), 7) + ROTR (T[7], 11) + W[26] + 0x487CAC60UL;
	T[6] = ROTR (F4 (T[0], T[4], T[2], T[1], T[7], T[3], T[5]), 7) + ROTR (T[6], 11) + W[ 6] + 0x5DEC8032UL;
	T[5] = ROTR (F4 (T[7], T[3], T[1], T[0], T[6], T[2], T[4]), 7) + ROTR (T[5], 11) + W[30] + 0xEF845D5DUL;
	T[4] = ROTR (F4 (T[6], T[2], T[0], T[7], T[5], T[1], T[3]), 7) + ROTR (T[4], 11) + W[20] + 0xE98575B1UL;
	T[3] = ROTR (F4 (T[5], T[1], T[7], T[6], T[4], T[0], T[2]), 7) + ROTR (T[3], 11) + W[18] + 0xDC262302UL;
	T[2] = ROTR (F4 (T[4], T[0], T[6], T[5], T[3], T[7], T[1]), 7) + ROTR (T[2], 11) + W[25] + 0xEB651B88UL;
	T[1] = ROTR (F4 (T[3], T[7], T[5], T[4], T[2], T[6], T[0]), 7) + ROTR (T[1], 11) + W[19] + 0x23893E81UL;
	T[0] = ROTR (F4 (T[2], T[6], T[4], T[3], T[1], T[5], T[7]), 7) + ROTR (T[0], 11) + W[ 3] + 0xD396ACC5UL;

	T[7] = ROTR (F4 (T[1], T[5], T[3], T[2], T[0], T[4], T[6]), 7) + ROTR (T[7], 11) + W[22] + 0x0F6D6FF3UL;
	T[6] = ROTR (F4 (T[0], T[4], T[2], T[1], T[7], T[3], T[5]), 7) + ROTR (T[6], 11) + W[11] + 0x83F44239UL;
	T[5] = ROTR (F4 (T[7], T[3], T[1], T[0], T[6], T[2], T[4]), 7) + ROTR (T[5], 11) + W[31] + 0x2E0B4482UL;
	T[4] = ROTR (F4 (T[6], T[2], T[0], T[7], T[5], T[1], T[3]), 7) + ROTR (T[4], 11) + W[21] + 0xA4842004UL;
	T[3] = ROTR (F4 (T[5], T[1], T[7], T[6], T[4], T[0], T[2]), 7) + ROTR (T[3], 11) + W[ 8] + 0x69C8F04AUL;
	T[2] = ROTR (F4 (T[4], T[0], T[6], T[5], T[3], T[7], T[1]), 7) + ROTR (T[2], 11) + W[27] + 0x9E1F9B5EUL;
	T[1] = ROTR (F4 (T[3], T[7], T[5], T[4], T[2], T[6], T[0]), 7) + ROTR (T[1], 11) + W[12] + 0x21C66842UL;
	T[0] = ROTR (F4 (T[2], T[6], T[4], T[3], T[1], T[5], T[7]), 7) + ROTR (T[0], 11) + W[ 9] + 0xF6E96C9AUL;

	T[7] = ROTR (F4 (T[1], T[5], T[3], T[2], T[0], T[4], T[6]), 7) + ROTR (T[7], 11) + W[ 1] + 0x670C9C61UL;
	T[6] = ROTR (F4 (T[0], T[4], T[2], T[1], T[7], T[3], T[5]), 7) + ROTR (T[6], 11) + W[29] + 0xABD388F0UL;
	T[5] = ROTR (F4 (T[7], T[3], T[1], T[0], T[6], T[2], T[4]), 7) + ROTR (T[5], 11) + W[ 5] + 0x6A51A0D2UL;
	T[4] = ROTR (F4 (T[6], T[2], T[0], T[7], T[5], T[1], T[3]), 7) + ROTR (T[4], 11) + W[15] + 0xD8542F68UL;
	T[3] = ROTR (F4 (T[5], T[1], T[7], T[6], T[4], T[0], T[2]), 7) + ROTR (T[3], 11) + W[17] + 0x960FA728UL;
	T[2] = ROTR (F4 (T[4], T[0], T[6], T[5], T[3], T[7], T[1]), 7) + ROTR (T[2], 11) + W[10] + 0xAB5133A3UL;
	T[1] = ROTR (F4 (T[3], T[7], T[5], T[4], T[2], T[6], T[0]), 7) + ROTR (T[1], 11) + W[16] + 0x6EEF0B6CUL;
	T[0] = ROTR (F4 (T[2], T[6], T[4], T[3], T[1], T[5], T[7]), 7) + ROTR (T[0], 11) + W[13] + 0x137A3BE4UL;

	/* PASS 5: */

	T[7] = ROTR (F5 (T[2], T[5], T[0], T[6], T[4], T[3], T[1]), 7) + ROTR (T[7], 11) + W[27] + 0xBA3BF050UL;
	T[6] = ROTR (F5 (T[1], T[4], T[7], T[5], T[3], T[2], T[0]), 7) + ROTR (T[6], 11) + W[ 3] + 0x7EFB2A98UL;
	T[5] = ROTR (F5 (T[0], T[3], T[6], T[4], T[2], T[1], T[7]), 7) + ROTR (T[5], 11) + W[21] + 0xA1F1651DUL;
	T[4] = ROTR (F5 (T[7], T[2], T[5], T[3], T[1], T[0], T[6]), 7) + ROTR (T[4], 11) + W[26] + 0x39AF0176UL;
	T[3] = ROTR (F5 (T[6], T[1], T[4], T[2], T[0], T[7], T[5]), 7) + ROTR (T[3], 11) + W[17] + 0x66CA593EUL;
	T[2] = ROTR (F5 (T[5], T[0], T[3], T[1], T[7], T[6], T[4]), 7) + ROTR (T[2], 11) + W[11] + 0x82430E88UL;
	T[1] = ROTR (F5 (T[4], T[7], T[2], T[0], T[6], T[5], T[3]), 7) + ROTR (T[1], 11) + W[20] + 0x8CEE8619UL;
	T[0] = ROTR (F5 (T[3], T[6], T[1], T[7], T[5], T[4], T[2]), 7) + ROTR (T[0], 11) + W[29] + 0x456F9FB4UL;

	T[7] = ROTR (F5 (T[2], T[5], T[0], T[6], T[4], T[3], T[1]), 7) + ROTR (T[7], 11) + W[19] + 0x7D84A5C3UL;
	T[6] = ROTR (F5 (T[1], T[4], T[7], T[5], T[3], T[2], T[0]), 7) + ROTR (T[6], 11) + W[ 0] + 0x3B8B5EBEUL;
	T[5] = ROTR (F5 (T[0], T[3], T[6], T[4], T[2], T[1], T[7]), 7) + ROTR (T[5], 11) + W[12] + 0xE06F75D8UL;
	T[4] = ROTR (F5 (T[7], T[2], T[5], T[3], T[1], T[0], T[6]), 7) + ROTR (T[4], 11) + W[ 7] + 0x85C12073UL;
	T[3] = ROTR (F5 (T[6], T[1], T[4], T[2], T[0], T[7], T[5]), 7) + ROTR (T[3], 11) + W[13] + 0x401A449FUL;
	T[2] = ROTR (F5 (T[5], T[0], T[3], T[1], T[7], T[6], T[4]), 7) + ROTR (T[2], 11) + W[ 8] + 0x56C16AA6UL;
	T[1] = ROTR (F5 (T[4], T[7], T[2], T[0], T[6], T[5], T[3]), 7) + ROTR (T[1], 11) + W[31] + 0x4ED3AA62UL;
	T[0] = ROTR (F5 (T[3], T[6], T[1], T[7], T[5], T[4], T[2]), 7) + ROTR (T[0], 11) + W[10] + 0x363F7706UL;

	T[7] = ROTR (F5 (T[2], T[5], T[0], T[6], T[4], T[3], T[1]), 7) + ROTR (T[7], 11) + W[ 5] + 0x1BFEDF72UL;
	T[6] = ROTR (F5 (T[1], T[4], T[7], T[5], T[3], T[2], T[0]), 7) + ROTR (T[6], 11) + W[ 9] + 0x429B023DUL;
	T[5] = ROTR (F5 (T[0], T[3], T[6], T[4], T[2], T[1], T[7]), 7) + ROTR (T[5], 11) + W[14] + 0x37D0D724UL;
	T[4] = ROTR (F5 (T[7], T[2], T[5], T[3], T[1], T[0], T[6]), 7) + ROTR (T[4], 11) + W[30] + 0xD00A1248UL;
	T[3] = ROTR (F5 (T[6], T[1], T[4], T[2], T[0], T[7], T[5]), 7) + ROTR (T[3], 11) + W[18] + 0xDB0FEAD3UL;
	T[2] = ROTR (F5 (T[5], T[0], T[3], T[1], T[7], T[6], T[4]), 7) + ROTR (T[2], 11) + W[ 6] + 0x49F1C09BUL;
	T[1] = ROTR (F5 (T[4], T[7], T[2], T[0], T[6], T[5], T[3]), 7) + ROTR (T[1], 11) + W[28] + 0x075372C9UL;
	T[0] = ROTR (F5 (T[3], T[6], T[1], T[7], T[5], T[4], T[2]), 7) + ROTR (T[0], 11) + W[24] + 0x80991B7BUL;

	E[7] += T[7] = ROTR (F5 (T[2], T[5], T[0], T[6], T[4], T[3], T[1]), 7) + ROTR (T[7], 11) + W[ 2] + 0x25D479D8UL;
	E[6] += T[6] = ROTR (F5 (T[1], T[4], T[7], T[5], T[3], T[2], T[0]), 7) + ROTR (T[6], 11) + W[23] + 0xF6E8DEF7UL;
	E[5] += T[5] = ROTR (F5 (T[0], T[3], T[6], T[4], T[2], T[1], T[7]), 7) + ROTR (T[5], 11) + W[16] + 0xE3FE501AUL;
	E[4] += T[4] = ROTR (F5 (T[7], T[2], T[5], T[3], T[1], T[0], T[6]), 7) + ROTR (T[4], 11) + W[22] + 0xB6794C3BUL;
	E[3] += T[3] = ROTR (F5 (T[6], T[1], T[4], T[2], T[0], T[7], T[5]), 7) + ROTR (T[3], 11) + W[ 4] + 0x976CE0BDUL;
	E[2] += T[2] = ROTR (F5 (T[5], T[0], T[3], T[1], T[7], T[6], T[4]), 7) + ROTR (T[2], 11) + W[ 1] + 0x04C006BAUL;
	E[1] += T[1] = ROTR (F5 (T[4], T[7], T[2], T[0], T[6], T[5], T[3]), 7) + ROTR (T[1], 11) + W[25] + 0xC1A94FB6UL;
	E[0] += T[0] = ROTR (F5 (T[3], T[6], T[1], T[7], T[5], T[4], T[2]), 7) + ROTR (T[0], 11) + W[15] + 0x409F60C4UL;

#ifndef LITTLE_ENDIAN
	memset (W, 0, sizeof (W));
#endif /* ?LITTLE_ENDIAN */
} /* havalTransform5 */


int havalInit (havalContext *hcp, int passes, int hashLength)
{
	if (hcp == NULL) {
		return 1; /* bad context */
	}
	/* check number of passes: */
	if (passes != 3 && passes != 4 && passes != 5) {
		return 2; /* invalid number of passes */
	}
	/* check hash length: */
	if (hashLength != 128 &&
		hashLength != 160 &&
		hashLength != 192 &&
		hashLength != 224 &&
		hashLength != 256) {
		return 3; /* invalid hash length */
	}
	/* properly initialize HAVAL context: */
	memset (hcp, 0, sizeof (havalContext));
	hcp->passes = passes;
	hcp->hashLength = hashLength;
    hcp->digest[0] = 0x243F6A88UL;
    hcp->digest[1] = 0x85A308D3UL;
    hcp->digest[2] = 0x13198A2EUL;
    hcp->digest[3] = 0x03707344UL;
    hcp->digest[4] = 0xA4093822UL;
    hcp->digest[5] = 0x299F31D0UL;
    hcp->digest[6] = 0x082EFA98UL;
    hcp->digest[7] = 0xEC4E6C89UL;
	return 0; /* OK */
} /* havalInit */


int havalUpdate (havalContext *hcp, const byte *dataBuffer, size_t dataLength)
{
	if (hcp == NULL) {
		return 1; /* bad context */
	}
	if (dataBuffer == NULL || dataLength == 0) {
		return 0; /* nothing to do */
	}

	assert (hcp->occupied < 128); /* invariant */

	/* update bit count: */
	if ((word32)dataLength << 3 > 0xFFFFFFFFUL - hcp->bitCount[0]) {
		hcp->bitCount[1]++;
	}
	hcp->bitCount[0] += (word32)dataLength << 3;
	
	/* if the data buffer is not enough to complete */
	/* the context data block, just append it: */
	if (hcp->occupied + (word32)dataLength < 128) { /* caveat: typecast avoids 16-bit overflow */
		memcpy (&hcp->block[hcp->occupied], dataBuffer, dataLength);
		hcp->occupied += dataLength;
		assert (hcp->occupied < 128);
		return 0; /* delay processing */
	}

	/* complete the context data block: */
	memcpy (&hcp->block[hcp->occupied], dataBuffer, 128 - hcp->occupied);
	dataBuffer += 128 - hcp->occupied;
	dataLength -= 128 - hcp->occupied;

	switch (hcp->passes) {
	case 3:
		/* process the completed context data block: */
		havalTransform3 (hcp->digest, hcp->block, hcp->temp);
		/* process data in chunks of 128 bytes: */
		while (dataLength >= 128) {
			havalTransform3 (hcp->digest, dataBuffer, hcp->temp);
			dataBuffer += 128;
			dataLength -= 128;
		}
		break;
	case 4:
		/* process the completed context data block: */
		havalTransform4 (hcp->digest, hcp->block, hcp->temp);
		/* process data in chunks of 128 bytes: */
		while (dataLength >= 128) {
			havalTransform4 (hcp->digest, dataBuffer, hcp->temp);
			dataBuffer += 128;
			dataLength -= 128;
		}
		break;
	case 5:
		/* process the completed context data block: */
		havalTransform5 (hcp->digest, hcp->block, hcp->temp);
		/* process data in chunks of 128 bytes: */
		while (dataLength >= 128) {
			havalTransform5 (hcp->digest, dataBuffer, hcp->temp);
			dataBuffer += 128;
			dataLength -= 128;
		}
		break;
	}

	/* delay processing of remaining data: */
	memcpy (hcp->block, dataBuffer, dataLength);
	hcp->occupied = dataLength; /* < 128 */
	
	assert (hcp->occupied < 128);
	return 0; /* OK */
} /* havalUpdate */


int havalFinal (havalContext *hcp, byte *digest)
{
#ifndef HARDWARE_ROTATIONS
	register word32 rot_tmp;
#endif /* ?HARDWARE_ROTATIONS */
	word32 w;

	if (hcp == NULL) {
		return 1; /* bad context */
	}
	if (digest == NULL) {
		return 2; /* bad digest buffer */
	}

	assert (hcp->occupied < 128); /* invariant */

	/* append toggle to the context data block: */
	hcp->block[hcp->occupied] = 0x01; /* corrected from 0x80 */

	/* pad the message with null bytes to make it 944 (mod 1024) bits long: */
	if (hcp->occupied++ >= 118) {
		/* no room for tail data on the current context block */
		memset (&hcp->block[hcp->occupied], 0, 128 - hcp->occupied);
		/* process the completed context data block: */
		switch (hcp->passes) {
		case 3:
			havalTransform3 (hcp->digest, hcp->block, hcp->temp);
			break;
		case 4:
			havalTransform4 (hcp->digest, hcp->block, hcp->temp);
			break;
		case 5:
			havalTransform5 (hcp->digest, hcp->block, hcp->temp);
			break;
		}
		memset (hcp->block, 0, 118);
	} else {
		memset (&hcp->block[hcp->occupied], 0, 118 - hcp->occupied);
	}
	/* append tail data and process last (padded) message block: */
	hcp->block[118] =
		((hcp->hashLength & 0x03U) << 6) |
		((hcp->passes     & 0x07U) << 3) |
		(HAVAL_VERSION           & 0x07U);
	hcp->block[119] = hcp->hashLength >> 2;
	w = hcp->bitCount[0];
	hcp->block[120] = (byte)(w);
	hcp->block[121] = (byte)(w >>  8);
	hcp->block[122] = (byte)(w >> 16);
	hcp->block[123] = (byte)(w >> 24);
	w = hcp->bitCount[1];
	hcp->block[124] = (byte)(w);
	hcp->block[125] = (byte)(w >>  8);
	hcp->block[126] = (byte)(w >> 16);
	hcp->block[127] = (byte)(w >> 24);
	switch (hcp->passes) {
	case 3:
		havalTransform3 (hcp->digest, hcp->block, hcp->temp);
		break;
	case 4:
		havalTransform4 (hcp->digest, hcp->block, hcp->temp);
		break;
	case 5:
		havalTransform5 (hcp->digest, hcp->block, hcp->temp);
		break;
	}

	/* fold 256-bit digest to fit the desired hash length (blaargh!): */
	switch (hcp->hashLength) {
	case 128:
		hcp->digest[3] +=
			( (hcp->digest[7] & 0xFF000000UL)
			| (hcp->digest[6] & 0x00FF0000UL)
			| (hcp->digest[5] & 0x0000FF00UL)
			| (hcp->digest[4] & 0x000000FFUL)
			);
		hcp->digest[2] +=
			(((hcp->digest[7] & 0x00FF0000UL)
			| (hcp->digest[6] & 0x0000FF00UL)
			| (hcp->digest[5] & 0x000000FFUL)
			) << 8) |
			( (hcp->digest[4] & 0xFF000000UL) >> 24);
		hcp->digest[1] +=
			(((hcp->digest[7] & 0x0000FF00UL)
			| (hcp->digest[6] & 0x000000FFUL)) << 16) |
			(((hcp->digest[5] & 0xFF000000UL)
			| (hcp->digest[4] & 0x00FF0000UL)) >> 16);
		hcp->digest[0] +=
			(((hcp->digest[6] & 0xFF000000UL)
			| (hcp->digest[5] & 0x00FF0000UL)
			| (hcp->digest[4] & 0x0000FF00UL)
			) >> 8) |
			( (hcp->digest[7] & 0x000000FFUL) << 24);
		memcpy (digest, hcp->digest, 128/8);
		break;
	case 160:
		hcp->digest[4] +=
			((hcp->digest[7] & 0xFE000000UL) | (hcp->digest[6] & 0x01F80000UL) | (hcp->digest[5] & 0x0007F000UL)) >> 12;
		hcp->digest[3] +=
			((hcp->digest[7] & 0x01F80000UL) | (hcp->digest[6] & 0x0007F000UL) | (hcp->digest[5] & 0x00000FC0UL)) >> 6;
		hcp->digest[2] +=
			((hcp->digest[7] & 0x0007F000UL) | (hcp->digest[6] & 0x00000FC0UL) | (hcp->digest[5] & 0x0000003FUL));
		hcp->digest[1] +=
			ROTR
			((hcp->digest[7] & 0x00000FC0UL) | (hcp->digest[6] & 0x0000003FUL) | (hcp->digest[5] & 0xFE000000UL), 25);
		hcp->digest[0] +=
			ROTR
			((hcp->digest[7] & 0x0000003FUL) | (hcp->digest[6] & 0xFE000000UL) | (hcp->digest[5] & 0x01F80000UL), 19);
		memcpy (digest, hcp->digest, 160/8);
		break;
	case 192:
		hcp->digest[5] +=
			((hcp->digest[7] & 0xFC000000UL) | (hcp->digest[6] & 0x03E00000UL)) >> 21;
		hcp->digest[4] +=
			((hcp->digest[7] & 0x03E00000UL) | (hcp->digest[6] & 0x001F0000UL)) >> 16;
		hcp->digest[3] +=
			((hcp->digest[7] & 0x001F0000UL) | (hcp->digest[6] & 0x0000FC00UL)) >> 10;
		hcp->digest[2] +=
			((hcp->digest[7] & 0x0000FC00UL) | (hcp->digest[6] & 0x000003E0UL)) >>  5;
		hcp->digest[1] +=
			((hcp->digest[7] & 0x000003E0UL) | (hcp->digest[6] & 0x0000001FUL));
		hcp->digest[0] +=
			ROTR
			((hcp->digest[7] & 0x0000001FUL) | (hcp->digest[6] & 0xFC000000UL), 26);
		memcpy (digest, hcp->digest, 192/8);
		break;
	case 224:
		hcp->digest[6] += (hcp->digest[7]      ) & 0x0000000FUL;
		hcp->digest[5] += (hcp->digest[7] >>  4) & 0x0000001FUL;
		hcp->digest[4] += (hcp->digest[7] >>  9) & 0x0000000FUL;
		hcp->digest[3] += (hcp->digest[7] >> 13) & 0x0000001FUL;
		hcp->digest[2] += (hcp->digest[7] >> 18) & 0x0000000FUL;
		hcp->digest[1] += (hcp->digest[7] >> 22) & 0x0000001FUL;
		hcp->digest[0] += (hcp->digest[7] >> 27) & 0x0000001FUL;
		memcpy (digest, hcp->digest, 224/8);
		break;
	case 256:
		memcpy (digest, hcp->digest, 256/8);
		break;
	}

	/* destroy sensitive information: */
	memset (hcp, 0, sizeof (havalContext));
	return 0; /* OK */
} /* havalFinal */


#ifdef SELF_TESTING

#include <stdio.h>


static void printDigest (const char *tag, const byte *digest, size_t length)
{
	size_t i;

	length >>= 3; /* convert bit length to byte length */
	printf ("%s = ", tag);
	for (i = 0; i < length; i++) {
		printf ("%02X", digest [i]);
	}
	printf ("\n");
} /* printDigest */


int main (int argc, char *argv[])
{
	havalContext hc;
	byte digest [32];

	printf ("HAVAL test -- compiled on " __DATE__ " " __TIME__".\n\n");

	switch (argc == 2 ? atoi (argv[1]) : 0) {
	case 3:
		havalInit   (&hc, 3, 128);
		havalUpdate (&hc, "", 0);
		havalFinal  (&hc, digest);
		printf      ("HAVAL(3,128,\"\")\n");
		printDigest ("evaluated", digest, 128);
		printf      ("expected  = C68F39913F901F3DDF44C707357A7D70\n\n");

		havalInit   (&hc, 3, 160);
		havalUpdate (&hc, "a", 1);
		havalFinal  (&hc, digest);
		printf      ("HAVAL(3,160,\"a\")\n");
		printDigest ("evaluated", digest, 160);
		printf      ("expected  = 4DA08F514A7275DBC4CECE4A347385983983A830\n\n");

		havalInit   (&hc, 3, 192);
		havalUpdate (&hc, "HAVAL", strlen ("HAVAL"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(3,192,\"HAVAL\")\n");
		printDigest ("evaluated", digest, 192);
		printf      ("expected  = 8DA26DDAB4317B392B22B638998FE65B0FBE4610D345CF89\n\n");

		havalInit   (&hc, 3, 224);
		havalUpdate (&hc, "0123456789", strlen ("0123456789"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(3,224,\"0123456789\")\n");
		printDigest ("evaluated", digest, 224);
		printf      ("expected  = EE345C97A58190BF0F38BF7CE890231AA5FCF9862BF8E7BEBBF76789\n\n");

		havalInit   (&hc, 3, 256);
		havalUpdate (&hc, "abcdefghijklmnopqrstuvwxyz", strlen ("abcdefghijklmnopqrstuvwxyz"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(3,256,\"abcdefghijklmnopqrstuvwxyz\")\n");
		printDigest ("evaluated", digest, 256);
		printf      ("expected  = 72FAD4BDE1DA8C8332FB60561A780E7F504F21547B98686824FC33FC796AFA76\n\n");

		havalInit   (&hc, 3, 256);
		havalUpdate (&hc, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", strlen ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(3,256,\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\")\n");
		printDigest ("evaluated", digest, 256);
		printf      ("expected  = 899397D96489281E9E76D5E65ABAB751F312E06C06C07C9C1D42ABD31BB6A404\n\n");
		break;

	case 4:
		havalInit   (&hc, 4, 128);
		havalUpdate (&hc, "", 0);
		havalFinal  (&hc, digest);
		printf      ("HAVAL(4,128,\"\")\n");
		printDigest ("evaluated", digest, 128);
		printf      ("expected  = EE6BBF4D6A46A679B3A856C88538BB98\n\n");

		havalInit   (&hc, 4, 160);
		havalUpdate (&hc, "a", 1);
		havalFinal  (&hc, digest);
		printf      ("HAVAL(4,160,\"a\")\n");
		printDigest ("evaluated", digest, 160);
		printf      ("expected  = E0A5BE29627332034D4DD8A910A1A0E6FE04084D\n\n");

		havalInit   (&hc, 4, 192);
		havalUpdate (&hc, "HAVAL", strlen ("HAVAL"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(4,192,\"HAVAL\")\n");
		printDigest ("evaluated", digest, 192);
		printf      ("expected  = 0C1396D7772689C46773F3DAACA4EFA982ADBFB2F1467EEA\n\n");

		havalInit   (&hc, 4, 224);
		havalUpdate (&hc, "0123456789", strlen ("0123456789"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(4,224,\"0123456789\")\n");
		printDigest ("evaluated", digest, 224);
		printf      ("expected  = BEBD7816F09BAEECF8903B1B9BC672D9FA428E462BA699F814841529\n\n");

		havalInit   (&hc, 4, 256);
		havalUpdate (&hc, "abcdefghijklmnopqrstuvwxyz", strlen ("abcdefghijklmnopqrstuvwxyz"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(4,256,\"abcdefghijklmnopqrstuvwxyz\")\n");
		printDigest ("evaluated", digest, 256);
		printf      ("expected  = 124F6EB645DC407637F8F719CC31250089C89903BF1DB8FAC21EA4614DF4E99A\n\n");

		havalInit   (&hc, 4, 256);
		havalUpdate (&hc, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", strlen ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(4,256,\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\")\n");
		printDigest ("evaluated", digest, 256);
		printf      ("expected  = 46A3A1DFE867EDE652425CCD7FE8006537EAD26372251686BEA286DA152DC35A\n\n");
		break;

	case 5:
		havalInit   (&hc, 5, 128);
		havalUpdate (&hc, "", 0);
		havalFinal  (&hc, digest);
		printf      ("HAVAL(5,128,\"\")\n");
		printDigest ("evaluated", digest, 128);
		printf      ("expected  = 184B8482A0C050DCA54B59C7F05BF5DD\n\n");

		havalInit   (&hc, 5, 160);
		havalUpdate (&hc, "a", 1);
		havalFinal  (&hc, digest);
		printf      ("HAVAL(5,160,\"a\")\n");
		printDigest ("evaluated", digest, 160);
		printf      ("expected  = F5147DF7ABC5E3C81B031268927C2B5761B5A2B5\n\n");

		havalInit   (&hc, 5, 192);
		havalUpdate (&hc, "HAVAL", strlen ("HAVAL"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(5,192,\"HAVAL\")\n");
		printDigest ("evaluated", digest, 192);
		printf      ("expected  = 794A896D1780B76E2767CC4011BAD8885D5CE6BD835A71B8\n\n");

		havalInit   (&hc, 5, 224);
		havalUpdate (&hc, "0123456789", strlen ("0123456789"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(5,224,\"0123456789\")\n");
		printDigest ("evaluated", digest, 224);
		printf      ("expected  = 59836D19269135BC815F37B2AEB15F894B5435F2C698D57716760F2B\n\n");

		havalInit   (&hc, 5, 256);
		havalUpdate (&hc, "abcdefghijklmnopqrstuvwxyz", strlen ("abcdefghijklmnopqrstuvwxyz"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(5,256,\"abcdefghijklmnopqrstuvwxyz\")\n");
		printDigest ("evaluated", digest, 256);
		printf      ("expected  = C9C7D8AFA159FD9E965CB83FF5EE6F58AEDA352C0EFF005548153A61551C38EE\n\n");

		havalInit   (&hc, 5, 256);
		havalUpdate (&hc, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", strlen ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
		havalFinal  (&hc, digest);
		printf      ("HAVAL(5,256,\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\")\n");
		printDigest ("evaluated", digest, 256);
		printf      ("expected  = B45CB6E62F2B1320E4F8F1B0B273D45ADD47C321FD23999DCF403AC37636D963\n\n");
		break;

	default:
		printf ("usage: haval <passes>\n");
		break;
	}
	return 0;
} /* main */

#endif /* ?SELF_TESTING */
