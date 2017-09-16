/*
 * Multiple-precision ("very long") integer arithmetic
 *
 * This public domain software was written by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> based on original C++ software written by
 * George Barwood <george.barwood@dial.pipex.com>
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * References:
 *
 * 1.	Knuth, D. E.: "The Art of Computer Programming",
 *		2nd ed. (1981), vol. II (Seminumerical Algorithms), p. 257-258.
 *		Addison Wesley Publishing Company.
 *
 * 2.	Hansen, P. B.: "Multiple-length Division Revisited: a Tour of the Minefield".
 *		Software - Practice and Experience 24:6 (1994), 579-601.
 *
 * 3.	Menezes, A. J., van Oorschot, P. C., Vanstone, S. A.:
 *		"Handbook of Applied Cryptography", CRC Press (1997), section 14.2.5.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ec_param.h"
#include "ec_vlong.h"


#ifdef SELF_TESTING

void vlPrint (FILE *out, const char *tag, const vlPoint k)
	/* printf prefix tag and the contents of k to file out */
{
	word16 i;

	assert (k != NULL);
	fprintf (out, "%s", tag);
	for (i = k[0]; i > 0; i--) {
		fprintf (out, "%04x", k[i]);
	}
	fprintf (out, "\n");
} /* vlPrint */


void vlRandom (vlPoint k)
	/* sets k := <random very long integer value> */
{
	int i;

	assert (k != NULL);
	for (i = 1; i <= VL_UNITS; i++) {
		k[i] = (word16)rand();
	}
	for (i = VL_UNITS; i > 0; i--) {
		if (k[i]) {
			break;
		}
	}
	k[0] = i;
} /* vlRandom */

#endif /* ?SELF_TESTING */


int vlEqual (const vlPoint p, const vlPoint q)
{
	assert (p != NULL);
	assert (q != NULL);
	return memcmp (p, q, (p[0] + 1) * sizeof (word16)) == 0 ? 1 : 0;
} /* vlEqual */


void vlClear (vlPoint p)
{
	assert (p != NULL);
	memset (p, 0, sizeof (vlPoint));
} /* vlClear */


void vlCopy (vlPoint p, const vlPoint q)
	/* sets p := q */
{
	assert (p != NULL);
	assert (q != NULL);
	memcpy (p, q, (q[0] + 1) * sizeof (word16));
} /* vlCopy */


void vlShortSet (vlPoint p, word16 u)
	/* sets p := u */
{
	assert (p != NULL);
	p[0] = 1; p[1] = u;
} /* vlShortSet */


int vlNumBits (const vlPoint k)
	/* evaluates to the number of bits of k (index of most significant bit, plus one) */
{
	int i;
	word16 m, w;

	assert (k != NULL);
	if (k[0] == 0) {
		return 0;
	}
	w = k[k[0]]; /* last unit of k */
	for (i = (int)(k[0] << 4), m = 0x8000U; m; i--, m >>= 1) {
		if (w & m) {
			return i;
		}
	}
	return 0;
} /* vlNumBits */


int vlTakeBit (const vlPoint k, word16 i)
	/* evaluates to the i-th bit of k */
{
	assert (k != NULL);
	if (i >= (k[0] << 4)) {
		return 0;
	}
	return (int)((k[(i >> 4) + 1] >> (i & 15)) & 1);
} /* vlTakeBit */


void vlAdd (vlPoint u, const vlPoint v)
{
	word16 i;
	word32 t;

	assert (u != NULL);
	assert (v != NULL);
	/* clear high words of u if necessary: */
	for (i = u[0] + 1; i <= v[0]; i++) {
		u[i] = 0;
	}
    if (u[0] < v[0])
      u[0] = v[0];
	t = 0L;
	for (i = 1; i <= v[0]; i++) {
		t = t + (word32)u[i] + (word32)v[i];
		u[i] = (word16) (t & 0xFFFFUL);
		t >>= 16;
	}
    i = v[0]+1;
	while (t) {
        if ( i > u[0] )
        {
          u[i] = 0;
          u[0] += 1;
        }
        t = (word32)u[i] + 1;
		u[i] = (word16) (t & 0xFFFFUL);
        t >>= 16;
        i += 1;
	}
} /* vlAdd */


void vlSubtract (vlPoint u, const vlPoint v)
{
	/* Assume u >= v */
	word32 carry = 0, tmp;
	int i;

	assert (u != NULL);
	assert (v != NULL);
	for (i = 1; i <= v[0]; i++) {
		tmp = 0x10000UL + (word32)u[i] - (word32)v[i] - carry;
		carry = 1;
		if (tmp >= 0x10000UL) {
			tmp -= 0x10000UL;
			carry = 0;
		}
		u[i] = (word16) tmp;
	}
	if (carry) {
		while (u[i] == 0) {
			i++;
		}
		u[i]--;
	}
	while (u[u[0]] == 0 && u[0]) {
		u[0]--;
	}
} /* vlSubtract */


void vlShortLshift (vlPoint p, int n)
{
	word16 i, T=0;

	assert (p != NULL);
	if (p[0] == 0) {
		return;
	}
	/* this will only work if 0 <= n <= 16 */
	if (p[p[0]] >> (16 - n)) {
		/* check if there is enough space for an extra unit: */
		if (p[0] <= VL_UNITS + 1) {
			++p[0];
			p[p[0]] = 0; /* just make room for one more unit */
		}
	}
	for (i = p[0]; i > 1; i--) {
		p[i] = (p[i] << n) | (p[i - 1] >> (16 - n));
	}
	p[1] <<= n;
} /* vlShortLshift */


void vlShortRshift (vlPoint p, int n)
{
	word16 i;

	assert (p != NULL);
	if (p[0] == 0) {
		return;
	}
	/* this will only work if 0 <= n <= 16 */
	for (i = 1; i < p[0]; i++) {
		p[i] = (p[i + 1] << (16 - n)) | (p[i] >> n);
	}
	p[p[0]] >>= n;
	if (p[p[0]] == 0) {
		--p[0];
	}
} /* vlShortRshift */


int vlShortMultiply (vlPoint p, const vlPoint q, word16 d)
	/* sets p = q * d, where d is a single digit */
{
	int i;
	word32 t;

	assert (p != NULL);
	assert (q != NULL);
	if (q[0] > VL_UNITS) {
		puts ("ERROR: not enough room for multiplication\n");
		return -1;
	}
	if (d > 1) {
		t = 0L;
		for (i = 1; i <= q[0]; i++) {
			t += (word32)q[i] * (word32)d;
			p[i] = (word16) (t & 0xFFFFUL);
			t >>= 16;
		}
		if (t) {
			p[0] = q[0] + 1;
			p[p[0]] = (word16) (t & 0xFFFFUL);
		} else {
			p[0] = q[0];
		}
	} else if (d) { /* d == 1 */
		vlCopy (p, q);
	} else { /* d == 0 */
		p[0] = 0;
	}
	return 0;
} /* vlShortMultiply */


int vlGreater (const vlPoint p, const vlPoint q)
{
	int i;

	assert (p != NULL);
	assert (q != NULL);
	if (p[0] > q[0]) return 1;
	if (p[0] < q[0]) return 0;
	for (i = p[0]; i > 0; i--) {
		if (p[i] > q[i]) return 1;
		if (p[i] < q[i]) return 0;
	}
	return 0;
} /* vlGreater */


void vlRemainder (vlPoint u, const vlPoint v)
{
	vlPoint t;
	int shift = 0;

	assert (u != NULL);
	assert (v != NULL);
	assert (v[0] != 0);
	vlCopy( t, v );
	while ( vlGreater( u, t ) )
	{
		vlShortLshift( t, 1 );
		shift += 1;
	}
	while ( 1 )
	{
		if ( vlGreater( t, u ) )
		{
			if (shift)
			{
				vlShortRshift( t, 1 );
				shift -= 1;
			}
			else
				break;
		}
		else
			vlSubtract( u, t );
	}
} /* vlRemainder */


#if 0
/*********************************************************************/
/* >>> CAVEAT: THIS IS WORK IN PROGRESS; SKIP THIS WHOLE SECTION <<< */
/*********************************************************************/

void vlMod (vlPoint u, const vlPoint v)
	/* sets u := u mod v */
{
	int i; word16 ud, vd;
	word32 phat, qhat, v1, v2;
	static word16 d, U[2*VL_UNITS], V[VL_UNITS], t[VL_UNITS];

	if (v[0] == 1) {
		/* short division: divide u[1...u[0]] by v[1] */
		v1 = (word32)v[1]; v2 = 0L;
		for (i = u[0]; i > 0; i--) {
			v2 = ((v2 << 16) + (word32)u[i]) % v1;
		}
		u[0] = 1; u[1] = (word16)v2;
	} else if (u[0] >= v[0]) { /* nothing to do if u[0] < v[0] (u is already reduced mod v) */
		/* long division: */
		ud = u[0]; vd = v[0];
		/* normalize: */
		d = (word16) (0x10000UL / ((word32)v[vd] + 1L));
		vlShortMultiply (U, u, d); U[ud + 1] = 0;
		vlShortMultiply (V, v, d); V[vd + 1] = 0;
		v1 = (word32) V[vd];
		v2 = (word32) V[vd - 1];
		/* loop on i: */
		for (i = ud + 1; i > vd; i--) {
			/* calculate qhat as a trial quotient digit: */
			phat = ((word32) U[i] << 16) + (word32) U[i - 1];
			qhat = ((word32) U[i] == v1) ? 0xFFFFUL : phat / v1;
			while (v2 * qhat > ((phat - v1 * qhat) << 16) + (word32) U[i - 2]) {
				qhat--;
			}
			/* multiply, subtract, and check result: */
			vlSmallMultiply (t, V, (word16) qhat);
			if (t[0] < vd) {
				t[vd] = 0;
			}
			if (vlPartialSub (U + i - vd, t, vd + 1)) {
				qhat--;
				vlPartialAdd (U + i - vd, V, vd + 1);
			}
		}
		/* unnormalize to evaluate the remainder (divide U[1...vd] by d): */
		v1 = 0L; v2 = (word32)d;
		for (i = vd; i > 0; i--) {
			v1 = (v1 << 16) + (word32)U[i];
			u[i] = (word16) (v1 / v2);
			v1 %= v2;
		}
		u[0] = vd;
	}
} /* vlMod */
#endif /* OMIT */


void vlMulMod (vlPoint u, const vlPoint v, const vlPoint w, const vlPoint m)
{
	vlPoint t;
	int i,j;
	
	assert (u != NULL);
	assert (v != NULL);
	assert (w != NULL);
	assert (m != NULL);
	assert (m[0] != 0);
	vlClear( u );
	vlCopy( t, w );
	for (i=1;i<=v[0];i+=1)
	{
		for (j=0;j<16;j+=1)
		{
			if ( v[i] & (1u<<j) )
			{
				vlAdd( u, t );
				vlRemainder( u, m );
			}
			vlShortLshift( t, 1 );
			vlRemainder( t, m );
		}
	}
} /* vlMulMod */


#ifdef SELF_TESTING

int vlSelfTest (int test_count)
{
	int i, tfail = 0, sfail = 0, afail = 0;
	vlPoint m, p, q;
	clock_t elapsed;

	srand ((unsigned)(time(NULL) % 65521U));
	printf ("Executing %d vlong self tests...", test_count);
	elapsed = -clock ();
	for (i = 0; i < test_count; i++) {
		vlRandom (m);
		/* scalar triplication test: 3*m = m + m + m */
		vlShortMultiply (p, m, 3);
		vlClear (q); vlAdd (q, m); vlAdd (q, m); vlAdd (q, m);
		if (!vlEqual (p, q)) {
			tfail++;
			/* printf ("Triplication test #%d failed!\n", i); */
		}
		/* shift test: (m << k) >> k = m */
		vlCopy (p, m);
		vlShortLshift (p, i%17);
		vlShortRshift (p, i%17);
		if (!vlEqual (p, m)) {
			sfail++;
			/* printf ("Shift test #%d failed!\n", i); */
		}
		/* addition vs. shift test: m + m = m << 1 */
		vlCopy (p, m); vlAdd (p, p);
		vlCopy (q, m); vlShortLshift (q, 1);
		if (!vlEqual (p, q)) {
			afail++;
			/* printf ("Addition test #%d failed!\n", i); */
		}
      
	}
	elapsed += clock ();
	printf (" done, elapsed time = %.1f s.\n", (float)elapsed/CLOCKS_PER_SEC);
	if (tfail) printf ("---> %d triplications failed <---\n", tfail);
	if (sfail) printf ("---> %d shifts failed <---\n", sfail);
	if (afail) printf ("---> %d additions failed <---\n", afail);
	return tfail || sfail || afail;
} /* vlSelfTest */

#endif /* ?SELF_TESTING */
