/*
 * Elliptic curves over GF(2^m)
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
 */

#include <stdlib.h>
#include <time.h>

#include "ec_curve.h"
#include "ec_field.h"
#include "ec_param.h"
#include "ec_vlong.h"

extern const vlPoint prime_order;
extern const ecPoint curve_point;


#ifdef SELF_TESTING

int ecCheck (const ecPoint *p)
	/* confirm that y^2 + x*y = x^3 + EC_B for point p */
{
	gfPoint t1, t2, t3, b;

	b[0] = 1; b[1] = EC_B;
	gfSquare (t1, p->y);
	gfMultiply (t2, p->x, p->y);
	gfAdd (t1, t1, t2);	/* t1 := y^2 + x*y */
	gfSquare (t2, p->x);
	gfMultiply (t3, t2, p->x);
	gfAdd (t2, t3, b);	/*/ t2 := x^3 + EC_B */
	return gfEqual (t1, t2);
} /* ecCheck */


void ecPrint (FILE *out, const char *tag, const ecPoint *p)
	/* printf prefix tag and the contents of p to file out */
{
	int i;

	fprintf (out, "%s = ( ", tag);
	for (i = p->x[0]; i > 0; i--) {
		fprintf (out, "%d:%04X ", i, p->x[i]);
	}
	fprintf (out, ", ");
	for (i = p->y[0]; i > 0; i--) {
		fprintf (out, "%d:%04X ", i, p->y[i]);
	}
	fprintf (out, ")\n");
} /* ecPrint */


int ecEqual (const ecPoint *p, const ecPoint *q)
	/* evaluates to 1 if p == q, otherwise 0 (or an error code) */
{
	return gfEqual (p->x, q->x) && gfEqual (p->y, q->y);
} /* ecEqual */


void ecRandom (ecPoint *p)
	/* sets p to a random point of the elliptic curve defined by y^2 + x*y = x^3 + EC_B */
{
	int check;

	do {
		/* generate a pseudo-random x component: */
		gfRandom (p->x);
		/* evaluate the corresponding y component: */
		check = ecCalcY (p, 0);
#ifdef CHECK_POINT_DERIVATION
		if (!ecCheck (p)) {
			printf (">>> invalid elliptic curve point <<<\n");
		}
#endif /* ?CHECK_POINT_DERIVATION */
	} while (!check);
} /* ecRandom */


void ecClear (ecPoint *p)
	/* sets p to the point at infinity O, clearing entirely the content of p */
{
	gfClear (p->x);
	gfClear (p->y);
} /* ecClear */

#endif /* SELF_TESTING */


void ecCopy (ecPoint *p, const ecPoint *q)
	/* sets p := q */
{
	gfCopy (p->x, q->x);
	gfCopy (p->y, q->y);
} /* ecCopy */


int ecCalcY (ecPoint *p, int ybit)
	/* given the x coordinate of p, evaluate y such that y^2 + x*y = x^3 + EC_B */
{
	gfPoint a, b, t;

	b[0] = 1; b[1] = EC_B;
	if (p->x[0] == 0) {
		/* elliptic equation reduces to y^2 = EC_B: */
		gfSquareRoot (p->y, EC_B);
		return 1;
	}
	/* evaluate alpha = x^3 + b = (x^2)*x + EC_B: */
	gfSquare (t, p->x); /* keep t = x^2 for beta evaluation */
	gfMultiply (a, t, p->x);
	gfAdd (a, a, b); /* now a == alpha */
	if (a[0] == 0) {
		p->y[0] = 0;
		/* destroy potentially sensitive data: */
		gfClear (a); gfClear (t);
		return 1;
	}
	/* evaluate beta = alpha/x^2 = x + EC_B/x^2 */
	gfSmallDiv (t, EC_B);
	gfInvert (a, t);
	gfAdd (a, p->x, a); /* now a == beta */
	/* check if a solution exists: */
	if (gfTrace (a) != 0) {
		/* destroy potentially sensitive data: */
		gfClear (a); gfClear (t);
		return 0; /* no solution */
	}
	/* solve equation t^2 + t + beta = 0 so that gfYbit(t) == ybit: */
	gfQuadSolve (t, a);
	if (gfYbit (t) != ybit) {
		t[1] ^= 1;
	}
	/* compute y = x*t: */
	gfMultiply (p->y, p->x, t);
	/* destroy potentially sensitive data: */
	gfClear (a); gfClear (t);
	return 1;
} /* ecCalcY */


void ecAdd (ecPoint *p, const ecPoint *q)
	/* sets p := p + q */
{
	gfPoint lambda, t, tx, ty, x3;

	/* first check if there is indeed work to do (q != 0): */
	if (q->x[0] != 0 || q->y[0] != 0) {
		if (p->x[0] != 0 || p->y[0] != 0) {
			/* p != 0 and q != 0 */
			if (gfEqual (p->x, q->x)) {
				/* either p == q or p == -q: */
				if (gfEqual (p->y, q->y)) {
					/* points are equal; double p: */
					ecDouble (p);
				} else {
					/* must be inverse: result is zero */
					/* (should assert that q->y = p->x + p->y) */
					p->x[0] = p->y[0] = 0;
				}
			} else {
				/* p != 0, q != 0, p != q, p != -q */
				/* evaluate lambda = (y1 + y2)/(x1 + x2): */
				gfAdd (ty, p->y, q->y);
				gfAdd (tx, p->x, q->x);
				gfInvert (t, tx);
				gfMultiply (lambda, ty, t);
				/* evaluate x3 = lambda^2 + lambda + x1 + x2: */
				gfSquare (x3, lambda);
				gfAdd (x3, x3, lambda);
				gfAdd (x3, x3, tx);
				/* evaluate y3 = lambda*(x1 + x3) + x3 + y1: */
				gfAdd (tx, p->x, x3);
				gfMultiply (t, lambda, tx);
				gfAdd (t, t, x3);
				gfAdd (p->y, t, p->y);
				/* deposit the value of x3: */
				gfCopy (p->x, x3);
			}
		} else {
			/* just copy q into p: */
			gfCopy (p->x, q->x);
			gfCopy (p->y, q->y);
		}
	}
} /* ecAdd */


void ecSub (ecPoint *p, const ecPoint *r)
	/* sets p := p - r */
{
	ecPoint t;

	gfCopy (t.x, r->x);
	gfAdd  (t.y, r->x, r->y);
	ecAdd (p, &t);
} /* ecSub */

#ifdef SELF_TESTING

void ecNegate (ecPoint *p)
	/* sets p := -p */
{
	gfAdd (p->y, p->x, p->y);
} /* ecNegate */

#endif /* SELF_TESTING */

void ecDouble (ecPoint *p)
	/* sets p := 2*p */
{
	gfPoint lambda, t1, t2;

	/* evaluate lambda = x + y/x: */
	gfInvert (t1, p->x);
	gfMultiply (lambda, p->y, t1);
	gfAdd (lambda, lambda, p->x);
	/* evaluate x3 = lambda^2 + lambda: */
	gfSquare (t1, lambda);
	gfAdd (t1, t1, lambda); /* now t1 = x3 */
	/* evaluate y3 = x^2 + lambda*x3 + x3: */
	gfSquare (p->y, p->x);
	gfMultiply (t2, lambda, t1);
	gfAdd (p->y, p->y, t2);
	gfAdd (p->y, p->y, t1);
	/* deposit the value of x3: */
	gfCopy (p->x, t1);
} /* ecDouble */


void ecMultiply (ecPoint *p, const vlPoint k)
	/* sets p := k*p */
{
	vlPoint h;
	int z, hi, ki;
	word16 i;
	ecPoint r;

	gfCopy (r.x, p->x); p->x[0] = 0;
	gfCopy (r.y, p->y); p->y[0] = 0;
	vlShortMultiply (h, k, 3);
	z = vlNumBits (h) - 1; /* so vlTakeBit (h, z) == 1 */
	i = 1;
	for (;;) {
		hi = vlTakeBit (h, i);
		ki = vlTakeBit (k, i);
		if (hi == 1 && ki == 0) {
			ecAdd (p, &r);
		}
		if (hi == 0 && ki == 1) {
			ecSub (p, &r);
		}
		if (i >= z) {
			break;
		}
		i++;
		ecDouble (&r);
	}
} /* ecMultiply */


int ecYbit (const ecPoint *p)
	/* evaluates to 0 if p->x == 0, otherwise to gfYbit (p->y / p->x) */
{
	gfPoint t1, t2;

	if (p->x[0] == 0) {
		return 0;
	} else {
		gfInvert (t1, p->x);
		gfMultiply (t2, p->y, t1);
		return gfYbit (t2);
	}
} /* ecYbit */


void ecPack (const ecPoint *p, vlPoint k)
	/* packs a curve point into a vlPoint */
{
	vlPoint a;

	if (p->x[0]) {
		gfPack (p->x, k);
		vlShortLshift (k, 1);
		vlShortSet (a, (word16) ecYbit (p));
		vlAdd (k, a);
	} else if (p->y[0]) {
		vlShortSet (k, 1);
	} else {
		k[0] = 0;
	}
} /* ecPack */


void ecUnpack (ecPoint *p, const vlPoint k)
	/* unpacks a vlPoint into a curve point */
{
	int yb;
	vlPoint a;

	vlCopy (a, k);
	yb = a[0] ? a[1] & 1 : 0;
	vlShortRshift (a, 1);
	gfUnpack (p->x, a);

	if (p->x[0] || yb) {
		ecCalcY (p, yb);
	} else {
		p->y[0] = 0;
	}
} /* ecUnpack */

#ifdef SELF_TESTING

int ecSelfTest (int test_count)
	/* perform test_count self tests */
{
	int i, yb, nfail = 0, afail = 0, sfail = 0, cfail = 0, qfail = 0, pfail = 0, yfail = 0;
	ecPoint f, g, x, y;
	vlPoint m, n, p;
	clock_t elapsed = 0L;

	srand ((unsigned)(time(NULL) % 65521U));
	printf ("Executing %d curve self tests...", test_count);
	for (i = 0; i < test_count; i++) {
		ecRandom (&f);
		ecRandom (&g);
		vlRandom (m);
		vlRandom (n);

		/* negation test: -(-f) = f */
		ecCopy (&x, &f);
		ecNegate (&x);
		ecNegate (&x);
		if (!ecEqual (&x, &f)) {
			nfail++;
			/* printf ("Addition test #%d failed!\n", i); */
		}
		/* addition test: f+g = g+f */
		ecCopy (&x, &f); ecAdd (&x, &g);
		ecCopy (&y, &g); ecAdd (&y, &f);
		if (!ecEqual (&x, &y)) {
			afail++;
			/* printf ("Addition test #%d failed!\n", i); */
		}
		/* subtraction test: f-g = f+(-g) */
		ecCopy (&x, &f); ecSub (&x, &g);
		ecCopy (&y, &g); ecNegate (&y); ecAdd (&y, &f);
		if (!ecEqual (&x, &y)) {
			sfail++;
			/* printf ("Subtraction test #%d failed!\n", i); */
		}
		/* quadruplication test: 2*(2*f) = f + f + f + f */
		ecCopy (&x, &f); ecDouble (&x); ecDouble (&x);
		ecClear (&y); ecAdd (&y, &f); ecAdd (&y, &f); ecAdd (&y, &f); ecAdd (&y, &f);
		if (!ecEqual (&x, &y)) {
			qfail++;
			/* printf ("Quadruplication test #%d failed!\n", i); */
		}
		/* scalar multiplication commutativity test: m*(n*f) = n*(m*f) */
		ecCopy (&x, &f);
		ecCopy (&y, &f);
		elapsed -= clock ();
		ecMultiply (&x, n); ecMultiply (&x, m);
		ecMultiply (&y, m); ecMultiply (&y, n);
		elapsed += clock ();
		if (!ecEqual (&x, &y)) {
			cfail++;
			/* printf ("Commutativity test #%d failed!\n", i); */
		}
		/* y calculation test: */
		yb = ecYbit (&f);
		ecClear (&x);
		gfCopy (x.x, f.x);
		ecCalcY (&x, yb);
		if (!ecEqual (&f, &x)) {
			yfail++;
			/* printf ("Y calculation test #%d failed!\n", i); */
		}
		/* packing test: unpack (pack (f)) = f */
		ecPack (&f, p);
		ecUnpack (&x, p);
		if (!ecEqual (&f, &x)) {
			pfail++;
			/* printf ("Packing test #%d failed!\n", i); */
		}
	}
	printf (" done, scalar multiplication time: %.3f s/op.\n",
		(float)elapsed/CLOCKS_PER_SEC/(test_count?4*test_count:4));
	if (nfail) printf ("---> %d negations failed <---\n", nfail);
	if (afail) printf ("---> %d additions failed <---\n", afail);
	if (sfail) printf ("---> %d subtractions failed <---\n", sfail);
	if (qfail) printf ("---> %d quadruplications failed <---\n", qfail);
	if (cfail) printf ("---> %d commutativities failed <---\n", cfail);
	if (yfail) printf ("---> %d y calculations failed <---\n", yfail);
	if (pfail) printf ("---> %d packings failed <---\n", pfail);
	return nfail || afail || sfail || qfail || cfail || yfail || pfail;
} /* ecSelfTest */

#endif /* ?SELF_TESTING */
