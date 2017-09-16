#ifndef __EC_CURVE_H
#define __EC_CURVE_H

#include <stddef.h>

#include "ec_field.h"
#include "ec_vlong.h"

#ifndef USUAL_TYPES
	#define USUAL_TYPES
	typedef unsigned char	byte;
	typedef unsigned short	word16;
	typedef unsigned long	word32;
#endif /* ?USUAL_TYPES */

typedef struct {
	gfPoint x, y;
} ecPoint;


extern const vlPoint prime_order;
extern const ecPoint curve_point;


int ecCheck (const ecPoint *p);
	/* confirm that y^2 + x*y = x^3 + EC_B for point p */

void ecPrint (FILE *out, const char *tag, const ecPoint *p);
	/* printf prefix tag and the contents of p to file out */

int ecEqual (const ecPoint *p, const ecPoint *q);
	/* evaluates to 1 if p == q, otherwise 0 (or an error code) */

void ecCopy (ecPoint *p, const ecPoint *q);
	/* sets p := q */

int ecCalcY (ecPoint *p, int ybit);
	/* given the x coordinate of p, evaluate y such that y^2 + x*y = x^3 + EC_B */

void ecRandom (ecPoint *p);
	/* sets p to a random point of the elliptic curve defined by y^2 + x*y = x^3 + EC_B */

void ecClear (ecPoint *p);
	/* sets p to the point at infinity O, clearing entirely the content of p */

void ecAdd (ecPoint *p, const ecPoint *r);
	/* sets p := p + r */

void ecSub (ecPoint *p, const ecPoint *r);
	/* sets p := p - r */

void ecNegate (ecPoint *p);
	/* sets p := -p */

void ecDouble (ecPoint *p);
	/* sets p := 2*p */

void ecMultiply (ecPoint *p, const vlPoint k);
	/* sets p := k*p */

int ecYbit (const ecPoint *p);
	/* evaluates to 0 if p->x == 0, otherwise to gfYbit (p->y / p->x) */

void ecPack (const ecPoint *p, vlPoint k);
	/* packs a curve point into a vlPoint */

void ecUnpack (ecPoint *p, const vlPoint k);
	/* unpacks a vlPoint into a curve point */

int ecSelfTest (int test_count);
	/* perform test_count self tests */

#endif /* __EC_CURVE_H */
