/* NN.C - natural numbers routines
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

/* 
 * MODIFIED BY RIPEM DEVELOPERS for improved performance 
 */

#include "global.h"
#include "rsaref.h"
#include "nn.h"
#include "digit.h"
#include "longlong.h"

/* use Montgomery multiplication */
#define USE_MONT 1

static NN_DIGIT NN_AddDigitMult PROTO_LIST 
  ((NN_DIGIT *, NN_DIGIT *, NN_DIGIT, NN_DIGIT *, unsigned int));
static NN_DIGIT NN_SubDigitMult PROTO_LIST 
  ((NN_DIGIT *, NN_DIGIT *, NN_DIGIT, NN_DIGIT *, unsigned int));
static unsigned int NN_DigitBits PROTO_LIST ((NN_DIGIT));

#ifdef USE_MONT
static void MontProduct PROTO_LIST
  ((NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int, NN_DIGIT,
    unsigned int));
static NN_DIGIT NN_Mod2Inv PROTO_LIST ((NN_DIGIT *));
static void NN_MontModExp PROTO_LIST
  ((NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int, NN_DIGIT *,
    unsigned int nDigits));
#endif

/* Decodes character string b into a, where character string is ordered
   from most to least significant.

   Lengths: a[digits], b[len].
   Assumes b[i] = 0 for i < len - digits * NN_DIGIT_LEN. (Otherwise most
   significant bytes are truncated.)
 */
void NN_Decode (a, digits, b, len)
NN_DIGIT *a;
unsigned char *b;
unsigned int digits, len;
{
  NN_DIGIT t;
  int j;
  unsigned int i, u;
  
  for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
    t = 0;
    for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
      t |= ((NN_DIGIT)b[j]) << u;
    a[i] = t;
  }
  
  for (; i < digits; i++)
    a[i] = 0;
}

/* Encodes b into character string a, where character string is ordered
   from most to least significant.

   Lengths: a[len], b[digits].
   Assumes NN_Bits (b, digits) <= 8 * len. (Otherwise most significant
   digits are truncated.)
 */
void NN_Encode (a, len, b, digits)
NN_DIGIT *b;
unsigned char *a;
unsigned int digits, len;
{
  NN_DIGIT t;
  int j;
  unsigned int i, u;

  for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
    t = b[i];
    for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
      a[j] = (unsigned char)(t >> u);
  }

  for (; j >= 0; j--)
    a[j] = 0;
}

/* Assigns a = b.

   Lengths: a[digits], b[digits].
 */
void NN_Assign (a, b, digits)
NN_DIGIT *a, *b;
unsigned int digits;
{
  unsigned int i;

  for (i = 0; i < digits; i++)
    a[i] = b[i];
}

/* Assigns a = 0.

   Lengths: a[digits].
 */
void NN_AssignZero (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  unsigned int i;

  for (i = 0; i < digits; i++)
    a[i] = 0;
}

/* Assigns a = 2^b.

   Lengths: a[digits].
   Requires b < digits * NN_DIGIT_BITS.
 */
void NN_Assign2Exp (a, b, digits)
NN_DIGIT *a;
unsigned int b, digits;
{
  NN_AssignZero (a, digits);

  if (b >= digits * NN_DIGIT_BITS)
    return;

  a[b / NN_DIGIT_BITS] = (NN_DIGIT)1 << (b % NN_DIGIT_BITS);
}

/* Computes a = b + c. Returns carry.

   Lengths: a[digits], b[digits], c[digits].
 */
NN_DIGIT NN_Add (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT ai, carry;
  unsigned int i;

  carry = 0;

  for (i = 0; i < digits; i++) {
    if ((ai = b[i] + carry) < carry)
      ai = c[i];
    else if ((ai += c[i]) < c[i])
      carry = 1;
    else
      carry = 0;
    a[i] = ai;
  }

  return (carry);
}

/* Computes a = b - c. Returns borrow.

   Lengths: a[digits], b[digits], c[digits].
 */
NN_DIGIT NN_Sub (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT ai, borrow;
  unsigned int i;

  borrow = 0;

  for (i = 0; i < digits; i++) {
    if ((ai = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
      ai = MAX_NN_DIGIT - c[i];
    else if ((ai -= c[i]) > (MAX_NN_DIGIT - c[i]))
      borrow = 1;
    else
      borrow = 0;
    a[i] = ai;
  }

  return (borrow);
}

/* Computes a = b * c.

   Lengths: a[2*digits], b[digits], c[digits].
   Assumes digits < MAX_NN_DIGITS.
 */
void NN_Mult (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT t[2*MAX_NN_DIGITS];
  unsigned int bDigits, cDigits, i;

  NN_AssignZero (t, 2 * digits);
  
  bDigits = NN_Digits (b, digits);
  cDigits = NN_Digits (c, digits);

  for (i = 0; i < bDigits; i++)
    t[i+cDigits] += NN_AddDigitMult (&t[i], &t[i], b[i], c, cDigits);
  
  NN_Assign (a, t, 2 * digits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires c < NN_DIGIT_BITS.
 */
NN_DIGIT NN_LShift (a, b, c, digits)
NN_DIGIT *a, *b;
unsigned int c, digits;
{
  NN_DIGIT bi, carry;
  unsigned int i, t;
  
  if (c >= NN_DIGIT_BITS)
    return (0);
  
  t = NN_DIGIT_BITS - c;

  carry = 0;

  for (i = 0; i < digits; i++) {
    bi = b[i];
    a[i] = (bi << c) | carry;
    carry = c ? (bi >> t) : 0;
  }
  
  return (carry);
}

/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires: c < NN_DIGIT_BITS.
 */
NN_DIGIT NN_RShift (a, b, c, digits)
NN_DIGIT *a, *b;
unsigned int c, digits;
{
  NN_DIGIT bi, carry;
  int i;
  unsigned int t;
  
  if (c >= NN_DIGIT_BITS)
    return (0);
  
  t = NN_DIGIT_BITS - c;

  carry = 0;

  for (i = digits - 1; i >= 0; i--) {
    bi = b[i];
    a[i] = (bi >> c) | carry;
    carry = c ? (bi << t) : 0;
  }
  
  return (carry);
}

/* Computes a = c div d and b = c mod d.

   Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits < 2 * MAX_NN_DIGITS,
           dDigits < MAX_NN_DIGITS.
 */
void NN_Div (a, b, c, cDigits, d, dDigits)
NN_DIGIT *a, *b, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT ai, cc[2*MAX_NN_DIGITS+1], dd[MAX_NN_DIGITS], t;
  int i;
  unsigned int ddDigits, shift;
  
  ddDigits = NN_Digits (d, dDigits);
  if (ddDigits == 0)
    return;
  
  /* Normalize operands.
   */
  shift = NN_DIGIT_BITS - NN_DigitBits (d[ddDigits-1]);
  NN_AssignZero (cc, ddDigits);
  cc[cDigits] = NN_LShift (cc, c, shift, cDigits);
  NN_LShift (dd, d, shift, ddDigits);
  t = dd[ddDigits-1];
  
  NN_AssignZero (a, cDigits);

  for (i = cDigits-ddDigits; i >= 0; i--) {
    /* Underestimate quotient digit and subtract.
     */
    if (t == MAX_NN_DIGIT)
      ai = cc[i+ddDigits];
    else
      NN_DigitDiv (&ai, &cc[i+ddDigits-1], t + 1);
    cc[i+ddDigits] -= NN_SubDigitMult (&cc[i], &cc[i], ai, dd, ddDigits);

    /* Correct estimate.
     */
    while (cc[i+ddDigits] || (NN_Cmp (&cc[i], dd, ddDigits) >= 0)) {
      ai++;
      cc[i+ddDigits] -= NN_Sub (&cc[i], &cc[i], dd, ddDigits);
    }
    
    a[i] = ai;
  }
  
  /* Restore result.
   */
  NN_AssignZero (b, dDigits);
  NN_RShift (b, cc, shift, ddDigits);

  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)cc, 0, sizeof (cc));
  R_memset ((POINTER)dd, 0, sizeof (dd));
}

/* Computes a = b mod c.

   Lengths: a[cDigits], b[bDigits], c[cDigits].
   Assumes c > 0, bDigits < 2 * MAX_NN_DIGITS, cDigits < MAX_NN_DIGITS.
 */
void NN_Mod (a, b, bDigits, c, cDigits)
NN_DIGIT *a, *b, *c;
unsigned int bDigits, cDigits;
{
  NN_DIGIT t[2 * MAX_NN_DIGITS];
  
  NN_Div (t, a, b, bDigits, c, cDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}

/* Computes a = b * c mod d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes d > 0, digits < MAX_NN_DIGITS.
 */
void NN_ModMult (a, b, c, d, digits)
NN_DIGIT *a, *b, *c, *d;
unsigned int digits;
{
  NN_DIGIT t[2*MAX_NN_DIGITS];

  NN_Mult (t, b, c, digits);
  NN_Mod (a, t, 2 * digits, d, digits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
}

#ifdef USE_MONT
#define NN_THRESH 5

/* Montgomery Product
   a = result
   b,c = values to "multiply"
   d = modulus
   n = # of digits
   v = -(1/d) mod 2^{NN_DIGIT_BITS} -- N.B.: this is a single digit
   k = number of digits in d (don't count leading zeros)

   Operand scanning version.
 */
static void MontProduct (a, b, c, d, n, v, k)
NN_DIGIT *a,*b,*c,*d; 
unsigned int n;
NN_DIGIT v;
unsigned int k;
{
  int i;
  NN_DIGIT cr, t[2 * MAX_NN_DIGITS + 1], u[MAX_NN_DIGITS + 1];

  NN_AssignZero (t, 2 * n + 1);

  for (i = 0; i < n; i++) {
    cr = t[i + n];;

    if ((cr +=  NN_AddDigitMult (&t[i], &t[i], b[i], c, n)) < t[i + n])
      /* carry */
      t[i + n + 1]++;
    t[i + n] = cr;
    if ((cr += NN_AddDigitMult (&t[i], &t[i], t[i] * v, d, n)) < t[i + n])
      /* carry */
      t[i + n + 1]++;
    t[i + n] = cr;
  }
    
  /* now shift right by k digits, i.e. divide by r=B^k */
  for (i = 0; i <= n; i++)  /* N.B. u can have n+1 digits */
    u[i] = t[i + k]; 

  /* after subtracting (if necessary), we know u will have at most n digits  
   */
  if (u[n] || NN_Cmp (u, d, n) >= 0) 
    NN_Sub (a, u, d, n);
  else
    NN_Assign (a, u, n);
}

#if (NN_DIGIT_BITS == 32) 

/* Calculate -(1/y) mod (2^NN_DIGIT_BITS).
   Thanks to Colin Plumb <colin@nyx10.cs.du.edu> for a cool way to do this
   computation. It could be extended to arbitrary NN_DIGIT_BITS, but it
   turns out that there isn't much point.
 */
static NN_DIGIT NN_Mod2Inv (y)  
NN_DIGIT *y;
{
  NN_DIGIT x = *y;
    
  x += x - (*y) * x * x;
  x += x - (*y) * x * x;
  x += x - (*y) * x * x;
  x += x - (*y) * x * x;

  return ((0xffffffff - x) + 1);
}
#else
/* Calculate -(1/x) mod (2^NN_DIGIT_BITS).
   See Dusse, Kaliski: A Cryptographic Library for the Motorola DSP56000
     in the Eurocrypt 90 proceedings. Clever, simple and fast.
 */
static NN_DIGIT NN_Mod2Inv (x)
NN_DIGIT *x;
{
  unsigned int i;
  NN_DIGIT v = 1;

  /* work up to NN_DIGIT_BITS */
  for (i = 2; i < NN_DIGIT_BITS; i++)  {
    if (( (x[0] * v) % (1 << i)) != 1)
      v |= 1 << (i - 1);
    /* LOOP INVARIANT: ((x[0] * v) % (1<<i) == 1) */
  }

  /* last bit */
  if ((x[0] * v) != 1)
    v |= (1<<(NN_DIGIT_BITS - 1));

  return ((MAX_NN_DIGIT - v) + 1);
}
#endif

/* x = a^c mod n, n must be odd
 */ 
static void NN_MontModExp (x, a, c, cDigits, n, nDigits) 
NN_DIGIT *x, *a, *c;
unsigned int cDigits;
NN_DIGIT *n;
unsigned int nDigits;
{
  int k, i;
  NN_DIGIT v, r[MAX_NN_DIGITS + 1], t1[2*MAX_NN_DIGITS + 1],
    a1[MAX_NN_DIGITS + 1], one[MAX_NN_DIGITS], aPower[15][MAX_NN_DIGITS], ci,
    t[MAX_NN_DIGITS];
  unsigned int ciBits, j, s;

  NN_AssignZero (one, nDigits);
  one[0] = 1;

  k = NN_Digits (n, nDigits);

  /* r = B^k, where B=2^{NN_DIGIT_BITS}*/
  NN_AssignZero (r, k + 1);
  r[k] = 1;

  /* v = -(1/n) mod B */
  v = NN_Mod2Inv (n);

  /* a1 = a*r mod n */
  NN_AssignZero (t1, 2 * k + 1);
  for (i = 0; i < k; i++) 
    t1[i + k] = a[i];
  NN_Mod (a1, t1, 2 * k + 1, n, nDigits);

  /* t = r mod n */
  NN_Mod (t, r, k + 1, n, nDigits);

  cDigits = NN_Digits (c, cDigits);
  if (cDigits < NN_THRESH) {
    /* take bits of exponent two at a time */
    NN_Assign (aPower[0], a1, k);
    MontProduct (aPower[1], aPower[0], a1, n, k, v,k);
    MontProduct (aPower[2], aPower[1], a1, n, k, v,k);
        
    for (i = cDigits - 1; i >= 0; i--) {
      ci = c[i];
      ciBits = NN_DIGIT_BITS;
            
      /* Scan past leading zero bits of most significant digit.
       */
      if (i == (int)(cDigits - 1)) {
        while (! DIGIT_2MSB (ci)) {
          ci <<= 2;
          ciBits -= 2;
        }
      }

      for (j = 0; j < ciBits; j += 2, ci <<= 2) {
        MontProduct (t, t, t, n, k, v,k);
        MontProduct (t, t, t, n, k, v,k);
        if ((s = DIGIT_2MSB (ci)) != 0)
          MontProduct (t, t, aPower[s - 1], n, k, v,k);
      }
    }
  }
  else {
    /* process exponent nibble by nibble */

    /* precompute */
    NN_Assign (aPower[0], a1, k);
    MontProduct (aPower[1], aPower[0], a1, n, k, v,k);   
    MontProduct (aPower[2], aPower[1], a1, n, k, v,k);  
    MontProduct (aPower[3], aPower[2], a1, n, k, v,k);   
    MontProduct (aPower[4], aPower[3], a1, n, k, v,k);  
    MontProduct (aPower[5], aPower[4], a1, n, k, v,k); 
    MontProduct (aPower[6], aPower[5], a1, n, k, v,k);
    MontProduct (aPower[7], aPower[6], a1, n, k, v,k);
    MontProduct (aPower[8], aPower[7], a1, n, k, v,k);  
    MontProduct (aPower[9], aPower[8], a1, n, k, v,k);   
    MontProduct (aPower[10], aPower[9], a1, n, k, v,k);  
    MontProduct (aPower[11], aPower[10], a1, n, k, v,k); 
    MontProduct (aPower[12], aPower[11], a1, n, k, v,k); 
    MontProduct (aPower[13], aPower[12], a1, n, k, v,k); 
    MontProduct (aPower[14], aPower[13], a1, n, k, v,k); 
        
    for (i = cDigits - 1; i >= 0; i--) {
      ci = c[i];
      ciBits = NN_DIGIT_BITS;
            
      /* Scan past leading zero bits of most significant digit.
       */
      if (i == (int)(cDigits - 1)) {
        while (! DIGIT_4MSB (ci)) {
          ci <<= 4;
          ciBits -= 4;
        }
      }

      for (j = 0; j < ciBits; j += 4, ci <<= 4) {
        MontProduct (t, t, t, n, k, v, k);
        MontProduct (t, t, t, n, k, v, k);
        MontProduct (t, t, t, n, k, v, k);
        MontProduct (t, t, t, n, k, v, k);
        if ((s = DIGIT_4MSB (ci)) != 0)
          MontProduct (t, t, aPower[s-1], n, k, v, k);
      }
    }
  }
 
  NN_AssignZero (x, nDigits); 
  MontProduct (x, t, one, n, k, v, k);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)aPower, 0, sizeof (aPower));
  R_memset ((POINTER)t, 0, sizeof (t));
}
#endif  
/* USE_MONT */

/* Computes a = b^c mod d.

   Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits > 0, dDigits < MAX_NN_DIGITS.
 */

void NN_ModExp (a, b, c, cDigits, d, dDigits)
NN_DIGIT *a, *b, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT bPower[3][MAX_NN_DIGITS], ci, t[MAX_NN_DIGITS];
  int i;
  unsigned int ciBits, j, s;

#ifdef USE_MONT
  /* if d is odd we use Montgomery multiplication -- for RSA d is always odd */
  if (d[0] & 0x01) {
    NN_MontModExp (a, b, c, cDigits, d, dDigits);
    return;
  }
#endif

  /* Store b, b^2 mod d, and b^3 mod d.
   */
  NN_Assign (bPower[0], b, dDigits);
  NN_ModMult (bPower[1], bPower[0], b, d, dDigits);
  NN_ModMult (bPower[2], bPower[1], b, d, dDigits);
  
  NN_ASSIGN_DIGIT (t, 1, dDigits);

  cDigits = NN_Digits (c, cDigits);
  for (i = cDigits - 1; i >= 0; i--) {
    ci = c[i];
    ciBits = NN_DIGIT_BITS;
    
    /* Scan past leading zero bits of most significant digit.
     */
    if (i == (int)(cDigits - 1)) {
      while (! DIGIT_2MSB (ci)) {
        ci <<= 2;
        ciBits -= 2;
      }
    }

    for (j = 0; j < ciBits; j += 2, ci <<= 2) {
      /* Compute t = t^4 * b^s mod d, where s = two MSB's of ci.
       */
      NN_ModMult (t, t, t, d, dDigits);
      NN_ModMult (t, t, t, d, dDigits);
      if ((s = DIGIT_2MSB (ci)) != 0)
        NN_ModMult (t, t, bPower[s-1], d, dDigits);
    }
  }
  
  NN_Assign (a, t, dDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)bPower, 0, sizeof (bPower));
  R_memset ((POINTER)t, 0, sizeof (t));
}

/* Compute a = 1/b mod c, assuming inverse exists.
   
   Lengths: a[digits], b[digits], c[digits].
   Assumes gcd (b, c) = 1, digits < MAX_NN_DIGITS.
 */
void NN_ModInv (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT q[MAX_NN_DIGITS], t1[MAX_NN_DIGITS], t3[MAX_NN_DIGITS],
    u1[MAX_NN_DIGITS], u3[MAX_NN_DIGITS], v1[MAX_NN_DIGITS],
    v3[MAX_NN_DIGITS], w[2*MAX_NN_DIGITS];
  int u1Sign;

  /* Apply extended Euclidean algorithm, modified to avoid negative
     numbers.
   */
  NN_ASSIGN_DIGIT (u1, 1, digits);
  NN_AssignZero (v1, digits);
  NN_Assign (u3, b, digits);
  NN_Assign (v3, c, digits);
  u1Sign = 1;

  while (! NN_Zero (v3, digits)) {
    NN_Div (q, t3, u3, digits, v3, digits);
    NN_Mult (w, q, v1, digits);
    NN_Add (t1, u1, w, digits);
    NN_Assign (u1, v1, digits);
    NN_Assign (v1, t1, digits);
    NN_Assign (u3, v3, digits);
    NN_Assign (v3, t3, digits);
    u1Sign = -u1Sign;
  }
  
  /* Negate result if sign is negative.
    */
  if (u1Sign < 0)
    NN_Sub (a, c, u1, digits);
  else
    NN_Assign (a, u1, digits);

  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)q, 0, sizeof (q));
  R_memset ((POINTER)t1, 0, sizeof (t1));
  R_memset ((POINTER)t3, 0, sizeof (t3));
  R_memset ((POINTER)u1, 0, sizeof (u1));
  R_memset ((POINTER)u3, 0, sizeof (u3));
  R_memset ((POINTER)v1, 0, sizeof (v1));
  R_memset ((POINTER)v3, 0, sizeof (v3));
  R_memset ((POINTER)w, 0, sizeof (w));
}

/* Computes a = gcd(b, c).

   Lengths: a[digits], b[digits], c[digits].
   Assumes b > c, digits < MAX_NN_DIGITS.
 */
void NN_Gcd (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT t[MAX_NN_DIGITS], u[MAX_NN_DIGITS], v[MAX_NN_DIGITS];

  NN_Assign (u, b, digits);
  NN_Assign (v, c, digits);

  while (! NN_Zero (v, digits)) {
    NN_Mod (t, u, digits, v, digits);
    NN_Assign (u, v, digits);
    NN_Assign (v, t, digits);
  }

  NN_Assign (a, u, digits);

  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
  R_memset ((POINTER)u, 0, sizeof (u));
  R_memset ((POINTER)v, 0, sizeof (v));
}

/* Returns sign of a - b.

   Lengths: a[digits], b[digits].
 */
int NN_Cmp (a, b, digits)
NN_DIGIT *a, *b;
unsigned int digits;
{
  int i;
  
  for (i = digits - 1; i >= 0; i--) {
    if (a[i] > b[i])
      return (1);
    if (a[i] < b[i])
      return (-1);
  }

  return (0);
}

/* Returns nonzero iff a is zero.

   Lengths: a[digits].
 */
int NN_Zero (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  unsigned int i;
  
  for (i = 0; i < digits; i++)
    if (a[i])
      return (0);
    
  return (1);
}

/* Returns the significant length of a in bits.

   Lengths: a[digits].
 */
unsigned int NN_Bits (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  if ((digits = NN_Digits (a, digits)) == 0)
    return (0);

  return ((digits - 1) * NN_DIGIT_BITS + NN_DigitBits (a[digits-1]));
}

/* Returns the significant length of a in digits.

   Lengths: a[digits].
 */
unsigned int NN_Digits (a, digits)
NN_DIGIT *a;
unsigned int digits;
{
  int i;
  
  for (i = digits - 1; i >= 0; i--)
    if (a[i])
      break;

  return (i + 1);
}

/* Computes a = b + c*d, where c is a digit. Returns carry.

   Lengths: a[digits], b[digits], d[digits].
 */
static NN_DIGIT NN_AddDigitMult (a, b, c, d, digits)
NN_DIGIT *a, *b, c, *d;
unsigned int digits;
{
  NN_DIGIT carry, t0,t1;
  unsigned int i;

  if (c == 0)
    return (0);

#ifdef USE_386_ASM
        /* Register assignments:
         *
         *      EAX     
         *      EBX     i
         *      ECX     carry
         * EDX  
         * ESI  &a
         * EDI  scratch register for array base addresses
         */
  _asm {
                sub     ebx,ebx ;i=0
                sub     ecx,ecx ;carry=0
                mov     esi,a           ;esi=&a
                cmp     digits,0
                jz              endloop ;jump if digits=0
        mulloop:;
                mov     edi,b           ;edi=&b
                add     ecx,[edi+4*ebx] ;carry += b[i]
                mov     [esi+4*ebx],ecx ;a[i] = carry+b[i]
                mov     ecx,0           ;carry=0
                jnc     nocar_add       ;jump if addition did not carry
                inc     ecx             ;carry=1
        nocar_add:;
                mov     eax,c           ;eax=c
                mov     edi,d           ;edi=&d
                mul     dword ptr [edi+4*ebx]   ;edx:eax = c*d[i]

                add     [esi+4*ebx],eax ;a[i] += low order product
                jnc     nocarry
                inc     ecx             ;carry++
        nocarry:;
                add     ecx,edx ;carry += high order product            
                inc     ebx             ;i++
                cmp     ebx,digits
                jb              mulloop ;jump if i<digits
        endloop:;       
                mov     carry,ecx
        };
#else
#if defined(__GNUC__) && defined(__i386__)
        asm("subl %%ebx,%%ebx; \
        subl %%ecx,%%ecx; \
        movl %1,%%esi   ; \
        cmpl $0, %2     ; \
        jz endloop; \
mulloop:; \
        movl %3,%%edi; \
        addl (%%edi, %%ebx, 4),%%ecx; \
        movl %%ecx,(%%esi,%%ebx,4); \
        movl $0, %%ecx; \
        jnc nocarr_add; \
        incl %%ecx; \
nocarr_add:; \
        movl %4, %%eax; \
        movl %5, %%edi; \
        mull (%%edi,%%ebx,4); \
        addl %%eax,(%%esi,%%ebx,4); \
        jnc nocarry; \
        incl %%ecx; \
nocarry:; \
        addl %%edx,%%ecx; \
        incl %%ebx; \
        cmpl %2,%%ebx ;\
        jl mulloop; \
endloop:; \
        mov %%ecx,%0"
:"=g"(carry)
:"g"(&a[0]), "g" (digits), "g" (&b[0]), "g" (c), "g" (&d[0]) :
"edi", "ecx", "ebx", "eax", "edx", "esi");
#else
  carry = 0;
  for (i = 0; i < digits; i++) {
    umul_ppmm(t1,t0,c,d[i]);
    if ((a[i] = b[i] + carry) < carry)
      carry = 1;
    else
      carry = 0;
    if ((a[i] += t0) < t0)
      carry++;
    carry += t1;
  }
#endif
#endif
  
  return (carry);
}

/* Computes a = b - c*d, where c is a digit. Returns borrow.

   Lengths: a[digits], b[digits], d[digits].
 */
static NN_DIGIT NN_SubDigitMult (a, b, c, d, digits)
NN_DIGIT *a, *b, c, *d;
unsigned int digits;
{
  register NN_DIGIT borrow;
#ifndef USE_386_ASM
  NN_DIGIT t0,t1;
  unsigned int i;
#endif

  if (c == 0)
    return (0);
#ifdef USE_386_ASM
        /* Register assignments:
         *
         *      EAX     Scratch reg for multiply
         *      EBX     i
         *      ECX     borrow
         * EDX  Scratch reg for multiply
         * ESI  &a
         * EDI  scratch register for array base addresses
         */
  _asm {
                sub     ebx,ebx ;i=0
                sub     ecx,ecx ;borrow=0
                mov     esi,a           ;esi=&a
                cmp     digits,0
                jz              endloop ;jump if digits=0
        mulloop:;
                mov     edi,b           ;edi=&b
                mov     eax,[edi+4*ebx] ;eax=b[i]
                sub     eax,ecx ;eax=b[i]-borrow
                mov     [esi+4*ebx],eax ;a[i] = b[i]-borrow
                mov     ecx,0           ;borrow=0
                jnc     noborrow_sub    ;jump if subtract did not borrow
                inc     ecx             ;borrow=1
        noborrow_sub:;
                mov     eax,c           ;eax=c
                mov     edi,d           ;edi=&d
                mul     dword ptr [edi+4*ebx]   ;edx:eax = c*d[i]

                sub     [esi+4*ebx],eax ;a[i] -= low order product
                jnc     noborrow
                inc     ecx             ;borrow++
        noborrow:;
                add     ecx,edx ;borrow += high order product           
                inc     ebx             ;i++
                cmp     ebx,digits
                jb              mulloop ;jump if i<digits
        endloop:;       
                mov     borrow,ecx
        };
#else
#if defined(__GNUC__) && defined(__i386__)
        asm("subl %%ebx,%%ebx; \
        subl %%ecx,%%ecx; \
        movl %1,%%esi   ; \
        cmpl $0, %2     ; \
        jz sendloop; \
smulloop:; \
        movl %3,%%edi; \
        movl (%%edi,%%ebx,4),%%eax; \
        subl %%ecx,%%eax; \
        movl %%eax,(%%esi,%%ebx,4); \
        movl $0, %%ecx; \
        jnc noborrow_sub; \
        incl %%ecx; \
noborrow_sub:;\
        movl %4, %%eax; \
        movl %5, %%edi; \
        mull (%%edi,%%ebx,4); \
        subl %%eax,(%%esi,%%ebx,4); \
        jnc noborrow; \
        incl %%ecx; \
noborrow:; \
        addl %%edx,%%ecx; \
        incl %%ebx; \
        cmpl %2,%%ebx ;\
        jl smulloop; \
sendloop:; \
        mov %%ecx,%0"
:"=g"(borrow)
:"g"(&a[0]), "g" (digits), "g" (&b[0]), "g" (c), "g" (&d[0]) :
"edi", "ecx", "ebx", "eax", "edx", "esi");

#else
  borrow = 0;
  for (i = 0; i < digits; i++) {
        umul_ppmm(t1,t0,c,d[i]);
    if ((a[i] = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
      borrow = 1;
    else
      borrow = 0;
    if ((a[i] -= t0) > (MAX_NN_DIGIT - t0))
      borrow++;
    borrow += t1;
  }
#endif
#endif
  return (borrow);
}

/* Returns the significant length of a in bits, where a is a digit.
 */
static unsigned int NN_DigitBits (a)
NN_DIGIT a;
{
  unsigned int i;
  
  for (i = 0; i < NN_DIGIT_BITS; i++, a >>= 1)
    if (a == 0)
      break;
    
  return (i);
}
