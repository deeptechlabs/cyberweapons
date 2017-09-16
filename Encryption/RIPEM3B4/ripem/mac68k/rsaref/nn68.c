/* NN.C - natural numbers routines
 */

/* Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
   Security, Inc. All rights reserved.
   
   921017 rwo : recode all low-level routines into 680[234]0 asm
   		for use with Symantec THINK C V5.02.  Eliminated digit.c.
   930123 rwo : eliminate jsrs in NN_div and NN_mult, thus eliminating
		NN_digit_div, NN_SubDigitMult and NN_AddDigitMult.
   930624 rwo : copied over the mch NN_2ModExp() code.
   930825 rwo : unwound the addmult and submult loops, comments.
   940329 rwo : added mch's montgomery mult variations
   940528 rwo : added mch's mod2inv() code
 */

#include "global.h"
#include "rsaref.h"
#include "nn.h"

static unsigned int NN_DigitBits PROTO_LIST ((NN_DIGIT));

/* Decodes character string b into a, where character string is ordered
   from most to least significant.

   Length: a[digits], b[len].
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
  
  for (i = 0, j = len - 1; j >= 0; i++) {
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

  for (i = 0, j = len - 1; i < digits; i++) {
    t = b[i];
    for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
      a[j] = (unsigned char)(t >> u);
  }

  for (; j >= 0; j--)
    a[j] = 0;
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

/* Computes a = b * c.

   Lengths: a[2*digits], b[digits], c[digits].
   Assumes digits < MAX_NN_DIGITS.
   Assumes even alignment of b & c.
 */
void NN_Mult (a, b, c, digits)
NN_DIGIT *a, *b, *c;
unsigned int digits;
{
  NN_DIGIT t[2*MAX_NN_DIGITS], *tp;
  unsigned int bDigits, cDigits;

  NN_AssignZero (t, 2 * digits);
  
  bDigits = NN_Digits (b, digits);
  cDigits = NN_Digits (c, digits);
  tp = t;

asm 68030 {
		movem.l	d0-d6/a0-a1,-(a7)
		move.l	bDigits,d6
		beq.s	@nada
		move.l  cDigits,d1 		;assumes sizeof(int) == 4
		beq.s	@nada
		subq.w	#1,d6			;assumes bDigits <= 2**16
		moveq	#0,d5			;fixed zero
@call:	moveq	#0,d0			;zero carries
		moveq	#0,d3
		movea.l	b,a0
		move.l	(a0),d2			;multiplier
		beq.s	@mula0
		movea.l	tp,a0
		movea.l	c,a1
		move.l	cDigits,d1		;slight waste
		lsr.w	#1,d1			;divide by 2
		bcc.s	@mulev			;all set to go
		lsr.w	#1,d5			;zero X 1st
		jmp		@mulod			;do just one 1st
@mulap:	move.l  (a1)+,d4		;load next multiplicand
		mulu.l	d2,d3:d4		;64-bit multiply
		addx.l	d0,d4			;X = (mpcd * mplr) + carry + X
		addx.l	d5,d3			;catch and carry
		add.l	d4,(a0)+
@mulod:	move.l  (a1)+,d4		;load next multiplicand
		mulu.l	d2,d0:d4		;64-bit multiply
		addx.l	d3,d4			;X = (mpcd * mplr) + carry + X
		addx.l	d5,d0			;catch and carry
		add.l	d4,(a0)+		
@mulev:	dbf		d1,@mulap		;get it?
		addx.l	d5,d0			;catch last carry, if any
		add.l	d0,(a0)			;co-incidentally t[i+cDigits]!
@mula0: addq.l	#4,b
		addq.l	#4,tp
		dbf		d6,@call
@nada:	movem.l	(a7)+,d0-d6/a0-a1
		}
  
  NN_Assign (a, t, 2 * digits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
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

#ifdef USE_2MODEXP
/* Computes a = 2^c mod d.

   Lengths: a[dDigits], c[cDigits], d[dDigits].
   Assumes 2 < d, d > 0, cDigits > 0, dDigits > 0,
           dDigits < MAX_NN_DIGITS.
 */
void NN_2ModExp (a, c, cDigits, d, dDigits)
NN_DIGIT *a, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT ci, t[MAX_NN_DIGITS], bt[MAX_NN_DIGITS*2];
  int i;
  unsigned int ciBits, j, s;

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
      /* Compute t = t^4 * 2^s mod d, where s = two MSB's of d.
       */
      NN_ModMult (t, t, t, d, dDigits);
      NN_ModMult (t, t, t, d, dDigits);
      if (s = DIGIT_2MSB (ci)) {
      	bt[dDigits]=NN_LShift(bt,t,s,dDigits);
      	NN_Mod(t, bt, dDigits+1, d, dDigits);
    	}
    }
  }
  
  NN_Assign (a, t, dDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)t, 0, sizeof (t));
  R_memset ((POINTER)bt, 0, sizeof(NN_DIGIT)*2);
}
#endif

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

/* Computes a = c div d and b = c mod d.

   Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits < 2 * MAX_NN_DIGITS,
           dDigits < MAX_NN_DIGITS.
   Assumes even alignment of a, b, c & d.
 */
void NN_Div (a, b, c, cDigits, d, dDigits)
NN_DIGIT *a, *b, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT cc[2*MAX_NN_DIGITS+1], dd[MAX_NN_DIGITS];
  NN_DIGIT ai, t, *ccidd, *cci;
  int i;
  unsigned int ddDigits, shift;
  
  ddDigits = NN_Digits (d, dDigits);
  if (ddDigits == 0)
    return;
  
  /* Normalize operands.
   */
  shift = NN_DIGIT_BITS - NN_DigitBits (d[ddDigits-1]);
  NN_AssignZero (cc, ddDigits);
  ccidd = &cc[cDigits];
  *ccidd = NN_LShift (cc, c, shift, cDigits);
  NN_LShift (dd, d, shift, ddDigits);
  t = dd[ddDigits-1];
  
  NN_AssignZero (a, cDigits);
  
  if( (i = cDigits - ddDigits) >= 0 ) cci = &cc[i];

  while( i >= 0 ) {
  
asm 68030 {
		movem.l	d0-d6/a0-a1,-(a7)
		move.l	t,d0
		cmpi.l	#MAX_NN_DIGIT,d0
		bne.s	@nndd
		movea.l	cci,a0
		move.l	dDigits,d0		; assumes sizeof(int) == 4
		lsl.l	#2,d0
		adda.l	d0,a0
		move.l	(a0),d1
		bra.s	@nnsdm
@nndd:	addq.l	#1,d0
		movea.l	ccidd,a0
		move.l	-4(a0),d1
		move.l	(a0),d2
		divu.l	d0,d2:d1
@nnsdm:	move.l	d1,ai
		beq.s	@muls0
		moveq	#0,d0			; zero borrows
		moveq	#0,d3
		moveq	#0,d5			; fixed zero
		move.l  ddDigits,d2		; assumes sizeof(int) == 4
		movea.l	cci,a0
		lea		dd,a1
		lsr.w	#1,d2
		bcc.s	@mulev
		lsr.w	#1,d5			; zero X
		jmp		@mulod
@mulsp:	move.l  (a1)+,d4
		mulu.l	d1,d3:d4
		move.l	(a0),d6
		subx.l	d0,d6			; subtract last borrow, if any
		addx.l	d5,d3			; add any borrow to next 
		sub.l	d4,d6			; then subtract this subtend
		move.l	d6,(a0)+
@mulod:	move.l  (a1)+,d4
		mulu.l	d1,d0:d4
		move.l	(a0),d6
		subx.l	d3,d6
		addx.l	d5,d0
		sub.l	d4,d6
		move.l	d6,(a0)+
@mulev:	dbf		d2,@mulsp
		addx.l	d5,d0
		sub.l	d0,(a0)
@muls0:	movem.l	(a7)+,a0-a1/d0-d6
		}

    /* Correct estimate. */
    while( *ccidd || (NN_Cmp (cci, dd, ddDigits) >= 0) ) {
		ai++;
		*ccidd -= NN_Sub (cci, cci, dd, ddDigits);
		}
    
    a[i] = ai;
    i--;
    ccidd--;
    cci--;
	}
  
  /* Restore result. */
  NN_AssignZero (b, dDigits);
  NN_RShift (b, cc, shift, ddDigits);

  /* Zeroize potentially sensitive information. */
  R_memset ((POINTER)cc, 0, sizeof (cc));
  R_memset ((POINTER)dd, 0, sizeof (dd));
  return;
}

/* Returns nonzero iff a is zero.

   Lengths: a[digits].
   Assumes even alignment of a.
 */
int NN_Zero (NN_DIGIT *a, unsigned int digits) {
asm {
		move.l	digits,d0
		beq.s	@zero1
		movea.l	a,a0
		subq.w	#1,d0
@zero2:	move.l	(a0)+,d1
		bne.s	@zero0
		dbf		d0,@zero2
@zero1:	moveq	#1,d0
		bra.s	@zero3
@zero0:	moveq	#0,d0
		}
zero3: return;
}  

/* Assigns a = b.

   Lengths: a[digits], b[digits].
   Assumes even alignment of a & b.
 */
void NN_Assign (NN_DIGIT *a, NN_DIGIT *b, unsigned int digits) {
asm {
		move.l	digits,d0
		beq.s	@asn0
		subq.w	#1,d0
		movea.l	a,a0
		movea.l b,a1
@asn1:	move.l	(a1)+,(a0)+
		dbf		d0,@asn1
		}
asn0: return;
}

/* Assigns a = 0.

   Lengths: a[digits].
   Assumes even alignment of a.
 */
void NN_AssignZero (NN_DIGIT *a, unsigned int digits) {
asm {
		move.l	digits,d0
		beq.s	@asz0
		subq.w	#1,d0
		movea.l	a,a0
		moveq	#0,d1
@asz1:	move.l	d1,(a0)+
		dbf		d0,@asz1
		}
asz0: return;
}

/* Returns sign of a - b.

   Lengths: a[digits], b[digits].
   Assumes even alignment of a & b.   
 */
int NN_Cmp (NN_DIGIT *a, NN_DIGIT *b, unsigned int digits) {
asm {
		move.l	digits,d0
		beq.s	@cmp0
		move.l	d0,d1
		movea.l	a,a0
		movea.l	b,a1
		lsl.l	#2,d1
		adda.l	d1,a0
		adda.l	d1,a1
		subq.w	#1,d0
@cmp1:	move.l	-(a0),d1
		move.l	-(a1),d2
		cmp.l	d2,d1			; a ? b
		bhi.s	@cmpgt			; a > b
		bcs.s	@cmplt			; a < b
		dbf		d0,@cmp1
		moveq	#0,d0			; a == b
		bra.s	@cmp0
@cmpgt:	moveq	#1,d0
		bra.s	@cmp0
@cmplt:	moveq	#-1,d0
		}
cmp0: return;
}

/* Returns the significant length of a in digits.

   Lengths: a[digits].
   Assumes even alignment of a.
 */
unsigned int NN_Digits (NN_DIGIT *a, unsigned int digits) {
asm {
		move.l	digits,d0
		beq.s	@digs0
		move.l	d0,d1
		movea.l	a,a0
		lsl.l	#2,d1
		adda.l	d1,a0
		subq.w	#1,d0
@digs1:	move.l	-(a0),d1
		bne.s	@digs2
		dbf		d0,@digs1
@digs2:	addq.w	#1,d0
		}
digs0: return;
}

/* Returns the significant length of a in bits, where a is a digit.
 */
static unsigned int NN_DigitBits (NN_DIGIT a) {
asm 68030 {
		move.l	a,d0
		moveq	#0,d1
		bfffo	d0{d1:d1},d1	;wow, that was fun!
		moveq	#32,d0
		sub.l	d1,d0
		}
return;
}

/* Computes a = b + c. Returns carry.

   Lengths: a[digits], b[digits], c[digits].
   Assumes even alignment of a, b & c.
 */
NN_DIGIT NN_Add (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, \
					unsigned int digits) {
asm {
		moveq	#0,d0			;zero return
		move.l  digits,d1 		;# of units
		beq.s	@add0
		movem.l	d3/a2,-(a7)
		movea.l	a,a0
		movea.l	b,a1
		movea.l	c,a2
		subq.w  #1,d1			;one off (dbf counter)
@addlp:	move.l	(a1)+,d2
		move.l	(a2)+,d3
		addx.l	d2,d3
		move.l	d3,(a0)+
		dbf		d1,@addlp
		negx.w	d0
		neg.w	d0				;make carry arithmetic
		movem.l	(a7)+,d3/a2
		}
add0: return;
}

/* Computes a = b - c. Returns borrow.

   Lengths: a[digits], b[digits], c[digits].
   Assumes even alignment of a, b & c.  */
NN_DIGIT NN_Sub (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *c, \
					unsigned int digits) {
asm {
		moveq	#0,d0			;zero return
		move.l  digits,d1 		;# of units
		beq.s	@sub0
		movem.l	d3/a2,-(a7)
		movea.l	a,a0
		movea.l	b,a1
		movea.l	c,a2
		subq.w  #1,d1			;one off (dbf counter)
@sublp:	move.l	(a1)+,d2
		move.l	(a2)+,d3
		subx.l	d3,d2
		move.l	d2,(a0)+
		dbf		d1,@sublp
		negx.w	d0
		neg.w	d0				;make borrow arithmetic
		movem.l	(a7)+,d3/a2
		}
sub0: return;
}

/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires c < NN_DIGIT_BITS.
   Assumes even alligment of a & b.
 */
NN_DIGIT NN_LShift (NN_DIGIT *a, NN_DIGIT *b, \
					unsigned int c, unsigned int digits) {
asm {
		movem.l	d3-d5,-(a7)
		moveq	#0,d0
		move.l	c,d1
		moveq	#32,d2
		cmp.b	d2,d1
		bge.s	@lsf0			;V1.1
		move.l	digits,d3
		beq.s	@lsf0
		sub.b	d1,d2
		movea.l	a,a0
		movea.l	b,a1
		subq	#1,d3
		move.b	d1,d1			;anything to do?
		bne.s	@lsf1			;yup
@lsf2:	move.l	(a1)+,(a0)+		;nope
		dbf		d3,@lsf2
		bra.s	@lsf0
@lsf1:	move.l	(a1)+,d4
		move.l	d4,d5
		lsl.l	d1,d4
		or.l	d0,d4
		move.l	d4,(a0)+
		lsr.l	d2,d5
		move.l	d5,d0
		dbf		d3,@lsf1
@lsf0:	movem.l	(a7)+,d3-d5
		}
return;
}

/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires: c < NN_DIGIT_BITS.
   Assumes even alignment of a & b.
 */
NN_DIGIT NN_RShift (NN_DIGIT *a, NN_DIGIT *b, \
					unsigned int c, unsigned int digits) {
asm {
		movem.l	d3-d5,-(a7)
		moveq	#0,d0
		move.l	c,d1
		moveq	#32,d2
		cmp.b	d2,d1
		bge.s	@rsf0			;V1.1
		move.l	digits,d3
		beq.s	@rsf0
		sub.b	d1,d2
		movea.l	a,a0
		movea.l	b,a1
		move.l	d3,d4			;adjust for pre-decrementing
		lsl.l	#2,d4
		adda.l	d4,a0
		adda.l	d4,a1
		subq	#1,d3
		move.b	d1,d1			;anything to do?
		bne.s	@rsf1			;yup
@rsf2:	move.l	-(a1),-(a0)		;nope
		dbf		d3,@rsf2
		bra.s	@rsf0
@rsf1:	move.l	-(a1),d4
		move.l	d4,d5
		lsr.l	d1,d4
		or.l	d0,d4
		move.l	d4,-(a0)
		lsl.l	d2,d5
		move.l	d5,d0
		dbf		d3,@rsf1
@rsf0:	movem.l	(a7)+,d3-d5
		}
return;
}

#ifdef USE_MONT

/* montgomery product 
 * a = result
 * b,c = values to "multiply"
 * d = modulus
 * n = # of digits
 * v = -(1/d) mod 2^{NN_DIGIT_BITS} -- N.B.: this is a single digit
 * k = number of digits in d (don't count leading zeros)
 */

/* you can play with this number for performance.  */
#define NN_THRESH 5

static void monpro(NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, \
	unsigned int, NN_DIGIT, unsigned int);
static NN_DIGIT NN_AddDigitMult(NN_DIGIT *, NN_DIGIT *, NN_DIGIT, \
					NN_DIGIT *, unsigned int);
static NN_DIGIT NN_Mod2Inv(NN_DIGIT);

/* Computes a = b + c*d, where c is a digit. Returns carry.
   Lengths: a[digits], b[digits], d[digits]. */
static NN_DIGIT NN_AddDigitMult (NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT c, \
					NN_DIGIT *d, unsigned int digits) {
asm 68030 {
		movem.l	d3-d5/a2,-(a7)
		moveq	#0,d0			;zero carry
		move.l	c,d2			;multiplier
		beq.s	@mula0
		move.l  digits,d1 		;# of units
		beq.s	@mula0
		moveq	#0,d5			;fixed zero
		moveq	#0,d3			;zero carry
		movea.l	a,a0
		movea.l	d,a1
		movea.l	b,a2
		lsr.w	#1,d1			;divide by 2
		bcc.s	@mulev			;all set to go
		lsr.w	#1,d5			;zero X 1st
		jmp		@mulod			;do just one 1st
@mulap:	move.l  (a1)+,d4		;load next multiplicand
		mulu.l	d2,d3:d4		;64-bit multiply
		addx.l	d0,d4			;X = (mpcd * mplr) + carry + X
		addx.l	d5,d3			;catch and carry
		add.l	(a2)+,d4
		move.l	d4,(a0)+
@mulod:	move.l  (a1)+,d4		;load next multiplicand
		mulu.l	d2,d0:d4		;64-bit multiply
		addx.l	d3,d4			;X = (mpcd * mplr) + carry + X
		addx.l	d5,d0			;catch and carry
		add.l	(a2)+,d4
		move.l	d4,(a0)+
@mulev:	dbf		d1,@mulap		;get it?
		addx.l	d5,d0			;catch last carry, if any
@mula0:	movem.l	(a7)+,d3-d5/a2
		}
return;
}

/* operand scanning version */
static void monpro(a,b,c,d,n,v,k)
NN_DIGIT *a,*b,*c,*d; 
unsigned int k,n;
NN_DIGIT v;
{
    int i;
    NN_DIGIT cr;
    NN_DIGIT t[2 * MAX_NN_DIGITS + 1];
    NN_DIGIT u[MAX_NN_DIGITS + 1];
    NN_AssignZero(t,2*n+1);
    for (i=0; i < n; i++) {
        cr = t[i+n];;
        if ((cr +=  NN_AddDigitMult(&t[i],&t[i],b[i],c,n)) < t[i+n])
            t[i+n+1]++;  /* carry */
        t[i+n] = cr;
        if ((cr += NN_AddDigitMult(&t[i],&t[i],t[i]*v,d,n)) < t[i+n])
            t[i+n+1]++;  /* carry */
        t[i+n] = cr;
    }

    /* now shift right by k digits, i.e. divide by r=B^k */
    for (i=0; i <= n; i++)  /* N.B. u can have n+1 digits */
        u[i] = t[i + k]; 

    /* after subtracting (if necessary), we know u will have at most 
     *  n digits  
     */
    if (u[n] || NN_Cmp(u,d,n) >= 0) NN_Sub(a,u,d,n);
    else NN_Assign(a,u,n);
}

#if (NN_DIGIT_BITS == 32) 
/* 
 * calculate -(1/y) mod (2^NN_DIGIT_BITS)
 * thanks to Colin Plumb <colin@nyx10.cs.du.edu> for a cool way to do this
 * computation. It could be extended to arbitrary NN_DIGIT_BITS, but it
 * turns out that there isn't much point
 */
static NN_DIGIT NN_Mod2Inv(xx)
NN_DIGIT xx;
{
asm 68030 {
	move.l	d3,-(a7)
	move.l	xx,d3
	move.l	d3,d0
	move.l	d0,d1
	move.l	d0,d2
	mulu.l	d0,d2
	mulu.l	d3,d2
	sub.l	d2,d1
	add.l	d1,d0
	move.l	d0,d1
	move.l	d0,d2
	mulu.l	d0,d2
	mulu.l	d3,d2
	sub.l	d2,d1
	add.l	d1,d0
	move.l	d0,d1
	move.l	d0,d2
	mulu.l	d0,d2
	mulu.l	d3,d2
	sub.l	d2,d1
	add.l	d1,d0
	move.l	d0,d1
	move.l	d0,d2
	mulu.l	d0,d2
	mulu.l	d3,d2
	sub.l	d2,d1
	add.l	d1,d0
 	neg.l	d0
	move.l	(a7)+,d3
	}
return;
}
 
#else

/* 
 * calculate -(1/x) mod (2^NN_DIGIT_BITS)
 * see Dusse, Kaliski: A Cryptographic Library for the Motorola DSP56000
 *  in the Eurocrypt 90 proceedings. Clever, simple and fast.
 */
static NN_DIGIT NN_Mod2Inv(xx)
NN_DIGIT xx;
{
    unsigned int i;
    NN_DIGIT v = 1;

    /* work up to NN_DIGIT_BITS */
    for (i=2; i < NN_DIGIT_BITS; i++)  {
        if (( (xx * v) % (1 << i)) != 1) v |= 1 << (i - 1);
        /* LOOP INVARIANT: ((xx * v) % (1<<i) == 1) */
    }

    /* last bit */
    if ((xx * v) != 1) v |= (1<<(NN_DIGIT_BITS -1));

    return((MAX_NN_DIGIT - v) + 1);
}
#endif
/* NN_DIGIT_BITS == 32 */

/* x = a^c mod n, n must be odd */
static void NN_MontModExp(x,a,c,cDigits,n,nDigits) 
  NN_DIGIT *x, *a, *c, *n;
  unsigned int nDigits, cDigits;
{
  int k,i;
  NN_DIGIT v;
  NN_DIGIT r[MAX_NN_DIGITS + 1];
  NN_DIGIT t1[2*MAX_NN_DIGITS + 1];
  NN_DIGIT a1[MAX_NN_DIGITS + 1];
  NN_DIGIT one[MAX_NN_DIGITS];
  NN_DIGIT aPower[15][MAX_NN_DIGITS], ci, t[MAX_NN_DIGITS];
  unsigned int ciBits, j, s;

  NN_AssignZero(one,nDigits);
  one[0] = 1;

  k = NN_Digits(n,nDigits);
  NN_AssignZero(r,k+1);
  r[k] = 1;   /* r = B^k, where B=2^{NN_DIGIT_BITS} */

  /* v = -(1/n) mod B */
  v = NN_Mod2Inv(n[0]);
  
  /* a1 = a*r mod n */
  NN_AssignZero(t1,2*k+1);
  for (i = 0; i < k; i++) t1[i+k] = a[i];
  NN_Mod(a1,t1,2*k+1,n,nDigits);

  /* t = r mod n */
  NN_Mod(t,r,k+1,n,nDigits);

  cDigits = NN_Digits (c, cDigits);
  if (cDigits < NN_THRESH) {   /* take bits of exponent two at a time */
        NN_Assign (aPower[0], a1, k);
        monpro (aPower[1], aPower[0], a1, n, k, v, k);
        monpro (aPower[2], aPower[1], a1, n, k, v, k);
        
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
                monpro (t, t, t, n, k, v, k);
                monpro (t, t, t, n, k, v, k);
                if (s = DIGIT_2MSB (ci))
                    monpro (t, t, aPower[s-1], n, k, v, k);
            }
        }
    }
    else { /* process exponent nibble by nibble */

        /* precompute */
        NN_Assign (aPower[0], a1, nDigits);
        monpro (aPower[1], aPower[0], a1, n, k, v, k);   
        monpro (aPower[2], aPower[1], a1, n, k, v, k);  
        monpro (aPower[3], aPower[2], a1, n, k, v, k);   
        monpro (aPower[4], aPower[3], a1, n, k, v, k);  
        monpro (aPower[5], aPower[4], a1, n, k, v, k); 
        monpro (aPower[6], aPower[5], a1, n, k, v, k);
        monpro (aPower[7], aPower[6], a1, n, k, v, k);
        monpro (aPower[8], aPower[7], a1, n, k, v, k);  
        monpro (aPower[9], aPower[8], a1, n, k, v, k);   
        monpro (aPower[10], aPower[9], a1, n, k, v, k);  
        monpro (aPower[11], aPower[10], a1, n, k, v, k); 
        monpro (aPower[12], aPower[11], a1, n, k, v, k); 
        monpro (aPower[13], aPower[12], a1, n, k, v, k); 
        monpro (aPower[14], aPower[13], a1, n, k, v, k); 
        
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
                monpro(t,t,t,n,k,v,k);
                monpro(t,t,t,n,k,v,k);
                monpro(t,t,t,n,k,v,k);
                monpro(t,t,t,n,k,v,k);
                if (s = DIGIT_4MSB (ci))
                    monpro (t, t, aPower[s-1], n, k, v, k);
            }
        }
    }
  NN_AssignZero(x,nDigits); 
  monpro(x,t,one,n,k,v,k);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)aPower, 0, sizeof (aPower));
  R_memset ((POINTER)t, 0, sizeof (t));
}

#endif
/* USE_MONT */

/* Computes a = b^c mod d.

   Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes b < d, d > 0, cDigits > 0, dDigits > 0,
           dDigits < MAX_NN_DIGITS.
 */
void NN_ModExp (a, b, c, cDigits, d, dDigits)
NN_DIGIT *a, *b, *c, *d;
unsigned int cDigits, dDigits;
{
  NN_DIGIT bPower[3][MAX_NN_DIGITS], ci, t[MAX_NN_DIGITS];
  int i;
  unsigned int ciBits, j, s;

#ifdef USE_MONT
  /* if d is odd we use Montgomery multiplication 
   * -- for RSA d is always odd.
   */
  if (d[0] & 0x01) {
	 NN_MontModExp(a,b,c,cDigits,d,dDigits);
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
      /* Compute t = t^4 * b^s mod d, where s = two MSB's of d.
       */
      NN_ModMult (t, t, t, d, dDigits);
      NN_ModMult (t, t, t, d, dDigits);
      if (s = DIGIT_2MSB (ci))
        NN_ModMult (t, t, bPower[s-1], d, dDigits);
    }
  }
  
  NN_Assign (a, t, dDigits);
  
  /* Zeroize potentially sensitive information.
   */
  R_memset ((POINTER)bPower, 0, sizeof (bPower));
  R_memset ((POINTER)t, 0, sizeof (t));
}

/************ end nn.c V1.8 940531 00:35 rwo @Walmer ******************/
