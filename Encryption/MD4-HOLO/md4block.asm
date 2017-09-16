;*--------------------------------------------------------------------------*
;* (C) Copyright 1990, RSA Data Security, Inc.  All rights reserved.        *
;* License to copy and use this software is granted provided it is          *
;* identified as the "RSA Data Security, Inc. MD4 message digest algorithm" *
;* in all material mentioning or referencing this software or function.     *
;*                                                                          *
;* License is also granted to make and use derivative works provided such   *
;* works are identified as "derived from the RSA Data Securitry, Inc. MD4   *
;* message digest algorithm" in all material mentioning or referencing the  *
;* derived work.                                                            *
;*                                                                          *
;* RSA Data Security, Inc. makes no representations concerning the          *
;* merchantability of this software or the suitability of the software      *
;* for any particular purpose.  It is provided "as is" without express      *
;* or implied warranty of any kind.                                         *
;*                                                                          *
;* These notices must be retained in any copies of any part of this         *
;* documentation and/or software.                                           *
;*--------------------------------------------------------------------------*
;** ********************************************************************
;** md4.c -- Implementation of MD4 Message Digest Algorithm           **
;** Updated: 1991.12.12 Jouko Holopainen                              **
;** (C) 1990 RSA Data Security, Inc.                                  **
;** ********************************************************************

	TITLE   md4block

_TEXT	SEGMENT  BYTE PUBLIC 'CODE'
_TEXT	ENDS
_DATA	SEGMENT  WORD PUBLIC 'DATA'
_DATA	ENDS
CONST	SEGMENT  WORD PUBLIC 'CONST'
CONST	ENDS
_BSS	SEGMENT  WORD PUBLIC 'BSS'
_BSS	ENDS

DGROUP	GROUP	CONST,	_BSS,	_DATA
	ASSUME  CS: _TEXT, DS: DGROUP, SS: DGROUP, ES: DGROUP

_BSS      SEGMENT
$S26_A	DW 02H DUP (?)
$S27_B	DW 02H DUP (?)
$S28_C	DW 02H DUP (?)
$S29_D	DW 02H DUP (?)
_BSS      ENDS

_TEXT      SEGMENT

ROTLL	MACRO		; rotate left (circular) long
	shl	ax,1
	rcl	dx,1
	adc	al,0
	ENDM

ROTRL	MACRO		; rotate right (circular) long
	LOCAL	.ff
	shr	dx,1
	rcr	ax,1
	jnc	.ff
	or	dh,80h
.ff:
	ENDM

;|*** #include "md4.h"
;|***
;|*** #define C2  013240474631     /* round 2 constant = sqrt(2) in octal */
;|*** #define C3  015666365641     /* round 3 constant = sqrt(3) in octal */
;|*** /* C2 and C3 are from Knuth, The Art of Programming, Volume 2
;|*** ** (Seminumerical Algorithms), Second Edition (1981), Addison-Wesley.
;|*** ** Table 2, page 660.
;|*** */
;|***
;|*** #define fs1  3               /* round 1 shift amounts */
;|*** #define fs2  7
;|*** #define fs3 11
;|*** #define fs4 19
;|*** #define gs1  3               /* round 2 shift amounts */
;|*** #define gs2  5
;|*** #define gs3  9
;|*** #define gs4 13
;|*** #define hs1  3               /* round 3 shift amounts */
;|*** #define hs2  9
;|*** #define hs3 11
;|*** #define hs4 15
;|***
;|*** /* Compile-time macro declarations for MD4.
;|*** ** Note: The "rot" operator uses the variable "tmp".
;|*** ** It assumes tmp is declared as unsigned int, so that the >>
;|*** ** operator will shift in zeros rather than extending the sign bit.
;|*** */
;|*** #define f(X,Y,Z)             ((X&Y) | ((~X)&Z))
;|*** #define g(X,Y,Z)             ((X&Y) | (X&Z) | (Y&Z))
;|*** #define h(X,Y,Z)             (X^Y^Z)
;|*** #define rot(X,S)             (tmp=X,(tmp<<S) | (tmp>>(32-S)))
;|*** #define ff(A,B,C,D,i,s)      A = rot((A + f(B,C,D) + X[i]),s)
;|*** #define gg(A,B,C,D,i,s)      A = rot((A + g(B,C,D) + X[i] + C2),s)
;|*** #define hh(A,B,C,D,i,s)      A = rot((A + h(B,C,D) + X[i] + C3),s)
;|***
;|*** /* MDblock(MDp,X)
;|*** ** Update message digest buffer MDp->buffer using 16-word data block X.
;|*** ** Assumes all 16 words of X are full of data.
;|*** ** Does not update MDp->count.
;|*** ** This routine is not user-callable.
;|*** */
;|*** void MDblock(MDp,X)
	PUBLIC	_MDblock
_MDblock	PROC NEAR
	push	bp
	mov	bp,sp
	push	di
	push	si
;|*** MDptr MDp;
;|*** WORD *X;
;|*** {
;	MDp = 4
;	X = 6
;|***   static WORD A, B, C, D;
;|***
;|***   A = MDp->buffer[0];
	mov	bx,[bp+4]	;MDp
	mov	ax,[bx]
	mov	dx,[bx+2]
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   C = MDp->buffer[2];
	mov	ax,[bx+8]
	mov	dx,[bx+10]
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   D = MDp->buffer[3];
	mov	ax,[bx+12]
	mov	dx,[bx+14]
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   B = MDp->buffer[1];
	mov	ax,[bx+4]
	mov	dx,[bx+6]
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   /* Update the message digest buffer */
;|***   ff(A , B , C , D ,  0 , fs1); /* Round 1 */
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	mov	bx,[bp+6]	;X
	add	ax,[bx]
	adc	dx,[bx+2]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   ff(D , A , B , C ,  1 , fs2);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+4]
	adc	dx,[bx+6]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTRL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   ff(C , D , A , B ,  2 , fs3);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+8]
	adc	dx,[bx+10]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   ff(B , C , D , A ,  3 , fs4);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+12]
	adc	dx,[bx+14]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	xchg	ax,dx
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   ff(A , B , C , D ,  4 , fs1);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+16]
	adc	dx,[bx+18]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   ff(D , A , B , C ,  5 , fs2);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+20]
	adc	dx,[bx+22]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTRL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   ff(C , D , A , B ,  6 , fs3);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+24]
	adc	dx,[bx+26]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   ff(B , C , D , A ,  7 , fs4);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+28]
	adc	dx,[bx+30]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	xchg	ax,dx
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   ff(A , B , C , D ,  8 , fs1);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+32]
	adc	dx,[bx+34]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   ff(D , A , B , C ,  9 , fs2);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+36]
	adc	dx,[bx+38]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTRL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   ff(C , D , A , B , 10 , fs3);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+40]
	adc	dx,[bx+42]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   ff(B , C , D , A , 11 , fs4);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+44]
	adc	dx,[bx+46]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	xchg	ax,dx
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   ff(A , B , C , D , 12 , fs1);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+48]
	adc	dx,[bx+50]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   ff(D , A , B , C , 13 , fs2);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+52]
	adc	dx,[bx+54]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTRL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   ff(C , D , A , B , 14 , fs3);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+56]
	adc	dx,[bx+58]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   ff(B , C , D , A , 15 , fs4);
	mov	cx,ax
	mov	di,dx
	not	ax
	not	dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+60]
	adc	dx,[bx+62]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	xchg	ax,dx
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   gg(A , B , C , D ,  0 , gs1); /* Round 2 */
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S28_C
	mov	di,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx]
	adc	dx,[bx+2]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   gg(D , A , B , C ,  4 , gs2);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S27_B
	mov	di,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+16]
	adc	dx,[bx+18]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   gg(C , D , A , B ,  8 , gs3);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S26_A
	mov	di,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+32]
	adc	dx,[bx+34]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,31129
	adc	dx,23170
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   gg(B , C , D , A , 12 , gs4);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S29_D
	mov	di,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+48]
	adc	dx,[bx+50]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,31129
	adc	dx,23170
	xchg	ax,dx
	ROTRL
	ROTRL
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   gg(A , B , C , D ,  1 , gs1);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S28_C
	mov	di,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+4]
	adc	dx,[bx+6]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   gg(D , A , B , C ,  5 , gs2);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S27_B
	mov	di,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+20]
	adc	dx,[bx+22]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   gg(C , D , A , B ,  9 , gs3);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S26_A
	mov	di,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+36]
	adc	dx,[bx+38]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,31129
	adc	dx,23170
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   gg(B , C , D , A , 13 , gs4);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S29_D
	mov	di,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+52]
	adc	dx,[bx+54]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,31129
	adc	dx,23170
	xchg	ax,dx
	ROTRL
	ROTRL
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   gg(A , B , C , D ,  2 , gs1);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S28_C
	mov	di,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+8]
	adc	dx,[bx+10]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   gg(D , A , B , C ,  6 , gs2);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S27_B
	mov	di,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+24]
	adc	dx,[bx+26]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   gg(C , D , A , B , 10 , gs3);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S26_A
	mov	di,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+40]
	adc	dx,[bx+42]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,31129
	adc	dx,23170
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   gg(B , C , D , A , 14 , gs4);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S29_D
	mov	di,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+56]
	adc	dx,[bx+58]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,31129
	adc	dx,23170
	xchg	ax,dx
	ROTRL
	ROTRL
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   gg(A , B , C , D ,  3 , gs1);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S28_C
	and	dx,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S28_C
	mov	di,WORD PTR $S28_C+2
	and	cx,WORD PTR $S29_D
	and	di,WORD PTR $S29_D+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+12]
	adc	dx,[bx+14]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   gg(D , A , B , C ,  7 , gs2);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S27_B
	and	dx,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S27_B
	mov	di,WORD PTR $S27_B+2
	and	cx,WORD PTR $S28_C
	and	di,WORD PTR $S28_C+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+28]
	adc	dx,[bx+30]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,31129
	adc	dx,23170
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   gg(C , D , A , B , 11 , gs3);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S26_A
	and	dx,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S26_A
	mov	di,si
	and	cx,WORD PTR $S27_B
	and	di,WORD PTR $S27_B+2
	or	ax,cx
	or	dx,di
	add	ax,[bx+44]
	adc	dx,[bx+46]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,31129
	adc	dx,23170
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   gg(B , C , D , A , 15 , gs4);
	mov	cx,ax
	mov	di,dx
	and	ax,WORD PTR $S29_D
	and	dx,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	mov	cx,WORD PTR $S29_D
	mov	di,WORD PTR $S29_D+2
	and	cx,WORD PTR $S26_A
	and	di,si
	or	ax,cx
	or	dx,di
	add	ax,[bx+60]
	adc	dx,[bx+62]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,31129
	adc	dx,23170
	xchg	ax,dx
	ROTRL
	ROTRL
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   hh(A , B , C , D ,  0 , hs1); /* Round 3 */
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	add	ax,[bx]
	adc	dx,[bx+2]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,-5215
	adc	dx,28377
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   hh(D , A , B , C ,  8 , hs2);
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	add	ax,[bx+32]
	adc	dx,[bx+34]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   hh(C , D , A , B ,  4 , hs3);
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	add	ax,[bx+16]
	adc	dx,[bx+18]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   hh(B , C , D , A , 12 , hs4);
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	add	ax,[bx+48]
	adc	dx,[bx+50]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,-5215
	adc	dx,28377
	xchg	ax,dx
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   hh(A , B , C , D ,  2 , hs1);
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	add	ax,[bx+8]
	adc	dx,[bx+10]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,-5215
	adc	dx,28377
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   hh(D , A , B , C , 10 , hs2);
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	add	ax,[bx+40]
	adc	dx,[bx+42]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   hh(C , D , A , B ,  6 , hs3);
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	add	ax,[bx+24]
	adc	dx,[bx+26]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   hh(B , C , D , A , 14 , hs4);
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	add	ax,[bx+56]
	adc	dx,[bx+58]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,-5215
	adc	dx,28377
	xchg	ax,dx
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   hh(A , B , C , D ,  1 , hs1);
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	add	ax,[bx+4]
	adc	dx,[bx+6]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,-5215
	adc	dx,28377
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   hh(D , A , B , C ,  9 , hs2);
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	add	ax,[bx+36]
	adc	dx,[bx+38]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   hh(C , D , A , B ,  5 , hs3);
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	add	ax,[bx+20]
	adc	dx,[bx+22]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   hh(B , C , D , A , 13 , hs4);
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	add	ax,[bx+52]
	adc	dx,[bx+54]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,-5215
	adc	dx,28377
	xchg	ax,dx
	ROTRL
	mov	WORD PTR $S27_B,ax
	mov	WORD PTR $S27_B+2,dx
;|***   hh(A , B , C , D ,  3 , hs1);
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	add	ax,[bx+12]
	adc	dx,[bx+14]
	add	ax,WORD PTR $S26_A
	adc	dx,si
	add	ax,-5215
	adc	dx,28377
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S26_A,ax
	mov	si,dx
;|***   hh(D , A , B , C , 11 , hs2);
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	xor	ax,WORD PTR $S28_C
	xor	dx,WORD PTR $S28_C+2
	add	ax,[bx+44]
	adc	dx,[bx+46]
	add	ax,WORD PTR $S29_D
	adc	dx,WORD PTR $S29_D+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	mov	WORD PTR $S29_D,ax
	mov	WORD PTR $S29_D+2,dx
;|***   hh(C , D , A , B ,  7 , hs3);
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	xor	ax,WORD PTR $S27_B
	xor	dx,WORD PTR $S27_B+2
	add	ax,[bx+28]
	adc	dx,[bx+30]
	add	ax,WORD PTR $S28_C
	adc	dx,WORD PTR $S28_C+2
	add	ax,-5215
	adc	dx,28377
	xchg	dh,dl
	xchg	dl,ah
	xchg	ah,al
	ROTLL
	ROTLL
	ROTLL
	mov	WORD PTR $S28_C,ax
	mov	WORD PTR $S28_C+2,dx
;|***   hh(B , C , D , A , 15 , hs4);
	xor	ax,WORD PTR $S29_D
	xor	dx,WORD PTR $S29_D+2
	xor	ax,WORD PTR $S26_A
	xor	dx,si
	add	ax,[bx+60]
	adc	dx,[bx+62]
	add	ax,WORD PTR $S27_B
	adc	dx,WORD PTR $S27_B+2
	add	ax,-5215
	adc	dx,28377
	xchg	ax,dx
	ROTRL
;|***   MDp->buffer[1] += B;
	mov	bx,[bp+4]	;MDp
	add	[bx+4],ax
	adc	[bx+6],dx
;|***   MDp->buffer[0] += A;
	mov	ax,WORD PTR $S26_A
	mov	dx,si
	add	[bx],ax
	adc	[bx+2],dx
;|***   MDp->buffer[2] += C;
	mov	ax,WORD PTR $S28_C
	mov	dx,WORD PTR $S28_C+2
	add	[bx+8],ax
	adc	[bx+10],dx
;|***   MDp->buffer[3] += D;
	mov	ax,WORD PTR $S29_D
	mov	dx,WORD PTR $S29_D+2
	add	[bx+12],ax
	adc	[bx+14],dx
;|*** }
$EX24:	pop	si
	pop	di
	pop	bp
	ret	
_MDblock	ENDP

_TEXT	ENDS
	END
