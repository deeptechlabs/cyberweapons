/* R_STDLIB.C - platform-specific C library routines for RSAREF
 */

/*	Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
	Security, Inc. All rights reserved.

	930124 rwo - Recoded these routines into 68000 asm for THINKC.
	930126 rwo - Special-case R_memset(a,0,b).
	930127 rwo - General-case R_memset(a,x,b).
 */

#include "global.h"
#include "rsaref.h"
#include <string.h>

void R_memset ( POINTER output, int value, size_t len ) {
asm {
		move.l	len,d1
		beq.s	@nada
		movea.l	output,a0
		move.l	value,d2	; assumes sizeof(int) == 4
		beq.s	@zero
		move.b	d2,d0
		lsl.w	#8,d0
		move.b	d2,d0
		move.w	d0,d2
		swap	d2
		move.w	d0,d2
@zero:	move.w	a0,d0
		and.w	#1,d0
		beq.s	@alin
		subq.l	#1,d1
		move.b	d2,(a0)+
@alin:	move.w	d1,d0
		lsr.l	#2,d1
		bra.s	@lp2
@l4:	swap	d1
@l3:	move.l	d2,(a0)+
@lp2:	dbf		d1,@l3
		swap	d1
		dbf		d1,@l4
		and.w	#3,d0
		beq.s	@nada
		lsl.w	#1,d0
		neg.w	d0
		jmp		@nada(d0.w)
		move.b	d2,(a0)+
		move.b	d2,(a0)+
		move.b	d2,(a0)+
		}
nada: return;
}

void R_memcpy ( POINTER output, POINTER input, size_t len ) {
asm {
		move.l	len,d1
		beq.s	@nada
		movea.l	output,a0
		movea.l	input,a1
		bra.s	@loop
@l2:	swap	d1
@l1:	move.b	(a1)+,(a0)+
@loop:	dbf		d1,@l1
		swap	d1
		dbf		d1,@l2
		}
nada: return;
}

int R_memcmp ( POINTER firstB, POINTER secondB, size_t len ) {
asm {
		moveq	#0,d0
		move.l	len,d1
		beq.s	@fin
		movea.l	firstB,a0
		movea.l	secondB,a1
		bra.s	@loop
@l2:	swap	d1
@l1:	cmpm.b	(a0)+,(a1)+
		bne.s	@l4
@loop:	dbf		d1,@l1
		swap	d1
		dbf		d1,@l2
		bra.s	@fin
@l4:	blo.s	@l3
		subq.l	#2,d0
@l3:	addq.l	#1,d0
		}
fin: return;
}

/******** end **********/
