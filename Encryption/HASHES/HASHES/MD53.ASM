; This code performs the core operation that computes the MD5 
; message digest of a bunch of longwords.  MD5 is defined over
; longwords; when it must be performed over smaller units (bytes
; or bits), they are packed into longwords little-endian.
; The byteReverse function swaps the bytes around in a buffer of
; longwords for this purpose.

; You start with a 4-long buffer initialized to the magic values
; $67452301, $efcdab89, $98badcfe, $10325476
; And then, for each 16-longword chunk of input, the Transform()
; function is called, which alters the 4-longword buffer in-place
; based on the next 16 longwords of input.
; 
; At the end of the input, it is padded with a 1 bit, and then as
; many 0 bits as are needed to come 2 longwords short of a full
; 16-longword chunk.  The last two longwords are a 64-bit count of the
; number of bits in the input, exclusive of padding, least signficant
; longword first.
;
; After that trailer has been fed through Transform(), the contents
; of the buffer are the MD5 checksum.  If they must be expressed as bytes,
; they should be presented in little-endian order.

; Byte-swap a buffer full of longs

	xdef	_byteReverse
_byteReverse:
; args: buf, longs
	move.l	4(sp),a0	; Buf
	move.w	10(sp),d0	; Longs
	subq.w	#1,d0		; We assume this is never 0 to start with
revloop:
	move.l	(a0),d1
	ror.w	#8,d1
	swap	d1
	ror.w	#8,d1
	move.l	d1,(a0)+

	dbra	d0,revloop
	
	rts

; Macros needed by the MD5 transformation code

; rotl	r1,bits - rotate register r1 left the given number of bits
rotl	macro	; args: reg, bits
    ifeq \2	; = 0
	mexit
    endc
    ifle \2-8	; <= 8
	rol.l	#\2,\1
	mexit
    endc
    ifge \2-24	; >= 24
	ror.l	#32-\2,\1
	mexit
    endc
	swap	\1
    iflt \2-16	; < 16
	ror.l	#16-\2,\1
	mexit
    endc
    ifgt \2-16	; > 16
	rol.l	#\2-16,\1
	mexit
    endc
	endm
; Cycles taken:
;  0 -  0   4 - 16   8 - 24  12 - 20  16 -  4  20 - 20  24 - 24  28 - 16
;  1 - 10   5 - 18   9 - 26  13 - 18  17 - 14  21 - 22  25 - 22  29 - 14
;  2 - 12   6 - 20  10 - 24  14 - 16  18 - 16  22 - 24  26 - 20  30 - 12
;  3 - 14   7 - 22  11 - 22  15 - 14  19 - 18  23 - 26  27 - 18  31 - 10
; MD5 uses 4 rotations each in the amounts 4, 5, 6, 7, 9, 10, 11, 12,
; 14, 15, 16, 17, 20, 21, 22, 23.  The total timing for each of
; those is 16+18+20+22 + 26+24+22+20 + 16+14+4+14 + 20+22+24+26 cycles,
; 4*19 + 4*23 + 4*12 + 4*23 = 4 * 77 = 308 cycles, or 1232 for the 4.

; Macros to compute the four boolean functions used in MD5
; Each one takes three arguments (x, y, z) and returns a result in d0.

f1	macro	; d0 = (x & y) | (~x & z)
	move.l	\3,d0
	eor.l	\2,d0
	and.l	\1,d0
	eor.l	\3,d0
	endm	; 4+8+8+8 = 28 cycles

f2	macro	; d0 = (x & z) | (x & ~z)
	f1 \3,\1,\2
	endm	; 28 cycles

f3	macro	; d0 = x ^ y ^ z
	move.l	\1,d0
	eor.l	\2,d0
	eor.l	\3,d0
	endm	; 4+8+8 = 20 cycles

f4	macro	; d0 = y ^ (x | ~z)
	move.l	\3,d0
	not.l	d0
	or.l	\1,d0
	eor.l	\2,d0
	endm	; 4+6+8+8 = 26 cycles

; The total time for these steps is 16 times (28+28+20+26) = 16 * 102 = 1632
; cycles.

; The basic step in the MD5 computation
; Note that the current code does not use the constant argument,
; getitng it from a table instead.  The constants have been left in
; the source because it's a real pain in the ass to type them all
; in correctly if changing this macro ever becomes a good idea.

md5step	macro	; args: f, w, x, y, z, const, input, shift
	\1	\3,\4,\5	; f(x, y, z) in d0
	add.l	(a0)+,d0
	add.l	\7,d0
	add.l	d0,\2	; w += f(x, y, z) + const + input
	rotl	\2,\8	; w = ROTL(w, shift)
	add.l	\3,\2	; w += x
	endm	; f + 14 + 6 + data + 8 + rot + 8 = 36 + f + data + rot cycles
; In most cases, the data cost is 12 cycles (long with 16-bit offset);
; values will be subtracted below where it's less.
; So that's a total of 48 cycles, times 64 is 3072 cycles.

; Okay, the actual code (finally):

	xdef	_Transform2
_Transform2:
; args: uint32 buf[4], uint32 in[16]
	move.l	4(sp),a0	; buf	 16
	move.l	8(sp),a1	; in	 16  32
	movem.l	d2-d4,-(sp)	;	 32  64

	movem.l	(a0),d1-d4	;	 44 108
	lea	md5table(pc),a0	;	  8 116

	md5step	f1,d1,d2,d3,d4,$d76aa478,(a1)+,7
	md5step	f1,d4,d1,d2,d3,$e8c7b756,(a1)+,12
	md5step	f1,d3,d4,d1,d2,$242070db,(a1)+,17
	md5step	f1,d2,d3,d4,d1,$c1bdceee,(a1)+,22
	md5step	f1,d1,d2,d3,d4,$f57c0faf,(a1)+,7
	md5step	f1,d4,d1,d2,d3,$4787c62a,(a1)+,12
	md5step	f1,d3,d4,d1,d2,$a8304613,(a1)+,17
	md5step	f1,d2,d3,d4,d1,$fd469501,(a1)+,22
	md5step	f1,d1,d2,d3,d4,$698098d8,(a1)+,7
	md5step	f1,d4,d1,d2,d3,$8b44f7af,(a1)+,12
	md5step	f1,d3,d4,d1,d2,$ffff5bb1,(a1)+,17
	md5step	f1,d2,d3,d4,d1,$895cd7be,(a1)+,22
	md5step	f1,d1,d2,d3,d4,$6b901122,(a1)+,7
	md5step	f1,d4,d1,d2,d3,$fd987193,(a1)+,12
	md5step	f1,d3,d4,d1,d2,$a679438e,(a1)+,17
	md5step	f1,d2,d3,d4,d1,$49b40821,(a1),22
; Subtract 4*16 = 64 cycles for no offsets

	md5step	f2,d1,d2,d3,d4,$f61e2562,4*1-60(a1),5
	md5step	f2,d4,d1,d2,d3,$c040b340,4*6-60(a1),9
	md5step	f2,d3,d4,d1,d2,$265e5a51,4*11-60(a1),14
	md5step	f2,d2,d3,d4,d1,$e9b6c7aa,4*0-60(a1),20
	md5step	f2,d1,d2,d3,d4,$d62f105d,4*5-60(a1),5
	md5step	f2,d4,d1,d2,d3,$02441453,4*10-60(a1),9
	md5step	f2,d3,d4,d1,d2,$d8a1e681,(a1),14
	md5step	f2,d2,d3,d4,d1,$e7d3fbc8,4*4-60(a1),20
	md5step	f2,d1,d2,d3,d4,$21e1cde6,4*9-60(a1),5
	md5step	f2,d4,d1,d2,d3,$c33707d6,-(a1),9
	md5step	f2,d3,d4,d1,d2,$f4d50d87,4*3-56(a1),14
	md5step	f2,d2,d3,d4,d1,$455a14ed,4*8-56(a1),20
	md5step	f2,d1,d2,d3,d4,$a9e3e905,-(a1),5
	md5step	f2,d4,d1,d2,d3,$fcefa3f8,4*2-52(a1),9
	md5step	f2,d3,d4,d1,d2,$676f02d9,4*7-52(a1),14
	md5step	f2,d2,d3,d4,d1,$8d2a4c8a,-(a1),20
; Subtract 4+6 = 10 cycles for no offsets

	md5step	f3,d1,d2,d3,d4,$fffa3942,4*5-48(a1),4
	md5step	f3,d4,d1,d2,d3,$8771f681,4*8-48(a1),11
	md5step	f3,d3,d4,d1,d2,$6d9d6122,-(a1),16
	md5step	f3,d2,d3,d4,d1,$fde5380c,4*14-44(a1),23
	md5step	f3,d1,d2,d3,d4,$a4beea44,4*1-44(a1),4
	md5step	f3,d4,d1,d2,d3,$4bdecfa9,4*4-44(a1),11
	md5step	f3,d3,d4,d1,d2,$f6bb4b60,4*7-44(a1),16
	md5step	f3,d2,d3,d4,d1,$bebfbc70,-(a1),23
	md5step	f3,d1,d2,d3,d4,$289b7ec6,4*13-40(a1),4
	md5step	f3,d4,d1,d2,d3,$eaa127fa,4*0-40(a1),11
	md5step	f3,d3,d4,d1,d2,$d4ef3085,4*3-40(a1),16
	md5step	f3,d2,d3,d4,d1,$04881d05,4*6-40(a1),23
	md5step	f3,d1,d2,d3,d4,$d9d4d039,4*9-40(a1),4
	md5step	f3,d4,d1,d2,d3,$e6db99e5,4*12-40(a1),11
	md5step	f3,d3,d4,d1,d2,$1fa27cf8,4*15-40(a1),16
	md5step	f3,d2,d3,d4,d1,$c4ac5665,4*2-40(a1),23
; subtract 4 cycles for no offsets

	md5step	f4,d1,d2,d3,d4,$f4292244,4*0-40(a1),6
	md5step	f4,d4,d1,d2,d3,$432aff97,4*7-40(a1),10
	md5step	f4,d3,d4,d1,d2,$ab9423a7,4*14-40(a1),15
	md5step	f4,d2,d3,d4,d1,$fc93a039,4*5-40(a1),21
	md5step	f4,d1,d2,d3,d4,$655b59c3,4*12-40(a1),6
	md5step	f4,d4,d1,d2,d3,$8f0ccc92,4*3-40(a1),10
	md5step	f4,d3,d4,d1,d2,$ffeff47d,(a1)+,15
	md5step	f4,d2,d3,d4,d1,$85845dd1,4*1-44(a1),21
	md5step	f4,d1,d2,d3,d4,$6fa87e4f,4*8-44(a1),6
	md5step	f4,d4,d1,d2,d3,$fe2ce6e0,4*15-44(a1),10
	md5step	f4,d3,d4,d1,d2,$a3014314,4*6-44(a1),15
	md5step	f4,d2,d3,d4,d1,$4e0811a1,4*13-44(a1),21
	md5step	f4,d1,d2,d3,d4,$f7537e82,4*4-44(a1),6
	md5step	f4,d4,d1,d2,d3,$bd3af235,(a1),10
	md5step	f4,d3,d4,d1,d2,$2ad7d2bb,4*2-44(a1),15
	md5step	f4,d2,d3,d4,d1,$eb86d391,4*9-44(a1),21
; Subtract 8 cycles for no offsets

				;	    116
	move.l	16(sp),a0	;	 16 132
	add.l	d1,(a0)+	;	 20 152
	add.l	d2,(a0)+	;	 20 172
	add.l	d3,(a0)+	;	 20 192
	add.l	d4,(a0)+	;	 20 212

	movem.l	(sp)+,d2-d4	;	 36 248
	rts			;	 16 264

; So, that's a total of 86 cycles subtracted for no offets, from
; 264 + 1232 + 1632 + 3072 = 6200 cycles.  The final tally is
; thus 6114 cycles.

; A table of the Mysterious Constants used by the MD5 computation.
md5table:
	dc.l $d76aa478,$e8c7b756,$242070db,$c1bdceee
	dc.l $f57c0faf,$4787c62a,$a8304613,$fd469501
	dc.l $698098d8,$8b44f7af,$ffff5bb1,$895cd7be
	dc.l $6b901122,$fd987193,$a679438e,$49b40821

	dc.l $f61e2562,$c040b340,$265e5a51,$e9b6c7aa
	dc.l $d62f105d,$02441453,$d8a1e681,$e7d3fbc8
	dc.l $21e1cde6,$c33707d6,$f4d50d87,$455a14ed
	dc.l $a9e3e905,$fcefa3f8,$676f02d9,$8d2a4c8a

	dc.l $fffa3942,$8771f681,$6d9d6122,$fde5380c
	dc.l $a4beea44,$4bdecfa9,$f6bb4b60,$bebfbc70
	dc.l $289b7ec6,$eaa127fa,$d4ef3085,$04881d05
	dc.l $d9d4d039,$e6db99e5,$1fa27cf8,$c4ac5665

	dc.l $f4292244,$432aff97,$ab9423a7,$fc93a039
	dc.l $655b59c3,$8f0ccc92,$ffeff47d,$85845dd1
	dc.l $6fa87e4f,$fe2ce6e0,$a3014314,$4e0811a1
	dc.l $f7537e82,$bd3af235,$2ad7d2bb,$eb86d391

	end
