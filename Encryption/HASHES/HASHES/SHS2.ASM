; shs2.asm - 680x0 Assembler version of the U.S. National Institute
; of Standards and Technology (NIST) Secure Hash Standard (SHS)
; core transformation function.

; As of Eurocrypt '93, which saw the presentation of a paper on
; pseudocollisions in MD5, MD5 is considered suspect and this
; algorithm seems to be the most highly regarded of the message
; digest algorithms.

; This code written 2 June 1993 by Colin Plumb.  No copyright is
; claimed; it is in the public domain.  Do with it as you wish.

; This takes 13388 cycles on a 68000, including the return
; but not the call.  It processes 64 bytes each time, taking
; 209 3/16 cycles per byte.

; It assembles to 2872 bytes of (straight-line, no branches) code.

; Background:
; The SHS produces 5 longwords (160 bits) of cryptographic checksum.
; Call the longwords a, b, c, d, and e.  They are initialized
; to some magic values, and for each 16-longword block of input
; data, a transformation function is called which modifies these
; 5 longwords.

; This consists of a core transformation, repeated 80 times, which is
; a' = e + (a <<< 5) + f(b, c, d) + k + W[i]
; b' = a
; c' = b <<< 30 /* or b >>> 2 */
; d' = c
; e' = d
; Where <<< is a rotate left operation, f is one of four functions
; (f1 for the first 20 rounds, then f2, f3 and f4), and k is one of
; four constants (also changing each 20 rounds), and W[i] is an
; 80-longword array derived from the 16-longword input by the mapping:
; W[i] = input[i], for 0 <= i < 16
; W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], for 16 <= i < 80.

; The four functions are
; f1(x, y, z) = (x & y) | (~x & z), a bit-selection function
; f2(x, y, z) = x ^ y ^ z
; f3(x, y, z) = (x & y) | (y & z) | (z & x), a majority function
; f4(x, y, z) = x ^ y ^ z
; (f1 and f3 can be optimized to use fewer boolean operations.)

; Instead of moving the variables around, it's easier to rotate the
; meanings of the 5 longwords each iteration and use 5 variations on
; e = e + (a <<< 5) + f(b, c, d) + k + W[i]
; b = b <<< 30 /* or b >>> 2 */
; as the core.  That is what is done below.
; (After 80 iterations, the values will be back in their proper places.)

; The W[] array is generated as needed, using the input data buffer as
; a 16-longword curcular buffer.

; Usage:
; Expects a pointer to a struct SHS_INFO, which starts with
; 16 longwords of data, then 5 longwords of digest.
; This uses the standard 68000 calling convention that only
; d0, d1, a0 and a1 are not preserved by the called function.
; The argument is passed on the stack.

shs_digest	equ	4*16	; Offset to digest field

; Register usage
;	d0 and d1 are temporaries
;	d2 through d6 hold the digest
;	d7 holds the Mysterious Constant for the current round
;	a0 holds a pointer to the beginning of the SHS_INFO structure
;	a1 holds a pointer to the current data item in the SHS_INFO
;	   structure
;	a2 holds a pointer to the item 3 behind a1
;	a3 holds a pointer to the item 8 behind a1
;	a4 holds a pointer to the item 14 behind a1

; The Mysterious Constants
K1	equ	$5A827999
K2	equ	$6ED9EBA1
K3	equ	$8F1BBCDC
K4	equ	$CA62C1D6

; The three functions used
; f1 is a bit-selection function, (x & y) | (~x & z)
f1	macro	; x, y, z, d0 = z ^ (x & (y ^ z))
	move.l	\3,d0	; 4   4
	eor.l	\2,d0	; 8  12
	and.l	\1,d0	; 8  20
	eor.l	\3,d0	; 8  28
	endm

; f2 is a three-input xor
f2	macro	; x, y, z, d0 = x ^ y ^ z
	move.l	\1,d0	; 4   4
	eor.l	\2,d0	; 8  12
	eor.l	\3,d0	; 8  20
	endm

; f3 is a majority function (x & y) | (y & z) | (z & x)
f3	macro	; x, y, z, d0 = (x & y) | (z & (x | y) )
	move.l	\1,d0	; 4   4
	and.l	\2,d0	; 8  12
	move.l	\1,d1	; 4  16
	or.l	\2,d1	; 8  24
	and.l	\3,d1	; 8  32
	or.l	d1,d0	; 8  40
	endm

; f4 is the same as f2

; each of these functions is called 20 times, for a total of 20*108
; cycles, or 2160.

; The core transformation.  The input data is expected to be added separately.
trans	macro	; a, b, c, d, e, f
	add.l	d7,\5	;  8   8	; e += k
	move.l	\1,d0	;  4  12
	rol.l	#5,d0	; 18  30	; e += ROTL(5,a)
	add.l	d0,\5	;  8  38
	\6	\2,\3,\4
	add.l	d0,\5	;  8  46	; e += f(b,c,d)
	ror.l	#2,\2	; 12  58	; b = ROTL(30,b)
	endm
; This is repeated 80 times, for a total of 4640 cycles.

; This is where I hate the fact that the 680x0 has only eor dn,<ea>,
; and not the other way around! It would save 1152 cycles and 384
; bytes of code.
; Merge old values together into d0 and add to digest value
expand	macro	; e = regiter to add to
	move.l	(a1)+,d0	; 12  12
	move.l	(a2)+,d1	; 12  24
	eor.l	d1,d0		;  8  32
	move.l	(a3)+,d1	; 12  44
	eor.l	d1,d0		;  8  52
	move.l	(a4)+,d1	; 12  64
	eor.l	d1,d0		;  8  72
	add.l	d0,\1		;  8  80
	endm

; There are 64 of these, for a total of 5120 cycles.

; Merge, add and store back into ciccular buffer.
expands	macro	; e
	move.l	(a1),d0		; 12  12
	move.l	(a2)+,d1	; 12  24
	eor.l	d1,d0		;  8  32
	move.l	(a3)+,d1	; 12  44
	eor.l	d1,d0		;  8  52
	move.l	(a4)+,d1	; 12  64
	eor.l	d1,d0		;  8  72
	add.l	d0,\1		;  8  80
	move.l	d0,(a1)+	; 12
	endm
; 61 of the expands are these, which have an extra 12-cycle store at the end,
; for 732 cycles extra.

; Other costs:
; - 16 iterations of add.l (a1)+,dn at 14 cycles each, for
;   a total of 224 cycles.
; - Each of a1 through a4 is initialized 5 times, a total of 20 move.l
;   instructions at 4 cycles each, for 80 cycles.
; - d7 is initialized with a Mysterious Constant 4 times, 12 cycles
;   each, for a total of 48 cycles.
; - 348 cycles from other overhead, itemized below.

; This totals 2160 + 4640 + 5120 + 732 + 224 + 80 + 48 + 384 = 13388 cycles.

; Okay, here's the code proper.

	section code

	xdef	_shsTransform
_shsTransform:
	move.l	4(sp),a0		; 12  12
	movem.l	d2-d7/a2-a4,-(sp)	; 80  92

	movem.l	shs_digest(a0),d2-d6	; 56 148

	move.l	#K1,d7

	move.l	a0,a1
	add.l	(a1)+,d6	; 0
	trans	d2,d3,d4,d5,d6,f1
	add.l	(a1)+,d5	; 1
	trans	d6,d2,d3,d4,d5,f1
	move.l	a1,a4
	add.l	(a1)+,d4	; 2
	trans	d5,d6,d2,d3,d4,f1
	add.l	(a1)+,d3	; 3
	trans	d4,d5,d6,d2,d3,f1
	add.l	(a1)+,d2	; 4
	trans	d3,d4,d5,d6,d2,f1
	add.l	(a1)+,d6	; 5
	trans	d2,d3,d4,d5,d6,f1
	add.l	(a1)+,d5	; 6
	trans	d6,d2,d3,d4,d5,f1
	add.l	(a1)+,d4	; 7
	trans	d5,d6,d2,d3,d4,f1
	move.l	a1,a3
	add.l	(a1)+,d3	; 8
	trans	d4,d5,d6,d2,d3,f1
	add.l	(a1)+,d2	; 9
	trans	d3,d4,d5,d6,d2,f1
	add.l	(a1)+,d6	; 10
	trans	d2,d3,d4,d5,d6,f1
	add.l	(a1)+,d5	; 11
	trans	d6,d2,d3,d4,d5,f1
	add.l	(a1)+,d4	; 12
	trans	d5,d6,d2,d3,d4,f1
	move.l	a1,a2
	add.l	(a1)+,d3	; 13
	trans	d4,d5,d6,d2,d3,f1
	add.l	(a1)+,d2	; 14
	trans	d3,d4,d5,d6,d2,f1
	add.l	(a1)+,d6	; 15
	trans	d2,d3,d4,d5,d6,f1
	move.l	a0,a1
	expands	d5		; 16
	trans	d6,d2,d3,d4,d5,f1
	expands	d4		; 17
	trans	d5,d6,d2,d3,d4,f1
	expands	d3		; 18
	trans	d4,d5,d6,d2,d3,f1
	move.l	a0,a2
	expands	d2		; 19
	trans	d3,d4,d5,d6,d2,f1

	move.l	#K2,d7

	expands	d6		; 20
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 21
	trans	d6,d2,d3,d4,d5,f2
	expands	d4		; 22
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 23
	trans	d4,d5,d6,d2,d3,f2
	move.l	a0,a3
	expands	d2		; 24
	trans	d3,d4,d5,d6,d2,f2
	expands	d6		; 25
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 26
	trans	d6,d2,d3,d4,d5,f2
	expands	d4		; 27
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 28
	trans	d4,d5,d6,d2,d3,f2
	expands	d2		; 29
	trans	d3,d4,d5,d6,d2,f2
	move.l	a0,a4
	expands	d6		; 30
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 31
	trans	d6,d2,d3,d4,d5,f2
	move.l	a0,a1
	expands	d4		; 32
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 33
	trans	d4,d5,d6,d2,d3,f2
	expands	d2		; 34
	trans	d3,d4,d5,d6,d2,f2
	move.l	a0,a2
	expands	d6		; 35
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 36
	trans	d6,d2,d3,d4,d5,f2
	expands	d4		; 37
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 38
	trans	d4,d5,d6,d2,d3,f2
	expands	d2		; 39
	trans	d3,d4,d5,d6,d2,f2

	move.l	#K3,d7

	move.l	a0,a3
	expands	d6		; 40
	trans	d2,d3,d4,d5,d6,f3
	expands	d5		; 41
	trans	d6,d2,d3,d4,d5,f3
	expands	d4		; 42
	trans	d5,d6,d2,d3,d4,f3
	expands	d3		; 43
	trans	d4,d5,d6,d2,d3,f3
	expands	d2		; 44
	trans	d3,d4,d5,d6,d2,f3
	expands	d6		; 45
	trans	d2,d3,d4,d5,d6,f3
	move.l	a0,a4
	expands	d5		; 46
	trans	d6,d2,d3,d4,d5,f3
	expands	d4		; 47
	trans	d5,d6,d2,d3,d4,f3
	move.l	a0,a1
	expands	d3		; 48
	trans	d4,d5,d6,d2,d3,f3
	expands	d2		; 49
	trans	d3,d4,d5,d6,d2,f3
	expands	d6		; 50
	trans	d2,d3,d4,d5,d6,f3
	move.l	a0,a2
	expands	d5		; 51
	trans	d6,d2,d3,d4,d5,f3
	expands	d4		; 52
	trans	d5,d6,d2,d3,d4,f3
	expands	d3		; 53
	trans	d4,d5,d6,d2,d3,f3
	expands	d2		; 54
	trans	d3,d4,d5,d6,d2,f3
	expands	d6		; 55
	trans	d2,d3,d4,d5,d6,f3
	move.l	a0,a3
	expands	d5		; 56
	trans	d6,d2,d3,d4,d5,f3
	expands	d4		; 57
	trans	d5,d6,d2,d3,d4,f3
	expands	d3		; 58
	trans	d4,d5,d6,d2,d3,f3
	expands	d2		; 59
	trans	d3,d4,d5,d6,d2,f3

	move.l	#K4,d7

	expands	d6		; 60
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 61
	trans	d6,d2,d3,d4,d5,f2
	move.l	a0,a4
	expands	d4		; 62
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 63
	trans	d4,d5,d6,d2,d3,f2
	move.l	a0,a1
	expands	d2		; 64
	trans	d3,d4,d5,d6,d2,f2
	expands	d6		; 65
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 66
	trans	d6,d2,d3,d4,d5,f2
	move.l	a0,a2
	expands	d4		; 67
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 68
	trans	d4,d5,d6,d2,d3,f2
	expands	d2		; 69
	trans	d3,d4,d5,d6,d2,f2
	expands	d6		; 70
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 71
	trans	d6,d2,d3,d4,d5,f2
	move.l	a0,a3
	expands	d4		; 72
	trans	d5,d6,d2,d3,d4,f2
	expands	d3		; 73
	trans	d4,d5,d6,d2,d3,f2
	expands	d2		; 74
	trans	d3,d4,d5,d6,d2,f2
	expands	d6		; 75
	trans	d2,d3,d4,d5,d6,f2
	expands	d5		; 76
	trans	d6,d2,d3,d4,d5,f2
	expand	d4		; 77, result not used later
	trans	d5,d6,d2,d3,d4,f2
	move.l	a0,a4
	expand	d3		; 78
	trans	d4,d5,d6,d2,d3,f2
	expand	d2		; 79
	trans	d3,d4,d5,d6,d2,f2

; a1 now points to the end of the data array, which is the beginning of
; the digest array.
					;    148
	add.l	d2,(a1)+		; 20 168
	add.l	d3,(a1)+		; 20 188
	add.l	d4,(a1)+		; 20 208
	add.l	d5,(a1)+		; 20 228
	add.l	d6,(a1)+		; 20 248

	movem.l	(sp)+,d2-d7/a2-a4	; 84 332

	rts				; 16 348
