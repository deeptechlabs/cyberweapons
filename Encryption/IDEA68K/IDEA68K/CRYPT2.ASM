;;; Crypt2.asm - 68000 assembler versions of heavily-used functions in
;;;              crypt.c for the IDEA cipher.  By Colin Plumb; not part
;;;              of the original distribution from ETH Zurich
;;;              isibee.ethz.ch:pub/simpl/idea.V1.0.tar.Z (129.132.38.1)
;;;
;;; No copyright is claimed on this code; it is in the public domain.
;;; It would be nice if you could give me credit if you use it, but
;;; the legal definition of "public domain" states that there is no
;;; legal obligation to do so.

;;; An earlier version of this code is circulating with a copyright notice
;;; on it; this was due to my mailing out an earlier version without any
;;; indication of the intended status, so the recipient assumed I claimed
;;; copyright.  It is, however, incorrect.  And if you want my e-mail
;;; address, the best one to use for the long term is <colin@nyx.cs.du.edu>.

;;; The following lecture on the proer use of this function in a
;;; cryptographic applicationn should bot be needed by readers of
;;; _Applied Cryptography_, but just in case you got his some other
;;; way, THIS IS IMPORTANT:

;;; The original code referenced above provides various encryption
;;; modes, in particular feedback and chaining modes which have a
;;; lag of greater than 1.  These are useful only in very specialized
;;; applications, and for general use the lag factor of 1 is strongest.
;;; There is no reason for a typical application package to use anything
;;; else.  In particular, the xpkidea.library which associates a "quality"
;;; of 100\ with a lag factor of 25 is downright dangerous; typical users
;;; aren't going to be able to come up with 25 fully random initial vectors.

;;; Electronic Code Book (ECB) mode, where you pass each block of plaintext
;;; through the cipher system, is not very good and should be avoided, as
;;; repeated plaintext results in repeated ciphertext, which gives information
;;; away.  Output Feedback (OFB) mode is vulnerable if you reuse keys and
;;; initial vectors.  In particular, if you encrypt two uncompressed ASCII
;;; messages with the same key and initial vector, it is not very difficult
;;; (even for a normal person, much less an intelligence agency!) to first,
;;; read both messages up to the minimum of their two lengths, and second,
;;; read any other shorter message sent with the same key and initial vector.

;;; The only modes that you should consider are Cipher Block Chaining (CBC)
;;; and Cipher Feedback (CFB) modes.  CFB has the advantage that the text
;;; does not have to be a multiple of a block long, and so does not expand
;;; the text.  It also does not require a decryption routine (or the moral
;;; equyivalent, InvertIdeaKey, below).  It is recommended for general use.

;;; Where the plaintext blocks are the array x[i] and the ciphertext are y[i],
;;; IDEA encryption is denoted by IDEA(plain,key) and decryption by
;;; IIDEA(cipher,key), the modes are as follows:

;;; CBC encrypt: y[i] = IDEA(x[i]^y[i-1], key)
;;; CBC decrypt: x[i] = y[i-1] ^ IIDEA(y[i], key)
;;; CFB encrypt: y[i] = x[i] ^ IDEA(y[i-1], key)
;;; CFB decrypt: x[i] = y[i] ^ IDEA(y[i-1], key)

;;; Both modes require initial vectors y[-1].  This can be a random number,
;;; or you can set it to a constant (e.g. 0) and make x[0] be a random
;;; number.  This saves you the effort of storing it somewhere else, at
;;; the expense of enlarging the ciphertext.

;;; For something like a disk or file encryptor, set it to some unique
;;; value, like the inode number or disk block number.  This way, identical
;;; blocks will still be encrypted differently.

;;; Folks, this is a pretty darn good encryption algorithm.  Proving
;;; that is a lot of work.  Some progress has been made in Xuejia Lai's
;;; PhD thesis ("On the Design an Security of Block Ciphers", ISBN
;;; 3-89191-573-X) and various papers at crypto conferencesd.  If
;;; you haven't read and understood this material, you're not competent
;;; to dink with it.

;;; Two things you *can* try, if you like:

;;; If there are alot of 0 bits in the key (which basically never
;;; happens if you choose keys at random, or use a good pass-phrase
;;; hashing function), you can produce a weak key, which can be
;;; cryptanalyzed more easily.  One way to fix this is to XOR
;;; the constant 0x0dae with each 16-bit word in the expanded
;;; key.  This is from the paper "Weak Keys for IDEA", by
;;; Joan Daemen, Rene' Govaerts and Joos Vandewalle.  Other
;;; values are possible, but you should read the paer before
;;; trying to come up with any.

;;; If you need greater speed and are willing to live with a smaller
;;; safety margin, the best attack on IDEA to date is no better than
;;; key exhaustion (trying all 2^128 keys) for 3 or more rounds.
;;; Thus, you could halve the time by going to 4 rounds.  This is
;;; recommended only for casual security, however.  Attacks will
;;; very likely get better.

;;; As for picking keys...

;;; Don't forget that english text has an average entropy of less than
;;; 2 bits per character.  That is, you have to compress ASCII by 4:1
;;; before it is totally random and can't be further compressed with
;;; sufficient effort.  So if you want to use a password, it should be 64
;;; bytes long, not 16.  (It can be shorter if you use a hard-to-remember
;;; string with lots of nonsense words, FUnNy capitalisation or @dd
;;; characters.)  You have to hash it down to 128 random bits.  An
;;; algorithm for that is not supplied.  Exclusive-oring 16-byte blocks
;;; together does not work well.

;;; Remember, 2^128 is a very large number.  38.5 decimal digits.
;;; 340,282,366,920,938,463,463,374,607,431,768,211,456.
;;; 340 thousand million billion trillion million.  Or, equivalently,
;;; 340 million million million million million million.  That's
;;; a bit over 27 totally random letters.  But a standard pass phrase,
;;; even a wierd one, is far from totally random.  For starters, it's
;;; usually easy to figure out where the blanks go even if they're
;;; stripped out.  "scramblepatternpipelineyellow" is 29 characters
;;; long, but nothing like random.  A random string of 27 letters
;;; looks like "xbrebwcrajhozfepyclvgkchqro".  This was a standard
;;; pseudo-random number generator; it may look random to you, but
;;; it's not good enough for high-security applications.

;;; Lecure is over, now for the code.

;;; (Okay, so the cycle counts indicate an unhealthy obsession.)
;;; Multiply takes, according to the 6th edition Motorola MC68000
;;; manual, 38+2n cycles, where n is the number of bits set in the
;;; source effective address.  Since the data are random, on average
;;; 8 of the 16 bits will be set, and multiplies will take 54 cycles
;;; on average.

	section code

nofKeyPerRound	equ	6 ; number of used keys per round
nofRound	equ	8 ; number of rounds

; Multiply two numbers in the range of 1..0x10000, modulo 0x10001.
; 0x10000 is represented as 0.

Mult	macro	; src1, src2, dest, neither source is 0
		; dest may equal src2, but not src1 (which is zeroed)
	mulu	\2,\1	; 54
	move.w	\1,\3	;  4
	swap	\1	;  4 \1 now holds high part
	sub.w	\1,\3	;  4
	moveq	#0,\1	;  4 does not affect X flag
	addx.w	\1,\3	;  4

	endm		; 74
; Code to handle the cases where one argument is 0 = 0x10000 = -1.
; Negate the other modulo 0x10001, giving 0x10001 - x = 1 - x.
; In-place and out-of-place versions

Invert1	macro	; dest
	neg.w	\1	;  4
	addq.w	#1,\1	;  4
	endm		;  8

Invert2	macro	; src, dest
	moveq	#1,\2	;  4
	sub.w	\1,\2	;  4
	endm		;  8

; Externally callable version (also a usage example)

	xdef	_Mul
	xdef	_Mul2
_Mul:
_Mul2:
	move.w	4(sp),d0	; 12
	beq.s	Mul_a_is_0	;  8
	move.w	6(sp),d1	; 12
	beq.s	Mul_b_is_0	;  8
	Mult	d1,d0,d0	; 54 (based on average of 8 bits set)
	rts			; 10 = 104 total
Mul_a_is_0:
	Invert2	6(sp),d0
	rts
Mul_b_is_0:
	Invert1	d0
	rts
MulEnd:
;; The cases where a or b are zero are so rare they don't affect the average
;; time significantly.


; encryption and decryption algorithm IDEA

; void  Idea(u_int16 dataIn[4], u_int16 dataOut[4], u_int16 key[52])

; This performs the core IDEA encryption.  It leaves no sensitive
; information behind in memory or registers, except for a temporary
; value from the last KeyMult in d0, which is probably safe to assume will
; quickly be trashed.

; Modifying this code is NOT recommended for the faint of heart.

; This code is, in a word, *tight*.  Note in particular the use of the low
; halves of d2-d7 only, to eliminate the overhead of saving and restoring
; their high halves, the use of d3 as a constant zero source, and a1
; doubling as a loop counter.  Also note that the exceptional cases in the
; KeyMult macro have been taken entirely out of line, and there has been
; some code motion to between KeyMult 5 and 6 so that the branches stay
; in short range.

; Unrolling this loop any further would result in the branches going out
; of short branch range, which would cost more in instruction fetch time
; than would be saved by the unrolling.  It would also take it out of a
; 68020's cache.

; Register usage:
; d0.l - KeyMult temp
; d1.l - Constant zero
; d2.w - s2
; d3.w - s1
; d4.w - x0
; d5.w - x2	<- Note reversal
; d6.w - x1
; d7.w - x3
; a0.l - dataIn, dataOut and key pointer limit
; a1.l - Pointer to current location in expanded key

; KeyMult: Multiply value in register by next available key (pointed at by a1).
; Requires corresponding MultAux code nearby.

; This macro *should* work, and be faster than the one in crypt2.asm.
; However, I have not had a chance to test it.
; inputs for zero by checking the flags after the multiply.  If the
; product is zero, one of the inputs had to be.  But that would require
; another round of careful crafting, which I don't feel like
; doing right now.

KeyMult	macro	; \1 = number, \2 = register
	move.w	\2,d0		;  4
	mulu	(a1)+,d0	; 58 (42 if key is 0)
	beq.s	Mul\1_0		;  8
	move.w	d0,\2		;  4
	swap	d0		;  4
	sub.w	d0,\2		;  4
	addx.w	d1,\2		;  4
Mul\1_done:
	endm			; 86 total

; Note: the following cases should occur about 1/32768 of the time,
; so the speed is not critical.

MultAux	macro	; \1 = number, \2 = register
Mul\1_0:
	neg.w	\2
	beq	Mul\1_0x
	sub.w	-2(a1),\2
Mul\1_0x:
	addq.w	#1,\2
	bra.s	Mul\1_done
	endm

	MultAux	1,d4
	MultAux	2,d7
	MultAux	3,d5
	MultAux	4,d6

	MultAux	5,d4

	xdef	_Idea
	xdef	_Idea2
_Idea:
_Idea2:
	move.l	4(sp),a0	;  16     dataIn
	move.l	12(sp),a1	;  16  32 key

; Since I am scrupulously careful never to touch the high halves of
; d2..d7, I only need to save the low halves.
	movem.w	d2-d7,-(sp)	;  32  68

	clr.w	d1		;   4  72 Constant 0
; movem.w <mem>,<regs> here would sign-extend.
	move.w	(a0)+,d4	;   8  80
	move.w	(a0)+,d6	;   8  88
	move.w	(a0)+,d5	;   8  96
	move.w	(a0),d7		;   8 104
; When a1 points here, stop.  96 = 2 bytes/key * 6 keys/round * 8 rounds
	lea	96(a1),a0	;   8 112

CryptLoop:
	KeyMult	1,d4		;  86     x0 *= *key++;
	add.w	(a1)+,d6	;   8  94 x1 += *key++;
	add.w	(a1)+,d5	;   8 102 x2 += *key++;
	KeyMult	2,d7		;  86 188 x3 *= *key++;

	move.w	d5,d2		;   4 192 s2 = x2
	eor.w	d4,d5		;   4 196 x2 ^= x0
	KeyMult	3,d5		;  86 282 x2 *= *key++;
	move.w	d6,d3		;   4 286 s1 = x1;
	eor.w	d7,d6		;   4 290 x1 ^= x3;
	add.w	d5,d6		;   4 294 x1 += x2;
	KeyMult	4,d6		;  86 380 x1 *= *key++;
	eor.w	d6,d4		;   4 384 x0 ^= x1;

;; Second unrolled copy.  Some of the first loop is postponed until after the
;; first KeyMult so that the branches there will be in short range (4 cycles).
	KeyMult	5,d4

	add.w	d6,d5		;   4 388 x2 += x1;  FIRST LOOP
	eor.w	d5,d7		;   4 392 x3 ^= x2;  FIRST LOOP
	eor.w	d2,d6		;   4 396 x1 ^= s2;  FIRST LOOP
	eor.w	d3,d5		;   4 400 x2 ^= s1;  FIRST LOOP

	add.w	(a1)+,d6
	add.w	(a1)+,d5

;; This code logically belongs after the KeyMult, but is moved up so that
;; the branches to MultAux will stay in short branch range.
	move.w	d5,d2
	eor.w	d4,d5
	move.w	d6,d3

	KeyMult	6,d7

	KeyMult	7,d5
	eor.w	d7,d6
	add.w	d5,d6
	KeyMult	8,d6
	add.w	d6,d5
	eor.w	d6,d4
	eor.w	d5,d7
	eor.w	d2,d6
	eor.w	d3,d5		; 400 800

	cmp.l	a0,a1		;   6 806
	bne	CryptLoop	;  10 816
				;   2 114 -> From top, if expired
	KeyMult	9,d4		;  94 208 x0 *= *key++;
	add.w	(a1)+,d5	;   8 216 x2 += *key++;
	add.w	(a1)+,d6	;   8 224 x1 += *key++;
	KeyMult	10,d7		;  94 318 x3 *= *key++;

	move.l	20(a7),a0	;  16 334 6 regs(12) + retaddr(4) + arg 1(4)
	movem.w	d4-d7,(a0)	;  24 358 Store x0,x2,x1,x3
; movem.w <mem>,<regs> sign-extends, which is not what we want...
	move.w	(sp)+,d2	;   8 366
	move.w	(sp)+,d3	;   8 374
	move.w	(sp)+,d4	;   8 382
	move.w	(sp)+,d5	;   8 390
	move.w	(sp)+,d6	;   8 398
	move.w	(sp)+,d7	;   8 406
	rts			;  16 422

	MultAux	6,d7
	MultAux	7,d5
	MultAux	8,d6

	MultAux	9,d4
	MultAux	10,d7

; 422 + 4 * 816 = 3686 cycles per block, or 460.75 cycles per byte.
; At 7159090 Hz, that's 1942.24 blocks per second, or 15537.9
; bytes per second.

; End of Idea

;; For reference, here's the original source:

; void  Idea(u_int16 *dataIn, u_int16 *dataOut, u_int16 *key)
; {
;   register u_int16 round, x0, x1, x2, x3, s1, s2;
;
;   x0 = *dataIn++; x1 = *dataIn++; x2 = *dataIn++; x3 = *dataIn;
;
;   for (round = nofRound; round > 0; round--) {
;     x0 = Mul(x0, *key++);
;     x1 += *key++;
;     x2 += *key++;
;     x3 = Mul(x3, *key++);
;
;     s1 = x1;  s2 = x2;
;     x2 ^= x0;
;     x2 = Mul(x2, *key++);
;     x1 ^= x3;
;     x1 += x2;
;     x1 = Mul(x1, *key++);
;     x2 += x1;
;
;     x0 ^= x1;
;     x3 ^= x2;
;
;     x1 ^= s2;
;     x2 ^= s1;
;   }
;   *(dataOut++) = Mul(x0, *key++);
;   *(dataOut++) = x2 + *key++;
;   *(dataOut++) = x1 + *key++;
;   *(dataOut) = Mul(x3, *key);
; } /* Idea */

;;;
;;; This expands a user key to a full idea key, copying the 128-bit block
;;; with a 25-bit rotation each time.
;;;

; void ExpandUserKey(uint16 userKey[8], uint16 key[52])
; Expand an 8-word (16-byte) user key into a 52-word (104-byte)
; working key, by rotating the 128-bit big-endian key left 25
; bits and storing the result in the next 8 words, successively.

; 1306 cycles total = (@ 7159090 Hz) 182.425 us

; Rotate a/b/c/d left 25 bits, by rotating right 7 and shifting
; down 1 register

shdown	macro	; a, b, c, d, e, temp, const
			; aaaa bbbb cccc dddd ____ ____
	move.l	\1,\5	; aaaa bbbb cccc dddd aaaa ____	 4
	and.w	\7,\1	; __0a bbbb cccc dddd aaaa ____	 4   8
	eor.w	\1,\5	; __0a bbbb cccc dddd aaa0 ____	 4  12

	move.w	\4,\6	; __0a bbbb cccc dddd aaa0 __dd	 4  16
	and.w	\7,\6	; __0a bbbb cccc dddd aaa0 __0d	 4  20
	eor.w	\6,\4	; __0a bbbb cccc ddd0 aaa0 __0d	 4  24
	or.w	\6,\5	; __0a bbbb cccc ddd0 aaad __0d	 4  28
	ror.l	#7,\5	; __0a bbbb cccc ddd0 daaa __0d	22  50

	move.w	\3,\6	; __0a bbbb cccc ddd0 daaa __cc	 4  54
	and.w	\7,\6	; __0a bbbb cccc ddd0 daaa __0c	 4  58
	eor.w	\6,\3	; __0a bbbb ccc0 ddd0 daaa __0c	 4  62
	or.w	\6,\4	; __0a bbbb ccc0 dddc daaa __0c	 4  66
	ror.l	#7,\4	; __0a bbbb ccc0 cddd daaa __0c	22  88

	move.w	\2,\6	; __0a bbbb ccc0 cddd daaa __bb	 4  92
	and.w	\7,\6	; __0a bbbb ccc0 cddd daaa __0b	 4  96
	eor.w	\6,\2	; __0a bbb0 ccc0 cddd daaa __0b	 4 100
	or.w	\6,\3	; __0a bbb0 cccb cddd daaa __0b	 4 104
	ror.l	#7,\3	; __0a bbb0 bccc cddd daaa __0b	22 126

	or.w	\1,\2	; __0a bbba bccc cddd daaa __0b	 4 130
	ror.l	#7,\2	; __0a abbb bccc cddd daaa __0b	22 152

; Rotate a/b/c/d left 25 bits, result in e/f/a/b.
	endm

shup	macro	; e, f, a, b, c, d, const
			; ____ ____ aaaa bbbb cccc dddd
	move.l	\4,\1	; bbbb ____ aaaa bbbb cccc dddd	 4
	and.w	\7,\4	; bbbb ____ aaaa __0b cccc cccc	 4   8
	eor.w	\4,\1	; bbb0 xxxx aaaa __0b cccc dddd	 4  12

	move.l	\5,\2	; bbb0 cccc aaaa __0b cccc dddd	 4  16
	and.w	\7,\5	; bbb0 cccc aaaa __0b __0c dddd	 4  20
	eor.w	\5,\2	; bbb0 ccc0 aaaa __0b __0c dddd	 4  24
	or.w	\4,\2	; bbb0 cccb aaaa __0b __0c dddd	 4  28
	ror.l	#7,\2	; bbb0 bccc aaaa __0b __0c dddd	22  50

	move.l	\3,\4	; bbb0 bccc aaaa aaaa __0c dddd	 4  54
	and.w	\7,\3	; bbb0 bccc __0a aaaa __0c dddd	 4  58
	eor.w	\3,\4	; bbb0 bccc __0a aaa0 __0c dddd	 4  62
	or.w	\3,\1	; bbba bccc __0a aaa0 __0c dddd	 4  66
	ror.l	#7,\1	; abbb bccc __0a aaa0 __0c dddd	22  88

	move.l	\6,\3	; abbb bccc dddd aaa0 __0c dddd	 4  92
	and.w	\7,\6	; abbb bccc dddd aaa0 __0c __0d	 4  96
	eor.w	\6,\3	; abbb bccc ddd0 aaa0 __0c __0d	 4 100
	or.w	\5,\3	; abbb bccc dddc aaa0 __0c __0d  4 104
	ror.l	#7,\3	; abbb bccc cddd aaa0 __0c __0d 22 126

	or.w	\6,\4	; abbb bccc cddd aaad __0c __0d  4 130
	ror.l	#7,\4	; abbb bccc cddd daaa __0c __0d 22 152

	endm

	xdef	_ExpandUserKey
	xdef	_ExpandUserKey2
_ExpandUserKey:
_ExpandUserKey2:
	move.l	4(sp),a0	; UserKey		 16
	move.l	8(sp),a1	; Key			 16   32
	movem.l	d2-d5,-(sp)	;			 40   72
	movem.l	(a0),d0-d3	; Fetched into d0-d3	 44  116
	move.l	d7,a0		;			  4  120
	moveq	#127,d7		;			  4  124

	movem.l	d0-d3,(a1)	; Store words 0..7	 40  164

	shdown	d0,d1,d2,d3,d4,d5,d7	;		152  318
	movem.l	d1-d4,16(a1)	; Store words 8..15	 44  360

	shdown	d1,d2,d3,d4,d5,d0,d7	;		152  512
	movem.l	d2-d5,32(a1)	; store words 16..23	 44  556

	shup	d0,d1,d2,d3,d4,d5,d7	;		152  708
	movem.l	d0-d3,48(a1)	; Store words 24..31	 44  752

	shdown	d0,d1,d2,d3,d4,d5,d7	;		152  904
	movem.l	d1-d4,64(a1)	; Store words 32..39	 44  948

	shdown	d1,d2,d3,d4,d5,d0,d7	;		152 1100
	movem.l	d2-d5,80(a1)	; store words 40..47	 44 1144

; We only need two longwords this iteration
;			 (d2   d3   d4   d5)

			; aaaa bbbb cccc dddd
	and.w	d7,d2	; __0a bbbb cccc dddd		  4 1148

	move.w	d3,d5	; __0a bbbb cccc __bb		  4 1152
	and.w	d7,d5	; __0a bbbb cccc __0b		  4 1156
	eor.w	d5,d3	; __0a bbb0 cccc __0b		  4 1160
	or.w	d2,d3	; __0a bbba cccc __0b		  4 1164
	ror.l	#7,d3	; __0a abbb cccc __0b		 22 1186

	not.w	d7	;				  4 1190
	and.w	d7,d4	; __0a abbb ccc0 __0b		  4 1194
	or.w	d5,d4	; __0a abbb cccb __0b		  4 1198
	ror.l	#7,d4	; __0a abbb bccc __0b		 22 1220

	movem.l	d3-d4,96(a1)	; store words 48..51	 28 1248

	move.l	a0,d7	;				  4 1252
	movem.l	(sp)+,d2-d5	;			 44 1296
	rts		;				 10 1306

;;;
;;; This section inverts keys
;;; First, the code to find a multiplicative inverse
;;;

; Set up the registers for InvCore
InvPrep	macro	; \1 = in.l, \2 = temp.l, \3 = out.w
	move.l	\1,\2
	move.w	\2,\3

	endm

; Note: this expects \1 to be set to the input value (high 16 bits zero!),
; and be non-zero, \2 to  be set to 0x10001, and \3 to be set to 1.  It
; returns the multiplicative inverse of \1 in \3.  It does not affect the
; high words of \1, \3 and \4.  \2 and \5 have all 32 bits trashed.

InvCore	macro	; \1 = in.l,   \2 = mod.l,  \3 = out.w,
		; \4 = temp.w, \5 = temp.l, \6 = #1.w
;iter1\@:
	divu	\1,\2
	bvs	Out1\@	; If ovfl, input=1, so inverse = 1 (in \3).
	move.w	\2,\4	; t0 = t0 + t1 * q = 0 + 1 * q = q
;	mulu	\3,\5	; If we had copied to d4, we would have done this...
;	add.w	\5,\4	; But since we know d0=1 and d2=0, we can skip it
	clr.w	\2
	swap	\2
;	cmp.w	#1,\2
	cmp.w	\3,\2	; Since \3 = 1
	beq	Out2\@	; remainder = 1, so quit - inverse in -\5

InvLoop\@:
;iter2\@:
	divu	\2,\1
	move.w	\1,\5
	mulu	\4,\5
	add.w	\5,\3
	clr.w	\1
	swap	\1
	cmp.w	\6,\1
	beq	Out1\@	; remainder = 1, so quit - inverse in \3
;iter3\@:
	divu	\1,\2
	move.w	\2,\5
	mulu	\3,\5
	add.w	\5,\4
	clr.w	\2
	swap	\2
	cmp.w	\6,\2
;	beq	Out2\@	; remainder = 1, so quit - inverse in -\4
;	bra	InvLoop\@
	bne	InvLoop\@

Out2\@:			; Inverse in -\4
	move.w	\6,\3
	sub.w	\4,\3
Out1\@:			; Inverse in \3

	endm

InputZero:
	moveq	#0,d0
	rts

	xdef	_MulInv
	xdef	_MulInv2
_MulInv:
_MulInv2:
	moveq	#0,d1
	move.w	4(sp),d1
	beq	InputZero
	move.l	d2,a0
	move.w	d3,-(sp)
	move.l	d4,a1

	moveq	#1,d0
	move.l	#$10001,d3

	InvCore	d1,d3,d0,d2,d4,#1

	move.l	a1,d4
	move.w	(sp)+,d3
	move.l	a0,d2

	rts
MulInvEnd:

; Because it's legal to invert a key on top of itself, we push the inverted
; key onto the stack and then copy it to the destination at the end.
; High-security applications should add some code to erase the stack
; buffer.

	xdef	_InvertIdeaKey
	xdef	_InvertIdeaKey2
_InvertIdeaKey:
_InvertIdeaKey2:
	move.l	4(sp),a0	; Source
	move.l	8(sp),a1	; Dest pointer
	movem.l	d2-d7,-(sp)

	move.l	#$10001,d7

	move.l	(a0)+,d0
	move.l	(a0)+,d1

	moveq	#0,d3		; Clear high half of d3
	move.w	d1,d3
	beq	IIKzero1
	InvPrep	d7,d4,d1
	InvCore	d3,d4,d1,d5,d6,d7
IIKzero1:
	swap	d1
	neg.w	d1
	swap	d1

	move.l	d1,-(sp)

	swap	d0
	move.w	d0,d3
	beq	IIKzero2
	InvPrep	d7,d4,d0
	InvCore	d3,d4,d0,d5,d6,d7
IIKzero2:
	swap	d0
	neg.w	d0

	move.l	d0,-(sp)

	moveq	#nofRound-2,d2
	bra	IIKloop

IIKzero3:	; Located here to be in short branch range
		; (saves 4*7 = 28 cycles; costs one branch = 10 cycles)
; d1.w == 0; d0.w is unknown
	move.w	d0,d4
	beq	IIKzero3a
	InvPrep	d7,d5,d1
	InvCore	d4,d5,d1,d0,d6,d7
	clr.w	d0
	bra	IIKzero3a

IIKzero4:
; d1.w != 0; d0.w == 0
	clr.w	d1
	bra	IIKzero4a

IIKloop:
	move.l	(a0)+,-(sp)
	move.l	(a0)+,d0
	move.l	(a0)+,d1

	neg.w	d0
	swap	d0
	move.w	d1,d3
	beq	IIKzero3
	move.w	d0,d4
	beq	IIKzero4
	InvPrep	d7,d5,d1
	InvCore	d4,d5,d1,d0,d6,d7
IIKzero4a:
	InvPrep	d7,d4,d0
	InvCore	d3,d4,d0,d5,d6,d7
IIKzero3a:
	move.l	d0,-(sp)
	swap	d1
	neg.w	d1
	move.l	d1,-(sp)

	dbra	d2,IIKloop

	move.l	(a0)+,d2
	move.l	(a0)+,d0
	move.l	(a0)+,d1

	move.w	d1,d3
	beq	IIKzero5
	InvPrep	d7,d4,d1
	InvCore	d3,d4,d1,d5,d6,d7
IIKzero5:
	swap	d1
	neg.w	d1
	swap	d1

	swap	d0
	move.w	d0,d3
	beq	IIKzero6
	InvPrep	d7,d4,d0
	InvCore	d3,d4,d0,d5,d6,d7
IIKzero6:
	swap	d0
	neg.w	d0

;	move.l	d0,(a1)+	; Install these last three longwords...NOT
;	move.l	d1,(a1)+	; Merge this with the movem below.
;	move.l	d2,(a1)+
				; 104 bytes of key = 26 longs = 9+9+8
	movem.l	(sp)+,d3-d7/a0
	movem.l	d0-d7/a0,(a1)	; 9 longs
	movem.l	(sp)+,d0-d7/a0
	movem.l	d0-d7/a0,36(a1)	; 9 longs
	movem.l	(sp)+,d0-d7
	movem.l	d0-d7,72(a1)	; 8 longs

	movem.l	(sp)+,d2-d7	; Retrieve registers
	rts

InvertIdeaKeyEnd:

;; And for reference, the original code...

; void InvertIdeaKey( u_int16 *key, u_int16 *invKey)
; {
;   register int  i;
;   KeyT(dk);
;
;   dk[nofKeyPerRound * nofRound + 0] = MulInv(*key++);
;   dk[nofKeyPerRound * nofRound + 1] = (addMod - *key++) & ones;
;   dk[nofKeyPerRound * nofRound + 2] = (addMod - *key++) & ones;
;   dk[nofKeyPerRound * nofRound + 3] = MulInv(*key++);
;   for (i = nofKeyPerRound * (nofRound - 1); i >= 0; i -= nofKeyPerRound) {
;     dk[i + 4] = *key++;
;     dk[i + 5] = *key++;
;     dk[i + 0] = MulInv(*key++);
;     if (i > 0) {
;       dk[i + 2] = (addMod - *key++) & ones;
;       dk[i + 1] = (addMod - *key++) & ones;
;     } else {
;       dk[i + 1] = (addMod - *key++) & ones;
;       dk[i + 2] = (addMod - *key++) & ones;
;     }
;     dk[i + 3] = MulInv(*key++);
;   }
;   for (i = 0; i < keyLen; i++)
;     invKey[i] = dk[i];
; } /* InvertIdeaKey */
