; Double-word (32-bit) rotates on an 8086

; This is just some hacking around with an 8086 to see how to
; implement MD5 and SHA efficiently, as the start of an
; implementation.  The biggest problem is the 32-bit rotates that
; the algorithms depend on.  Addition is no problem, ans
; 32-bit logical operations can simply be done in two halves.

; These use cx as a temporary register.

; This code is useful as primitive in message-digest algorithms such
; as MD5 and SHA, which operate on 32-bit words.

; The trick used here to rotate a register pair, let's say
; 4 bits left, is to rotate each half 4 bits left, and then
; exchange the rightmost (lowest) 4 bits.

; For example:
; 1234 5678 -> 2341 6785 -> 2345 6781

; The swap is done using another bit of trickery.
; You may recall the way to swap two registers without
; a third temporary:

; start	  a   b
; a ^= b  a^b b
; b ^= a  a^b a
; a ^= b  b   a

; Now, observe that if the middle step is left out,  you get a no-op:

; start   a   b
; a ^= b  a^b b
; a ^= b  a^b b

; Since this is a bitwise operation, we can get a combination of the two
; effects with the sequence:
; a ^= b
; b ^= a & mask
; a ^= b

; If the mask is all 1's, this degenerates to the first case.  If it is
; all 0's, it degenerates to the second.  If it holds, say, only the
; low 4 bits set, the low 4 bits are swapped.

; In the code below, we arrange the rotates so at most 8 bits have to
; be swapped, and use byte operations, with ch for the mask.  We load
; it at the same time as cl is loaded with the rotate count.
; The result is admittedly very tricky code, but it's acceptable for
; cryptographic hashes to be write-only code.


; One-bit rotates are faster the naive way
; Note: slightly faster if r1 is ax.
rotl1	MACRO	r1,r2
	shl	r1,1
	rcl	r2,1
	adc	r1,0
ENDM

rotr1	MACRO	r1,r2
	mov	cx,r1
	rcr	cx,1
	rcr	r2,1
	rcr	r1,1
ENDM

rotr2	MACRO	r1,r2
	mov	cx,r1
	rcr	cx,1
	rcr	r2,1
	rcr	r1,1
	rcr	cx,1
	rcr	r2,1
	rcr	r1,1
ENDM

; Note: r1 and r2 should be specified by first letter only; no x!

; Eight-bit rotates can be done by register half shuffling
rotl8	MACRO	r1,r2
	xchg	r1&h,r1&l
	xchg	r1&l,r2&h
	xchg	r2&h,r2&l
ENDM

rotr8	MACRO	r1,r2
	xchg	r2&l,r2&h
	xchg	r2&h,r1&l
	xchg	r1&l,r1&h
ENDM

; It's the in-between cases that require work

; Rotate left 0 to 8 bits
rotl	MACRO	count,r1,r2
	mov	cx,((255 SHR (8-count)) SHL 8) + count
	rol	r1&x,cl
	rol	r2&x,cl
	xor	r1&l,r2&l
	and	ch,r1&l
	xor	r2&l,ch
	xor	r1&l,r2&l
ENDM

; Rotate right 0 to 8 bits (left 24 to 32)
rotr	MACRO	count,r1,r2
	mov	cx,(((255 SHL (8-count) AND 255) SHL 8) + count
	ror	r1&x,cl
	ror	r2&x,cl
	xor	r1&h,r2&h
	and	ch,r1&h
	xor	r2&h,ch
	xor	r1&h,r2&h
ENDM

; The other tricky part of MD%, for example, is the fact that you run out
; of registers very fast.  There's just no place to keep 128 bits
; in an 8086's 7 (sp is reserved) available 16-bit registers.

; I think the way to do an MD5 step is (where <<< is rotate left):

; In regs
; d,a
; a,b	a += F(b, c, d) + x + const;
; 	a <<<= s;
; a,b	a += b;

; d,a	d += F(a, b, c) + x + const;
; 	d <<<= s;
; d,a	d += a;

; c,d	c += F(d, a, b) + x + const;
; 	c <<<= s;
; c,d	c += d;

; Now, for the rotate, a, b, and c, respoectively, must be in x regsiters.
; That means one of ax, bx or dx (since cx is used by the rotate).

; Let's see how to shuffle things.  In the first round, assume a is in
; ax and dx.  We add b to it.  Then, the old plan was to compute ...
