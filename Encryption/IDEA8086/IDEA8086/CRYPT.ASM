	%PAGESIZE	59	; Turbo assembler formatting codes
	%BIN	13
	%LINUM	3
 
; This code is placed in the public domain.
; Recognition of its authorship, by Colin Plumb, would be appreciated,
; but cannot be required under the law of "public domain."

; The functions provided all use the C calling convention, and
; the large code/data model.

; The entry points are:

; void Idea2(char in[8], char out[8], short key[52])
;	This performs the basic ECB IDEA encryption.  It is called
;	Idea2 so it can be tested against a C version called Idea.
;	Obviously, this is trivial to change if you want.

; void IdeaCFB(char iv[8], short key[52], char *in, char *out, short blocks)
;	This encrypts (blocks-1)*8 bytes from in to out, using CFB
;	mode.  It encrypts the IV before starting and rewrites the
;	encrypted form of the last ciphertext block, performing
;	blocks IDEA ECB encryptions in total.
;	It is intended to be used with a wrapper function that does the
;	appropriate XORs of partial blocks at the beginning and end.

; void IdeaCFBx(char iv[8], short key[52], char *in, char *out, short blocks)
;	This is the same as the above, but it decrypts.
 
	.model large
	.code
 
; A core operation in IDEA is multiplication modulo 65537.
; The valid inputs, 1 through 66636 inclusive are represented in
; 16-bit registers modulo 65536.  I.e. a value of 0 means 65536,
; or -1.  Thus, we need to test for that specially.  -x, modulo
; 65537, is 65537-x = 1-x.
; For any other number, represent the product as a*65536+b.  Since
; 65536 = -1 (mod 65537), this is the same number as b-a.  Should
; this result be negautive (generate a borrow), -n mod 65537 = 1-n
; mod 65536.  Or in other words, if you add the borrow bit back on,
; you get the right answer.
 
; This is what the assembly code does.  It forms a zero, and adds
; that on with carry.
 
; Another useful optimisation takes advantage of the fact that
; a and b are equal only if the answer is congruent to 0 mod 65537.
; Since 65537 is prime, this happens only if one of the inputs is
; congruent to 0 mod 65537.  Since the inputs are all less than 65537,
; this means it must have been zero.
 
; The code below tests for a zero result of the subtraction, and if
; one arises, it branches out of line to figure out what happened.
 
 
; This code implemets the IDEA encryption algorithm.
; It follows in pseudo-C, where the * operator operates
; modulo 65537, as Idea needs.  (If you don't understand,
; learn IDEA better.)
 
; IDEA is works on 16-bit units.  If you're processing bytes,
; it's defined to be big-endian, so an Intel machine needs to
; swap the bytes around.
 
; void Idea(u_int16 *in, u_int16 *out, u_int16 *key)
; {
;	register u+int16 x0, x1, x2, x3, s1, s2, round;
;
;	x0 = *in++;  x1 = *in++;  x2 = *in++;  x3 = *in;
;
;	for (round = 0; round < 8; round++) {
;	x0 *= *key++;
;	x1 += *key++;
;	x2 += *key++;
;	x3 *= *key++;
;
;	s1  = x1;  s2  = x2;
;	x2 ^= x0;  x1 ^= x3;
;
;	x2 *= *key++;
;	x1 += x2;
;	x1 *= *key++;
;	x2 += x1;
;
;	x0 ^= x1;  x3 ^= x2;
;	x1 ^= s2;  x2 ^= s1;
;	}
;	*out++ = x0 * *key++;
;	*out++ = x2 + *key++;	/* Yes, this is x2, not x1 */
;	*out++ = x1 + *key++;
;	*out	= x3 * *key;
; }
 
; This is the "Core" if the IDEA algorithm.  It is meant to
; be called by wrapper functions that can cope with its unusual
; calliing conventions:

; ds:si points to key, ax, dx are temps, args in bx, cx, di, bp
; Trashes *all* registers.  direction flag must be clear.
; Leaves es zero.
 
; Since there is no spare register to hold the loop count, I make
; clever use of the stack, pushing the start of the loop several
; times and using a ret instruction to do the return.
 
; Annoyingly, lods is fastest on 8086's, but other techniques are
; best on 386's.  Well, that's what the manual says, but real
; life is different.  USELODS wins on a 386SX, at least.
; Leave it set for all platforms.
 
USELODS	equ	1

; This can be turned off for non-portable applications

DOSWAP	equ	1
 
; bp must be x0 for some of the code below to work
x0	equ	bp
x1	equ	bx
x2	equ	cx
x3	equ	di
; di must be x3 for some of the code below to work
 
;; Now, this is rather interesting.  We test for zero arguments
;; after the multiply.  Assuming random inputs, one or both are
;; zero (2^17-1)/2^32, or approximately 1/32768 of the time.
;; Encryption in any feedback mode produces essentially random
;; inputs, so average-case analysis is okay.  While we don't
;; want the out-of-line code to waste time, it is not worth
;; slowing down the in-line case to speed it up.
;;
;; Basically, we start inverting the source x, and if that was 0,
;; we use the inverse of the key instead.
 
Core1Z:
	neg	x0
	jnz	Core1Za
if USELODS
	sub	x0,[si-2]
else
	sub	x0,[si]
endif
Core1Za:
	inc	x0
	jmp	Core1done
Core2Z:
	neg	x3
	jnz	Core2Za
if USELODS
	sub	x3,[si-2]
else
	sub	x3,[si+6]
endif
Core2Za:
	inc	x3
	jmp	Core2done
Core3Z:
	neg	x2
	jnz	Core3Za
if USELODS
	sub	x2,[si-2]
else
	sub	x2,[si+8]
endif
Core3Za:
	inc	x2
	jmp	Core3done
Core4Z:
	neg	x1
	jnz	Core4Za
if USELODS
	sub	x1,[si-2]
else
	sub	x1,[si+10]
endif
Core4Za:
	inc	x1
	jmp	Core4done
 
; We need a constant 0 that we can move into a register without affecting
; the carry flag (as the classic xor ax,ax is wont to do), so we use the
; es register for a constant 0 source.  This is okay even in protected
; mode.  (I *told* you this was tricky code!)
 
; BTW, in case you want to know, this is 8 + 78*4 + 16 = 336 instructions.
 
Core	proc	near
	xor	ax,ax
	mov	es,ax
	mov	ax,OFFSET Finish
	push	ax
	mov	ax,OFFSET Coreloop
	push	ax	; Loop 3 times, then return
	push	ax
	push	ax
 
Coreloop:
if USELODS
	lodsw
else
	mov	ax,[si]	; x0 *= *key++
endif
	mul	x0
	sub	ax,dx
	jz	Core1Z
	mov	x0,es
	adc	x0,ax
Core1done:
 
if USELODS
	lodsw
	add	x1,ax
	lodsw
	add	x2,ax
else
	add	x1,[si+2]	; x1 += *key++
	add	x2,[si+4]	; x2 += *key++
endif
 
if USELODS
	lodsw
else
	mov	ax,[si+6]	; x3 += *key++
endif
	mul	x3
	sub	ax,dx
	jz	Core2Z
	mov	x3,es
	adc	x3,ax
Core2done:
 
	push	x1	; s1 = x1
	push	x2	; s2 = x2
 
	xor	x1,x3	; x1 ^= x3
	xor	x2,x0	; x2 ^= x0
 
if USELODS
	lodsw
else
	mov	ax,[si+8]	; x2 *= *key++
endif
	mul	x2
	sub	ax,dx
	jz	Core3Z
	mov	x2,es
	adc	x2,ax
Core3done:
 
	add	x1,x2	; x1 += x2
 
if USELODS
	lodsw
else
	mov	ax,[si+10]	; x1 *= *key++
endif
	mul	x1
	sub	ax,dx
	jz	Core4Z
	mov	x1,es
	adc	x1,ax
Core4done:
 
	add	x2,x1	; x2 += x1
 
	xor	x0,x1	; x0 ^= x1
	xor	x3,x2	; x3 ^= x2
 
	pop	dx
	xor	x1,dx	; x1 ^= s2
	pop	dx
	xor	x2,dx	; x2 ^= s1
 
; Second unrolling of loop
if USELODS
	lodsw
else
	mov	ax,[si+12]	; x0 *= *key++
endif
	mul	x0
	sub	ax,dx
	jz	Core5Z
	mov	x0,es
	adc	x0,ax
Core5done:
 
if USELODS
	lodsw
	add	x1,ax
	lodsw
	add	x2,ax
else
	add	x1,[si+14]	; x1 += *key++
	add	x2,[si+16]	; x2 += *key++
endif
 
if USELODS
	lodsw
else
	mov	ax,[si+18]	; x3 *= *key++
endif
	mul	x3
	sub	ax,dx
	jz	Core6Z
	mov	x3,es
	adc	x3,ax
Core6done:
 
	push	x1	; s1 = x1
	push	x2	; s2 = x2
 
	xor	x1,x3	; x1 ^= x3
	xor	x2,x0	; x2 ^= x0
 
if USELODS
	lodsw
else
	mov	ax,[si+20]	; x2 *= *key++
endif
	mul	x2
	sub	ax,dx
	jz	Core7Z
	mov	x2,es
	adc	x2,ax
Core7done:
 
	add	x1,x2	; x1 += x2
 
if USELODS
	lodsw
else
	mov	ax,[si+22]	; x1 *= *key++
endif
	mul	x1
	sub	ax,dx
	jz	Core8Z
	mov	x1,es
	adc	x1,ax
Core8done:
 
	add	x2,x1	; x2 += x1
 
	xor	x0,x1	; x0 ^= x1
	xor	x3,x2	; x3 ^= x2
 
	pop	dx
	xor	x1,dx	; x1 ^= s2
	pop	dx
	xor	x2,dx	; x2 ^= s1
 
ife USELODS
	lea	si,[si+24]
endif
 
	ret	; Used as a loop instruction!
 
Core5Z:
	neg	x0
	jnz	Core5Za
if USELODS
	sub	x0,[si-2]
else
	sub	x0,[si+12]
endif
Core5Za:
	inc	x0
	jmp	Core5done
Core6Z:
	neg	x3
	jnz	Core6Za
if USELODS
	sub	x3,[si-2]
else
	sub	x3,[si+18]
endif
Core6Za:
	inc	x3
	jmp	Core6done
Core7Z:
	neg	x2
	jnz	Core7Za
if USELODS
	sub	x2,[si-2]
else
	sub	x2,[si+20]
endif
Core7Za:
	inc	x2
	jmp	Core7done
Core8Z:
	neg	x1
	jnz	Core8Za
if USELODS
	sub	x1,[si-2]
else
	sub	x1,[si+22]
endif
Core8Za:
	inc	x1
	jmp	Core8done
Core9Z:
	neg	x0
	jnz	Core9Za
if USELODS
	sub	x0,[si-2]
else
	sub	x0,[si]
endif
Core9Za:
	inc	x0
	jmp	Core9done
; Special: compute into dx (zero on entry)
Core10Z:
	sub	dx,x3
	jnz	Core10Za
if USELODS
	sub	dx,[si-2]
else
	sub	dx,[si+6]
endif
Core10Za:
	inc	dx
;	jmp	Core10done
	ret
 
 
Finish:
if USELODS
	lodsw
else
	mov	ax,[si]	; x0 *= *key++
endif
	mul	x0
	sub	ax,dx
	jz	Core9Z
	mov	x0,es
	adc	x0,ax
Core9done:
 
	xchg	x1,x2
if USELODS
	lodsw
	add	x1,ax
	lodsw
	add	x2,ax
else
	add	x1,[si+2]	; x1 += *key++
	add	x2,[si+4]	; x2 += *key++
endif
 
; This is special: compute into dx, not x3
if USELODS
	lodsw
else
	mov	ax,[si+6]	; x3 *= *key++
endif
	mul	x3
	sub	ax,dx
	mov	dx,es
	jz	Core10Z
	adc	dx,ax
Core10done:
 
	ret
 
	endp
 
 
; Args are in, out, key
	public	_Idea2
_Idea2 proc far
	cld
	push	bp	; Args start at [bp+6]
	mov	bp,sp
	push	si
	push	di
	push	ds	; 6 more words here, so args are at [sp+12]
	lds	si,[bp+6]	; in
if DOSWAP
	lodsw
	xchg	ah,al
	mov	dx,ax
	lodsw
	xchg	ah,al
	mov	x1,ax
	lodsw
	xchg	ah,al
	mov	x2,ax
	lodsw
	xchg	ah,al
	mov	x3,ax
else
	les	dx,[si]
	mov	x1,es
	les	x2,[si+4]
	mov	x3,es
endif
	lds	si,[bp+14]	; key
 
	mov	x0,dx
 
	call	Core	; Returns results in x0/x1/x2/dx
 
	mov	ax,x0
	mov	bp,sp
	les	di,[bp+16]
if DOSWAP
	xchg	ah,al
endif
	stosw
	mov	ax,x1
if DOSWAP
	xchg	ah,al
endif
	stosw
	mov	ax,x2
if DOSWAP
	xchg	ah,al
endif
	stosw
	mov	ax,dx
if DOSWAP
	xchg	ah,al
endif
	stosw
 
	pop	ds
	pop	di
	pop	si
	pop	bp
 
	ret
 
	endp
 
; Okay, the basic plan for the CFB kernel is
; get x0,x1,x2,x3
; get key pointer
; call core
; get buffer pointers
;Loop:
; lodsw
; xor	ax,x0
; mov	x0,ax
; stosw
; lodsw
; xor	ax,x1
; mov	x0,ax
; stosw
; lodsw
; xor	ax,x2
; mov	x0,ax
; stosw
; lodsw
; xor	ax,x3
; mov	x3,ax
; stosw
; push buffer pointers
; get key pointer
; call	core
; pop buffer pointers
; loop
; lodsw/xor/etc.
;
;
; This function is designed to go in the middle of a byte-granularity
; CFB engine.  It performs "len" encryptions of the IV, encrypting
; 8*(len-1) bytes from the source to the destination.  The idea is
; that you first xor any odd leading bytes, then call this function,
; then xor up to 8 trailing bytes.
 
; The main loop in this is 38 instructions, plus the 336 for the core
; makes 374 total.  That's 46.75 instructions per byte.
; (It's the same for IdeaCFBx)
 
; IV, key, plain, cipher, len
	public	_IdeaCFB
_IdeaCFB proc far	; Args are at [sp+4]
	cld
	push	bp
	push	si
	push	di
	push	ds	; 8 more words here, so args are at [sp+12]
; To be precise, IV is at 12, key at 16, plain at 20,
; cipher at 24 and len at 28
	mov	bp,sp
	lds	si,[bp+12]	; IV
if DOSWAP
; Load and byte-swap IV
	mov	ax,[si]
	xchg	ah,al
	mov	x1,[si+2]
	mov	x2,[si+4]
	xchg	bh,bl
	xchg	ch,cl
	mov	dx,[si+6]
	xchg	dh,dl
 
	lds	si,[bp+16]	; Key
	mov	x0,ax
	mov	x3,dx
else
; Load IV
	mov	ax,[si]
	mov	x1,[si+2]
	mov	x2,[si+4]
	mov	d3,[si+6]
	lds	si,[bp+16]	; Key
	mov	x0,ax
endif
	
	call	Core
IdeaCFBLoop:
;	mov	ax,x0
;	mov	bp,sp
;	dec	WORD PTR [bp+28]	; Decrement count
;	jz	IdeaCFBEnd
;	lds	si,[bp+20]
;	les	di,[bp+24]
;	mov	x0,ax
; Alternate code: (which is faster?  Two moves or three segment overrides?)
	mov	si,sp
	dec	WORD PTR ss:[si+28]
	jz	IdeaCFBEnd
	les	di,ss:[si+24]
	lds	si,ss:[si+20]
 
if DOSWAP
	lodsw
	xchg	ah,al
	xor	ax,x0
	mov	x0,ax
	xchg	ah,al
	stosw

	lodsw
	xchg	ah,al
	xor	ax,x1
	mov	x1,ax
	xchg	ah,al
	stosw

	lodsw
	xchg	ah,al
	xor	ax,x2
	mov	x2,ax
	xchg	ah,al
	stosw

	lodsw
	xchg	ah,al
	xor	ax,dx
	mov	dx,ax
	xchg	ah,al
	stosw
else
	lodsw
	xor	ax,x0
	mov	x0,ax
	stosw

	lodsw
	xor	ax,x1
	mov	x1,ax
	stosw

	lodsw
	xor	ax,x2
	mov	x2,ax
	stosw

	lodsw
	xor	ax,dx
	mov	dx,ax
	stosw
endif
 
;	mov	ax,x0
;	mov	bp,sp
;	mov	[bp+20],si	; Save source offset
;	mov	[bp+24],di	; Save destination offset
;	lds	si,[bp+16]	; Key
;	mov	x0,ax	; Get x0 in place for another iteration
; Alternate code for the above: (which is faster?  One move or three ss:?)
	mov	ax,si
	mov	si,sp
	mov	ss:[si+20],ax
	mov	ss:[si+24],di
	lds	si,ss:[si+16]
 
	mov	x3,dx	; Get x3 in place
	mov	ax,OFFSET IdeaCFBLoop
	push	ax
	jmp	Core
 
IdeaCFBEnd:
;	lds	si,[bp+12]
	lds	di,ss:[si+12]	; Get IV for writing back
 
if DOSWAP
	mov	ax,x0
	xchg	ah,al
	mov	[di],ax	; Use stosw?
	xchg	bh,bl
	xchg	ch,cl
	mov	[di+2],x1
	mov	[di+4],x2
	xchg	dh,dl
	mov	[di+6],dx
else
	mov	[di],x0
	mov	[di+2],x1
	mov	[di+4],x2
	mov	[di+6],dx
endif
 
	pop	ds
	pop	di
	pop	si
	pop	bp
 
	ret
 
	endp
 
; This decoding step is similar, except that instead of
;	lods
;	xor	x0,ax
;	mov	ax,x0
;	stos
; the feedback step is
;	lods
;	xchg	x0,ax
;	xor	ax,x0
;	stos
 
; IV, key, cipher, plain, len
	public	_IdeaCFBx
_IdeaCFBx proc far	; Args are at [sp+4]
	cld
	push	bp
	push	si
	push	di
	push	ds	; 8 more words here, so args are at [sp+12]
	mov	bp,sp
	lds	si,[bp+12]	; IV
if DOSWAP
; Load and byte-swap IV
	mov	ax,[si]
	xchg	ah,al
	mov	x1,[si+2]
	mov	x2,[si+4]
	xchg	bh,bl
	xchg	ch,cl
	mov	dx,[si+6]
	xchg	dh,dl
 
	lds	si,[bp+16]	; Key
	mov	x0,ax
	mov	x3,dx
else
; Load IV
	mov	ax,[si]
	mov	x1,[si+2]
	mov	x2,[si+4]
	mov	d3,[si+6]
	lds	si,[bp+16]	; Key
	mov	x0,ax
endif
 
	call	Core
IdeaCFBxLoop:
;	mov	ax,x0
;	mov	bp,sp
;	dec	WORD PTR [bp+28]	; Decrement count
;	jz	IdeaCFBxEnd
;	lds	si,[bp+20]
;	les	di,[bp+24]
;	mov	x0,ax
; Alternate code: (which is faster?  Two moves or three segment overrides)
	mov	si,sp
	dec	WORD PTR ss:[si+28]
	jz	IdeaCFBxEnd
	les	di,ss:[si+24]
	lds	si,ss:[si+20]
 
if DOSWAP
	lodsw
	xchg	ah,al
	xchg	x0,ax
	xor	ax,x0
	xchg	ah,al
	stosw

	lodsw
	xchg	ah,al
	xchg	x1,ax
	xor	ax,x1
	xchg	ah,al
	stosw

	lodsw
	xchg	ah,al
	xchg	x2,ax
	xor	ax,x2
	xchg	ah,al
	stosw

	lodsw
	xchg	ah,al
	xchg	dx,ax
	xor	ax,dx
	xchg	ah,al
	stosw
else
	lodsw
	xchg	x0,ax
	xor	ax,x0
	stosw

	lodsw
	xchg	x1,ax
	xor	ax,x1
	stosw

	lodsw
	xchg	x2,ax
	xor	ax,x2
	stosw

	lodsw
	xchg	dx,ax
	xor	ax,dx
	stosw
endif
 
;	mov	ax,x0
;	mov	bp,sp
;	mov	[bp+20],si	; Save source offset
;	mov	[bp+24],di	; Save destination offset
;	lds	si,[bp+16]	; Key
;	mov	x0,ax	; Get x0 in place for another iteration
; Alternate code for the above: (which is faster?  One move or three ss:?)
	mov	ax,si
	mov	si,sp
	mov	ss:[si+20],ax
	mov	ss:[si+24],di
	lds	si,ss:[si+16]
 
	mov	x3,dx	; Get x3 in place
	mov	ax,OFFSET IdeaCFBxLoop
	push	ax
	jmp	Core
 
IdeaCFBxEnd:
;	lds	si,[bp+12]
	lds	di,ss:[si+12]	; Get IV for writing back
 
if DOSWAP
	mov	ax,x0
	xchg	ah,al
	mov	[di],ax	; Use stosw?
	xchg	bh,bl
	xchg	ch,cl
	mov	[di+2],x1
	mov	[di+4],x2
	xchg	dh,dl
	mov	[di+6],dx
else
	mov	[di],x0
	mov	[di+2],x1
	mov	[di+4],x2
	mov	[di+6],x3
endif 
 
	pop	ds
	pop	di
	pop	si
	pop	bp
 
	ret
 
	endp
 
 
 
	end
