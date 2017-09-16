;A while ago I posted a message claiming a speed of 238,000
;bytes/sec for an implementation of IDEA on a 33Mh 486.  Below is
;an explanation and some code to show how it works.  The basic
;trick should be useful on many (but not all) processors.  I
;expect only those familiar with IDEA and its reference
;implementation will be able to follow the discussion.  See:
;
;Lai, Xueja and Massey, James L.  A Proposal for a New Block
;Encryption Standard, Eurocrypt 90
;
;For those who have been asking for the code, sorry I kept
;putting it off.  I wanted to get it out of Turbo Pascal
;ideal-mode, but I never had the time.
;
;Colin Plum wrote IDEA-386 code which is included in PGP
;2.3a and uses the same tricks.  I don't know who's is
;faster, but I expect they will be very close.  Now
;here's how it's done.
;
;A major bottleneck in software IDEA is the mul() routine, which
;is used 34 times per 64 bit block.  The routine performs
;multiplication in the multiplicative group mod 2^16+1.  The two
;factors are each in a 16 bit word, and the output is also in a 16
;bit word.  Note that 0 is not a member of the multiplicative
;group and 2^16 does not fit in 16 bits. We therefor use the 0
;word to represent 2^16.  Now group elements map one to one onto
;all possible 16 bit words, since 2^16+1 is prime.
;
;Here is (essentially) the reference implementation from [Lai].
;
;
;unsigned mul( unsigned a, unsigned b ) {
;  long int p ;
;  long unsigned q ;
;	if( a==0 ) p= 0x00010001 - b ;
;	else if( b==0 ) p= 0x00010001 - a ;
;	else {
;		q= a*b;
;		p= (q & 0xffff) - (q>>16)
;		if( p<0 ) p= p + 0x00010001 ;
;	  }
;	return (unsigned)(p & 0xffff) ;
;}
;
;
;Note the method of reducing a 32 bit word modulo 2^16-1.  We
;subtract the high word from the low word, and add the modulus
;back if the result is less than 0.  [Lai] contains a proof that
;this works, and you can convince yourself fairly easily.
;
;To speed up this routine, we note that the tests for a=0 and b=0
;will rarely be false.  With the possible exception of the first 2
;of the 34 multiplications, 0 should be no more likely than any of
;the other 65535 numbers.  Note that if (and only if) either a or
;b is 0 then q will also be 0, and we can check for this in one
;instruction if our processor sets a zero flag for multiplication
;(as the 68000 does but 80x86 does not).
;
;Fortunately p will also be zero after the subtraction if and only
;if either a or b is 0.  Proof: r will be zero when the high order
;word of q equals the low order word, and that happens when q is
;divisible by 00010001 hex.  Since 00010001h = 2^16+1 is prime,
;this happens if either a or b is a multiple of 2^16+1, and 0 is
;the only such multiple which will fit in a 16 bit word.
;
;The speed-up strategy is to proceed under the assumption that a
;and b are not 0, check to be sure in one instruction, and
;recompute if the assumption was wrong.  Here's some 8086
;assembler code:
;
;	mov  ax, [a]
;	mul  [b]        ; ax is implied. q is now in DX AX
;	sub  ax, dx     ; mod 2^16+1
;	jnz  not0       ; Jump if neither op was 0. Usually taken.
;
;	mov  ax, 1      ; recompute result knowing one op is 0.
;	sub  ax, [a]
;	sub  ax, [b]
;	jmp  out        ; Just jump over adding the carry.
;not0:
;	adc  ax, 0      ; If r<0 add 1, otherwise do nothing.
;out:                ; Result is now in ax
;
;
;Note that when r<0 we add 1 instead of 2^16+1 since the 2^16 part
;overflows out of the result.  The "adc  ax, 0" does all the work
;of checking for a negative result and adding the modulus if
;needed.
;
;The multiplication takes 9 instructions, 4 of which are rarely
;executed.  I believe similar tricks are possible on many
;processors.  The one drawback to the check-after-multiply tactic
;is that we can't let the multiply overwrite the only copy of an
;operand.
;
;Note that most software implementations of IDEA will run at
;slightly different speeds when 0's come up in the multiply
;routine.  The reference implementation is faster on 0, this one
;is faster on non-zero.  This may be a problem for some real-time
;stuff, and also suggests an attack based on timing.
;
;Finally, below is an implementation of the complete encryption
;function in 8086 assembler, to replace the cipher_idea() function
;in PGP.  It takes the same parameters as the function from PGP,
;and uses the c language calling conventions.  I tested it using
;the debug features of the idea.c file in PGP.  You will need to
;add segment/assume directives.  This version uses no global data
;and should be reentrant.
;
;The handling of zero multipliers is outside the inner loop so
;that a short conditional jump can loop back to the beginning.
;Forward conditional jumps are usually not taken and backward
;jumps are usually taken, which is consistent with 586 branch
;prediction (or so I've heard).  Stalls where the output of one
;instruction is needed for the next seem unavoidable.
;
;Last I heard, IDEA was patent pending.  My code is up for grabs,
;although I would get a kick out being credited if you use it.
;On the other hand Colin's code is already tested and ready
;to assemble and link with PGP.
;
;--Bryan
;
;____________________CODE STARTS BELOW THIS LINE_________

;  Called as: asmcrypt( inbuff, outbuff, zkey ) just like PGP

PROC    _asmcrypt

        ; establish parameter and local space on stack
        ; follow c language calling conventions

        ARG  inblock:Word, outblock:Word, zkey:Word
        LOCAL sx1:Word,sx4:Word,skk:Word,done8:Word =stacksize

        push bp
        mov  bp, sp
        sub  sp, stacksize

 ;      push ax     ; My compiler assumes these are not saved.
 ;      push bx
 ;      push cx
 ;      push dx

        push si
        push di

; Put the 16 bit sub-blocks in registers and/or local variables
        mov  si, [inblock]
        mov  ax, [si]
        mov  [sx1], ax       ; x1  is in ax and sx1
        mov  di, [si+2]      ; x2  is in di
        mov  bx, [si+4]      ; x3  is in bx
        mov  dx, [si+6]
        mov  [sx4], dx       ; x4  is in sx4

        mov  si, [zkey]      ; si points to next subkey
        mov  [done8], si
        add  [done8], 96     ; we will be finished with 8 rounds
                             ; when si=done8

@@loop:                      ; 8 rounds of this
        add  di, [si+2]      ; x2+=zkey[2]  is in di
        add  bx, [si+4]      ; x3+=zkey[4]  is in bx

        mul  [Word si]       ;x1 *= zkey[0]
        sub  ax, dx
        jz  @@x1             ; if 0, use special case multiply
        adc  ax, 0
@@x1out:
        mov  [sx1], ax       ; x1 is in ax and sx1

        xor  ax, bx          ; ax= x1^x3
        mul  [Word si+8]     ; compute kk
        sub  ax, dx          ; if 0, use special case multiply
        jz  @@kk
        adc  ax, 0
@@kkout:
        mov  cx, ax          ; kk is in cx

        mov  ax, [sx4]       ; x4 *= zkey[6]
        mul  [Word si+6]
        sub  ax, dx
        jz   @@x4            ; if 0, use special case multiply
        adc  ax, 0
@@x4out:
        mov  [sx4], ax       ; x4 is in sx4 and ax

        xor  ax, di          ; x4^x2
        add  ax, cx          ; kk+(x2^x4)
        mul  [Word si+10]    ; compute t1
        sub  ax, dx
        jz  @@t1             ; if 0, use special case multiply
        adc  ax, 0
@@t1out:                     ; t1 is in ax

        add  cx, ax          ; t2 is in cx   kk+t1

        xor  [sx4], cx       ; x4 in sx4
        xor  di, cx          ; new x3 in di
        xor  bx, ax          ; new x2 in bx
        xchg bx, di          ; x2 in di, x3 in bx
        xor  ax, [sx1]       ; x1 in ax
        mov  [sx1], ax       ; and [sx1]

        add  si, 12          ; point to next subkey
        cmp  si, [done8]
        jne  @@loop
        jmp  @@out8

;------------------------------------------
; Special case multiplications, when one factor is 0

@@x1:   mov  ax, 1
        sub  ax, [sx1]
        sub  ax, [Word si]
        jmp  @@x1out

@@kk:   mov  ax, [sx1]       ; rebuild overwritten operand
        xor  ax, bx
        neg  ax
        inc  ax
        sub  ax, [si+8]
        jmp  @@kkout

@@x4:   mov  ax, 1
        sub  ax, [sx4]
        sub  ax, [Word si+6]
        jmp  @@x4out

@@t1:   mov  ax, [sx4]       ; rebuild
        xor  ax, di
        add  ax, cx
        neg  ax
        inc  ax
        sub  ax, [si+10]
        jmp  @@t1out

;---------------------------------------------------
;   8 rounds are done, now that extra pseudo-round

@@out8:
        push di
        mov  di, [outblock]

        mul  [Word si]
        sub  ax, dx
        jnz  @@o1n           ; jump over special case code
        mov  ax, 1
        sub  ax, [sx1]
        sub  ax, [si]
        jmp  @@o1out
@@o1n:  adc  ax, 0
@@o1out:  mov [di], ax       ; final ciphertext block 1

        mov  ax, [sx4]
        mul  [Word si+6]
        sub  ax, dx
        jnz  @@o4n           ; jump over special case code
        mov  ax, 1
        sub  ax, [sx4]
        sub  ax, [si+6]
        jmp  @@o4out
@@o4n:  adc  ax, 0
@@o4out: mov  [di+6], ax     ; final ciphertext block 4

        add  bx, [si+2]
        mov  [di+2], bx      ; final ciphertext block 2
        pop  ax
        add  ax, [si+4]
        mov  [di+4], ax      ; final ciphertext block 3

;  Restore the stack and return

        pop  di
        pop  si
;       pop  dx
;       pop  cx
;       pop  bx
;       pop  ax

        mov  sp, bp
        pop  bp
        ret
ENDP    _asmcrypt
