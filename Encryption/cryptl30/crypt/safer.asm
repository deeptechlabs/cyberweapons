		INCLUDE MISC.INC
		MODULE SAFER

		.386

		PUBLIC	_saferEncryptBlock, _saferDecryptBlock

; Code to implement the improved SAFER-SK form of the SAFER cipher,
; originally published as "SAFER K-64: A Byte-Oriented Block-Ciphering
; Algorithm", James L. Massey, "Fast Software Encryption", Lecture Notes in
; Computer Science No. 809, Springer-Verlag 1994, p.1.  This code implements
; the 128-bit key extension designed by the Special Projects Team of the
; Ministry of Home Affairs, Singapore and published as "SAFER K-64: One Year
; Later", James L.Massey, presented at the K. U. Leuven Workshop on
; Algorithms, Leuven, Belgium, 14-16 December, 1994, to appear in "Fast
; Software Encryption II", Lecture Notes in Computer Science, Springer-Verlag
; 1995, along with Lars Knudsen's strengthened key schedule, presented in
; "A Key-Schedule Weakness in SAFER K-64," Lars Knudsen, presented at Crypto
; '95 in Santa Barbara, California.
;
; All parts of the SAFER-SK algorithm are non-proprietary and freely
; available for anyone to use as they see fit.
;
; Written 4 December 1995, Peter Gutmann <pgut01@cs.auckland.ac.nz>.
;
; This version is about 3 times as fast as the C implementation.

; The two-point Pseudo-Hadamard Transform
;
;	b1 = 2a1 + a2
;	b2 =  a1 + a2
;
; and inverse two-point Pseudo-Hadamard Transform
;
;	a1 =  b1 -  b2
;	a2 = -b1 + 2b2
;
; which are used to create a three-dimensional PHT (ie independant two-point
; PHT's in each of three dimensions, which is why there are 2^3 = 8 bytes in
; the input and output of the PHT) through a decimation-by-two/fanning-out-
; by-two network.  The PHT provides guaranteed complete diffusion within one
; linear layer.

PHT1 MACRO x, y
	add y, x
ENDM

PHT2 MACRO x, y
	add x, y
ENDM

IPHT1 MACRO x, y
	sub x, y
ENDM

IPHT2 MACRO x, y
	sub y, x
ENDM

; Since we have a great many independant operations we can interleave the two
; parts of the transform:
;
;	PHT(x,y) -> { y += x; x += y; }
;
; with the PHT's surrounding it to eliminate pipeline stalls, and the same
; for the IPHT.  Therefore we define the PHT in two parts PHT1 and PHT2 with
; a four-instruction interleave between the halves.

interleavePHT MACRO a, b, c, d, e, f, g, h
	PHT1 a, b
	PHT1 c, d
	PHT1 e, f
	PHT1 g, h
	PHT2 a, b						; PHT( a, b );
	PHT2 c, d						; PHT( c, d );
	PHT2 e, f						; PHT( e, f );
	PHT2 g, h						; PHT( g, h );
ENDM

interleaveIPHT MACRO a, b, c, d, e, f, g, h
	IPHT1 a, b
	IPHT1 c, d
	IPHT1 e, f
	IPHT1 g, h
	IPHT2 a, b						; PHT( a, b );
	IPHT2 c, d						; PHT( c, d );
	IPHT2 e, f						; PHT( e, f );
	IPHT2 g, h						; PHT( g, h );
ENDM

; Load the word register corresponding to a byte half-register into an
; address-capable word register in preparation for using it to index memory.

loadWordReg MACRO wordReg, byteReg
  IF byteReg EQ al OR byteReg EQ ah
	mov wordReg, ax
  ELSEIF byteReg EQ bl OR byteReg EQ bh
	mov wordReg, bx
  ELSEIF byteReg EQ cl OR byteReg EQ ch
	mov wordReg, cx
  ELSEIF byteReg EQ dl OR byteReg EQ dh
	mov wordReg, dx
  ELSE
	ERROR Incorrect byte register passed to loadWordReg
  ENDIF
ENDM

; Perform the mixed xor/byte addition of the round input with the subkey
; K2i-1, combined with the first level of the nonlinear layer, either
; 45^n mod 257 or log45n, and the mixed xor/byte addition with the subkey
; K2i.  We interleave two sets of operations to reduce pipeline stalls and
; make the maximum use of all available registers.

nonLinear MACRO reg1, op1, table1, reg2, op2, table2, keyOfs
	op1 reg1, es:[di+keyOfs]
	op2 reg2, es:[di+keyOfs+1]
	loadWordReg si, reg1
	loadWordReg bp, reg2
	and si, 0FFh
	shr bp, 8
	mov reg1, es:[di+keyOfs+8]
	mov reg2, es:[di+keyOfs+9]
	op2 reg1, table1[si]
	op1 reg2, table2[bp]
ENDM

; Perform the mixed xor/byte addition of the inverse PHT output with the
; subkey K2r+2-2i, combined with the second level of the nonlinear layer,
; either 45^n mod 257 or log45n, and finally the mixed xor/byte addition of
; the round output with K2r+1-2i.  We interleave two sets of operations to
; reduce pipeline stalls and make the maximum use of all available registers.

nonLinearInv MACRO reg1, op1, table1, reg2, op2, table2, keyOfs
	op1 reg1, es:[di+keyOfs]
	op2 reg2, es:[di+keyOfs-1]
	loadWordReg si, reg1
	loadWordReg bp, reg2
	shr si, 8
	and bp, 0FFh
	mov reg1, table1[si]
	mov reg2, table2[bp]
	op2 reg1, es:[di+keyOfs-8]
	op1 reg2, es:[di+keyOfs-9]
ENDM

; Rotate three bytes by one byte to the left.  This transforms a b c to
; b c a in two swaps.

swapData MACRO a, b, c
	xchg a, c
	xchg a, b
ENDM

; Symbolic defines for the byte values used in SAFER

A	EQU		al
B	EQU		ah
C	EQU		bl
D	EQU		bh
E	EQU		cl
F	EQU		ch
G	EQU		dl
H	EQU		dh

		DATA

; The lookup table for logs and exponents.  These contain the powers of the
; primitive element 45 of GF( 257 ) (ie values of 45^n mod 257) in "expTable"
; with the corresponding logs base 45 stored in "logTable".  They may be
; calculated as follows:
;
;	exponent = 1;
;	for( i = 0; i < 256; i++ )
;		{
;		int exp = exponent & 0xFF;
;
;		expTable[ i ] = exp;
;		logTable[ exp ] = i;
;		exponent = ( exponent * 45 ) % 257;
;		}

expTable	DB	001h, 02Dh, 0E2h, 093h, 0BEh, 045h, 015h, 0AEh
			DB	078h, 003h, 087h, 0A4h, 0B8h, 038h, 0CFh, 03Fh
			DB	008h, 067h, 009h, 094h, 0EBh, 026h, 0A8h, 06Bh
			DB	0BDh, 018h, 034h, 01Bh, 0BBh, 0BFh, 072h, 0F7h
			DB	040h, 035h, 048h, 09Ch, 051h, 02Fh, 03Bh, 055h
			DB	0E3h, 0C0h, 09Fh, 0D8h, 0D3h, 0F3h, 08Dh, 0B1h
			DB	0FFh, 0A7h, 03Eh, 0DCh, 086h, 077h, 0D7h, 0A6h
			DB	011h, 0FBh, 0F4h, 0BAh, 092h, 091h, 064h, 083h
			DB	0F1h, 033h, 0EFh, 0DAh, 02Ch, 0B5h, 0B2h, 02Bh
			DB	088h, 0D1h, 099h, 0CBh, 08Ch, 084h, 01Dh, 014h
			DB	081h, 097h, 071h, 0CAh, 05Fh, 0A3h, 08Bh, 057h
			DB	03Ch, 082h, 0C4h, 052h, 05Ch, 01Ch, 0E8h, 0A0h
			DB	004h, 0B4h, 085h, 04Ah, 0F6h, 013h, 054h, 0B6h
			DB	0DFh, 00Ch, 01Ah, 08Eh, 0DEh, 0E0h, 039h, 0FCh
			DB	020h, 09Bh, 024h, 04Eh, 0A9h, 098h, 09Eh, 0ABh
			DB	0F2h, 060h, 0D0h, 06Ch, 0EAh, 0FAh, 0C7h, 0D9h
			DB	000h, 0D4h, 01Fh, 06Eh, 043h, 0BCh, 0ECh, 053h
			DB	089h, 0FEh, 07Ah, 05Dh, 049h, 0C9h, 032h, 0C2h
			DB	0F9h, 09Ah, 0F8h, 06Dh, 016h, 0DBh, 059h, 096h
			DB	044h, 0E9h, 0CDh, 0E6h, 046h, 042h, 08Fh, 00Ah
			DB	0C1h, 0CCh, 0B9h, 065h, 0B0h, 0D2h, 0C6h, 0ACh
			DB	01Eh, 041h, 062h, 029h, 02Eh, 00Eh, 074h, 050h
			DB	002h, 05Ah, 0C3h, 025h, 07Bh, 08Ah, 02Ah, 05Bh
			DB	0F0h, 006h, 00Dh, 047h, 06Fh, 070h, 09Dh, 07Eh
			DB	010h, 0CEh, 012h, 027h, 0D5h, 04Ch, 04Fh, 0D6h
			DB	079h, 030h, 068h, 036h, 075h, 07Dh, 0E4h, 0EDh
			DB	080h, 06Ah, 090h, 037h, 0A2h, 05Eh, 076h, 0AAh
			DB	0C5h, 07Fh, 03Dh, 0AFh, 0A5h, 0E5h, 019h, 061h
			DB	0FDh, 04Dh, 07Ch, 0B7h, 00Bh, 0EEh, 0ADh, 04Bh
			DB	022h, 0F5h, 0E7h, 073h, 023h, 021h, 0C8h, 005h
			DB	0E1h, 066h, 0DDh, 0B3h, 058h, 069h, 063h, 056h
			DB	00Fh, 0A1h, 031h, 095h, 017h, 007h, 03Ah, 028h

logTable	DB	080h, 000h, 0B0h, 009h, 060h, 0EFh, 0B9h, 0FDh
			DB	010h, 012h, 09Fh, 0E4h, 069h, 0BAh, 0ADh, 0F8h
			DB	0C0h, 038h, 0C2h, 065h, 04Fh, 006h, 094h, 0FCh
			DB	019h, 0DEh, 06Ah, 01Bh, 05Dh, 04Eh, 0A8h, 082h
			DB	070h, 0EDh, 0E8h, 0ECh, 072h, 0B3h, 015h, 0C3h
			DB	0FFh, 0ABh, 0B6h, 047h, 044h, 001h, 0ACh, 025h
			DB	0C9h, 0FAh, 08Eh, 041h, 01Ah, 021h, 0CBh, 0D3h
			DB	00Dh, 06Eh, 0FEh, 026h, 058h, 0DAh, 032h, 00Fh
			DB	020h, 0A9h, 09Dh, 084h, 098h, 005h, 09Ch, 0BBh
			DB	022h, 08Ch, 063h, 0E7h, 0C5h, 0E1h, 073h, 0C6h
			DB	0AFh, 024h, 05Bh, 087h, 066h, 027h, 0F7h, 057h
			DB	0F4h, 096h, 0B1h, 0B7h, 05Ch, 08Bh, 0D5h, 054h
			DB	079h, 0DFh, 0AAh, 0F6h, 03Eh, 0A3h, 0F1h, 011h
			DB	0CAh, 0F5h, 0D1h, 017h, 07Bh, 093h, 083h, 0BCh
			DB	0BDh, 052h, 01Eh, 0EBh, 0AEh, 0CCh, 0D6h, 035h
			DB	008h, 0C8h, 08Ah, 0B4h, 0E2h, 0CDh, 0BFh, 0D9h
			DB	0D0h, 050h, 059h, 03Fh, 04Dh, 062h, 034h, 00Ah
			DB	048h, 088h, 0B5h, 056h, 04Ch, 02Eh, 06Bh, 09Eh
			DB	0D2h, 03Dh, 03Ch, 003h, 013h, 0FBh, 097h, 051h
			DB	075h, 04Ah, 091h, 071h, 023h, 0BEh, 076h, 02Ah
			DB	05Fh, 0F9h, 0D4h, 055h, 00Bh, 0DCh, 037h, 031h
			DB	016h, 074h, 0D7h, 077h, 0A7h, 0E6h, 007h, 0DBh
			DB	0A4h, 02Fh, 046h, 0F3h, 061h, 045h, 067h, 0E3h
			DB	00Ch, 0A2h, 03Bh, 01Ch, 085h, 018h, 004h, 01Dh
			DB	029h, 0A0h, 08Fh, 0B2h, 05Ah, 0D8h, 0A6h, 07Eh
			DB	0EEh, 08Dh, 053h, 04Bh, 0A1h, 09Ah, 0C1h, 00Eh
			DB	07Ah, 049h, 0A5h, 02Ch, 081h, 0C4h, 0C7h, 036h
			DB	02Bh, 07Fh, 043h, 095h, 033h, 0F2h, 06Ch, 068h
			DB	06Dh, 0F0h, 002h, 028h, 0CEh, 0DDh, 09Bh, 0EAh
			DB	05Eh, 099h, 07Ch, 014h, 086h, 0CFh, 0E5h, 042h
			DB	0B8h, 040h, 078h, 02Dh, 03Ah, 0E9h, 064h, 01Fh
			DB	092h, 090h, 07Dh, 039h, 06Fh, 0E0h, 089h, 030h

; Temporary variables

rounds		DW	0

		CODE

; Encrypt a block of data with SAFER.

_saferEncryptBlock PROC FAR
	push bp
	mov bp, sp
	push si
	push di							; Save register vars

	; Copy the input block to machine registers
	les di, [bp+6]					; ES:DI = data
	mov ax, es:[di]					; a = data[ 0 ]; b = data[ 1 ];
	mov bx, es:[di+2]				; c = data[ 2 ]; d = data[ 3 ];
	mov cx, es:[di+4]				; e = data[ 4 ]; f = data[ 5 ];
	mov dx, es:[di+6]				; g = data[ 6 ]; h = data[ 7 ];

	; Remember the number of rounds
	push bp							; Save temporary register
	les di, [bp+10]					; ES:DI = key
	mov bp, es:[di]
	and bp, 0FFh					; BP = rounds
	mov rounds, bp
	inc di

@@encryptLoop:
	; Perform the mixed xor/byte addition of the round input with the subkey
	; K2i-1, combined with the first level of the nonlinear layer, either
	; 45^n mod 257 or log45n, and the mixed xor/byte addition with the subkey
	; K2i.
	nonLinear A, xor, expTable, B, add, logTable, 0
	nonLinear C, add, logTable, D, xor, expTable, 2
	nonLinear E, xor, expTable, F, add, logTable, 4
	nonLinear G, add, logTable, H, xor, expTable, 6

	; Perform the Pseudo-Hadamard Trasform of the round output.
	interleavePHT A, B, C, D, E, F, G, H
	interleavePHT A, C, E, G, B, D, F, H
	interleavePHT A, E, B, F, C, G, D, H

	; Swap the data octets around.  If we unrol the loop we can eliminate
	; this step through register renaming, although at four instructions
	; total it's not a major performance hit.
	swapData B, E, C
	swapData D, F, G

	; Prepare for the next round
	add di, 16						; key += 16;
	dec rounds
	jnz @@encryptLoop
	pop bp							; Restore temporary register

	; Perform the final mixed xor/byte addition output transformation using
	; K2r + 1
	xor A, es:[di+0]				; data[ 0 ] = a ^ key[ 0 ];
	add B, es:[di+1]				; data[ 1 ] = b + key[ 1 ];
	add C, es:[di+2]				; data[ 2 ] = c + key[ 2 ];
	xor D, es:[di+3]				; data[ 3 ] = d ^ key[ 3 ];
	xor E, es:[di+4]				; data[ 4 ] = e ^ key[ 4 ];
	add F, es:[di+5]				; data[ 5 ] = f + key[ 5 ];
	add G, es:[di+6]				; data[ 6 ] = g + key[ 6 ];
	xor H, es:[di+7]				; data[ 7 ] = h ^ key[ 7 ];
	les di, [bp+6]					; ES:DI = data
	mov es:[di+0], A
	mov es:[di+1], B
	mov es:[di+2], C
	mov es:[di+3], D
	mov es:[di+4], E
	mov es:[di+5], F
	mov es:[di+6], G
	mov es:[di+7], H

	pop di
	pop si							; Restore register vars
	pop bp
	ret
_saferEncryptBlock ENDP

; Decrypt a block of data with SAFER.

_saferDecryptBlock PROC FAR
	push bp
	mov bp, sp
	push si
	push di							; Save register vars

	; Copy the input block to machine registers
	les di, [bp+6]					; ES:DI = data
	mov ax, es:[di]					; a = data[ 0 ]; b = data[ 1 ];
	mov bx, es:[di+2]				; c = data[ 2 ]; d = data[ 3 ];
	mov cx, es:[di+4]				; e = data[ 4 ]; f = data[ 5 ];
	mov dx, es:[di+6]				; g = data[ 6 ]; h = data[ 7 ];

	; Remember the number of rounds
	push bp							; Save temporary register
	les di, [bp+10]					; ES:DI = key
	mov bp, es:[di]
	and bp, 0FFh					; BP = rounds
	mov rounds, bp

	; Since we're now running throught the algorithm backwards, we move to
	; the end of the key and start from there.
	add bp, bp
	inc bp
	shl bp, 3
	add di, bp						; key += SAFER_BLOCKSIZE * ( 1 + 2 * rounds );

	; Perform the initial mixed xor/byte addition input transformation
	; using K2r+1.
	xor A, es:[di-7]				; data[ 0 ] = a ^ key[ -7 ];
	sub B, es:[di-6]				; data[ 1 ] = b - key[ -6 ];
	sub C, es:[di-5]				; data[ 2 ] = c - key[ -5 ];
	xor D, es:[di-4]				; data[ 3 ] = d ^ key[ -4 ];
	xor E, es:[di-3]				; data[ 4 ] = e ^ key[ -3 ];
	sub F, es:[di-2]				; data[ 5 ] = f - key[ -2 ];
	sub G, es:[di-1]				; data[ 6 ] = g - key[ -1 ];
	xor H, es:[di-0]				; data[ 7 ] = h ^ key[ 0 ];
	sub di, 8						; key -= 8;

@@decryptLoop:
	; Swap the data octets around.  If we unrol the loop we can eliminate
	; this step through register renaming, although at four instructions
	; total it's not a major performance hit.
	swapData E, B, C
	swapData F, D, G

	; Perform the inverse Pseudo-Hadamard Trasform of the round input.
	interleaveIPHT A, E, B, F, C, G, D, H
	interleaveIPHT A, C, E, G, B, D, F, H
	interleaveIPHT A, B, C, D, E, F, G, H

	; Perform the mixed xor/byte addition of the inverse PHT output with
	; the subkey K2r+2-2i, combined with the second level of the nonlinear
	; layer, either 45^n mod 257 or log45n, and finally the mixed xor/byte
	; addition of the round output with K2r+1-2i.
	nonLinearInv H, sub, logTable, G, xor, expTable, 0
	nonLinearInv F, xor, expTable, E, sub, logTable, -2
	nonLinearInv D, sub, logTable, C, xor, expTable, -4
	nonLinearInv B, xor, expTable, A, sub, logTable, -6

	; Prepare for the next round
	sub di, 16						; key -= 16;
	dec rounds
	jnz @@decryptLoop
	pop bp							; Restore temporary register

	; Copy the result back to the data buffer
	les di, [bp+6]					; ES:DI = data
	mov es:[di+0], A
	mov es:[di+1], B
	mov es:[di+2], C
	mov es:[di+3], D
	mov es:[di+4], E
	mov es:[di+5], F
	mov es:[di+6], G
	mov es:[di+7], H

	pop di
	pop si							; Restore register vars
	pop bp
	ret
_saferDecryptBlock ENDP
	ENDMODULE
