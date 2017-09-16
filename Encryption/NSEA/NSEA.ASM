; Fast ASM routines to implement the NSEA core encryption routine.  Note
; that this code does not include CBC handling, thought it can easily be
; added
;
; Written 21 April 1992 by Peter C.Gutmann

		.MODEL COMPACT

		LOCALS	@@

; Define the following to include a 32-bit version of the core encryption
; code

DO_32BIT	EQU		1

; Various external vars

		EXTRN	_sBoxBase : WORD
		EXTRN	_tempKey : DWORD
		EXTRN	_lcrngNumber : WORD

		EXTRN	_initIV : PROC
		EXTRN	_encryptCFB : PROC

		.CODE

; The size of the S-Boxes

SBOX_SIZE	EQU		1024			; 256 * sizeof( LONG )

;****************************************************************************
;*																			*
;*								Key Setup Routines							*
;*																			*
;****************************************************************************

		PUBLIC	_rnd
		PUBLIC	_initSBoxes			; Make them externally visible

; WORD rnd( void )

_rnd PROC NEAR
	mov ax, _lcrngNumber			; ax = X
	mov bx, 23311
	mul bx							; DX:AX = X * a
	add ax, 1
	adc dx, 0						; DX:AX = X * a + c
	mov bx, 65533
	div bx
	mov ax, dx						; ax = ( X * a + c ) mod m
	mov _lcrngNumber, ax
	ret
_rnd ENDP

; void setInitialSBox( BYTE *sBox -> ES )

setInitialSBox PROC NEAR
	; for( i = 0; i < 256; i++ )
	; 	for( j = 0; j < sizeof( LONG ); j++ )
	;		sBox[ index++ ] = i;
	xor ax, ax						; i = 0
@@loop:
	stosw							; Set low word of sBox
	stosw							; Set high word of sBox
	inc ah
	inc al							; i++
	jnz SHORT @@loop				; Continue if i < 256
	ret
setInitialSBox ENDP

; void initTempKey( WORD salt -> bx, BYTE *tempKeyPtr -> ES:DI )

initTempKey PROC NEAR
	; while( keyLength-- )
	;	salt = ( salt << 1 ) ^ *key++;
	; initRnd( salt );
	push ds
	lds si, [bp+4]					; Point DS:SI at key
	mov cx, [bp+8]					; cx = keyLength
@@saltLoop:
	shl bx, 1						; salt = salt << 1
	lodsb
	xor bl, al						; salt ^= key[ i ]
	loop @@saltLoop
	pop ds
	mov _lcrngNumber, bx			; initRnd( salt );

	; for( i = 0; i < SBOX_SIZE; i++ )
	;	*tempKeyPtr++ = ( BYTE ) ( rnd() >> 8 );
	mov cx, SBOX_SIZE
@@keyLoop:
	call _rnd						; ax = rnd()
	mov al, ah
	stosb							; tempKey[ i ] = ( BYTE ) ( rnd() >> 8 );
	loop @@keyLoop

	ret
initTempKey ENDP

; void permuteSBox( BYTE *sBox -> ES, int tempKeyIndex -> AX )

permuteSBox PROC NEAR
	push ds							; Save DS
	lds si, _tempKey
	add si, ax						; Point DS:SI at tempKey

	; for( srcIndex = 0; srcIndex < SBOX_SIZE; srcIndex++ )
	;	{
	;	destIndex = tempKey[ tempKeyIndex++ ] + columnTable[ srcIndex & 3 ];
	;
	;	temp = sBox[ srcIndex ];
	;	sBox[ srcIndex ] = sBox[ destIndex ];
	;	sBox[ destIndex ] = temp;
	;	}
	xor ax, ax
	mov bx, -256
	xor di, di						; srcIndex = 0
@@loop:
	add bx, 256
	and bx, 0300h					; bx = ( srcIndex + 256 ) & 0x300;
	lodsb							; ax = tempKey[ tempKeyIndex++ ]
	add bx, ax						; bx = destIndex

	mov al, es:[di]					; temp = sBox[ srcIndex ]
	xchg es:[bx], al				; sBox[ destIndex ] = temp
	stosb							; sBox[ srcIndex++ ] = sBox[ destIndex ]

	cmp di, SBOX_SIZE				; Check if reached and of range
	jne @@loop						; No, continue

	pop ds							; Restore DS
	ret
permuteSBox ENDP

; void initSBoxes( const BYTE *key, const int keyLength, const WORD salt )

_initSBoxes PROC NEAR
	push bp
	mov bp, sp
	push si
	push di							; Save register vars

	; Set up initial sBoxes
	mov es, _sBoxBase
	xor di, di						; Point ES:DI at sBox1
	call setInitialSBox				; setInitialSBox( sBox1 );
	call setInitialSBox				; setInitialSBox( sBox2 );

	; Generate the salt and initialise the LCRNG
	; for( i = 0; i < keyLength; i++ )
	;	salt = ( salt << 1 ) ^ key[ i ];
	; initRnd( salt );
	mov bx, [bp+10]					; bx = ( WORD ) salt
	les di, _tempKey				; Point ES:DI at tempKey
	call initTempKey
	mov bx, [bp+12]					; bx = ( WORD ) ( salt >> 16 )
	call initTempKey

	; Permute the S-Boxes in a pseudo-random manner
	mov es, _sBoxBase
	xor ax, ax
	call permuteSBox				; permuteSBox( sBoxByte1, 0 );
	mov ax, es
	add ax, SBOX_SIZE SHR 4
	mov es, ax						; Point ES to sBoxes2
	mov ax, SBOX_SIZE
	call permuteSBox				; permuteSBox( sBoxByte2, SBOX_SIZE );

	; Encrypt the key using the standard S-Boxes
	; initIV( salt );
	; tempKey[ 0 ] = ( BYTE ) ( keyLength >> 8 );
	; tempKey[ 1 ] = ( BYTE ) keyLength;
	; memcpy( tempKey + 2, key, keyLength );
	; memset( tempKey + 2 + keyLength, 0, \
	;		( SBOX_SIZE * 2 ) - ( keyLength + 2 ) );
	; encryptCFB( tempKey, SBOX_SIZE * 2 );
	push [bp+12]
	push [bp+10]					; Push salt
	call _initIV					; initCFB( key, keyLength, salt );
	add sp, 4						; Clean up stack
	les di, _tempKey				; Point ES:DI at tempKey
	mov ax, [bp+8]					; ax = keyLength
	xchg ah, al
	stosb							; tempKey[ 0 ] = ( BYTE ) ( keyLength >> 8 );
	xchg ah, al
	stosb							; tempKey[ 1 ] = ( BYTE ) keyLength;
	mov cx, ax						; cx = keyLength
	push ds
	lds si, [bp+4]					; Point DS:SI at key
	rep movsb						; memcpy( tempKey + 2, key, keyLength );
	pop ds
	add ax, 2						; ax = keyLength + 2
	neg ax
	add ax, SBOX_SIZE * 2			; ax = ( SBOX_SIZE * 2 ) - ( keyLength + 2 )
	xchg cx, ax						; cx = count, ax = 0
	repe stosb						; memset( tempKey + 2 + keyLength, 0, count );
	mov ax, SBOX_SIZE * 2
	push ax							; Push length of data
	push _tempKey					; Push address of data (NB pushes DWORD)
	call _encryptCFB				; encryptCFB( tempKey, SBOX_SIZE * 2 );
	add sp, 6						; Clean up stack

	; Reset the initial sBoxes
	mov es, _sBoxBase
	xor di, di						; Point ES:DI at sBox1
	call setInitialSBox				; setInitialSBox( sBox1 );
	call setInitialSBox				; setInitialSBox( sBox2 );

	; Permute the sBoxes using the encrypted key as our source of random
	; numbers
	mov es, _sBoxBase
	xor ax, ax
	call permuteSBox				; permuteSBox( sBoxByte1, 0 );
	mov ax, es
	add ax, SBOX_SIZE SHR 4
	mov es, ax						; Point ES to sBoxes2
	mov ax, SBOX_SIZE
	call permuteSBox				; permuteSBox( sBoxByte2, SBOX_SIZE );

	pop di
	pop si							; Restore register var
	pop bp
	ret
_initSBoxes ENDP

;****************************************************************************
;*																			*
;*							Block Encryption Routines						*
;*																			*
;****************************************************************************

; A macro to handle rotation of 64-bit values.  Total exec.time = 21 cycles

rotl64 MACRO
	xchg ah, al						;<2>
	mov si, ax						;<2>
	mov al, bh						;<2>
	mov bh, bl						;<2>
	mov bl, ch						;<2>
	mov ch, cl						;<2>
	mov cl, dh						;<2>
	mov dh, dl						;<2>
	and si, 0FFh					;<3>
	xor dl, dl						;<2>
	or dx, si						;<2>
ENDM

; The 32-bit CPU version of this rotate takes 9 cycles:
;
;	rol eax, 8						;<3>
;	rol ebx, 8						;<3>
;	xchg al, bl						;<3>

; Some useful defines.  The naming for the parts of each codeword are:
; lLeftHi : lLeftLo : rLeftHi : rLeftLo : lRightHi : lRightLo : rRightHi : rRightLo
;	16		  16		16		  16		 16			16		   16		  16

lLeftLo		EQU		[di]
lLeftHi		EQU		[di+2]
rLeftLo		EQU		[di+4]
rLeftHi		EQU		[di+6]
lRightLo	EQU		[di+8]
lRightHi	EQU		[di+10]
rRightLo	EQU		[di+12]
rRightHi	EQU		[di+14]

		PUBLIC	_encrypt			; Make it externally visible

; void encrypt( BYTE *inData, BYTE *outData )

_encrypt PROC NEAR
	push bp
	mov bp, sp
	push si
	push di							; Save register vars
	push ds							; Save DS

	; Copy input data to output buffer
	mov ax, _sBoxBase				; Save sBox base addr.before we lose DS
	lds si, [bp+4]					; DS:SI = source pointer
	les di, [bp+8]					; ES:DI = dest pointer
	mov cx, 8
	rep movsw						; Move data to output buffer

	lds di, [bp+8]					; Point DS:DI to destination
	mov es, ax
	xor si, si						; Point ES:SI at sBoxes base address
	mov ax, lLeftHi
	mov bx, lLeftLo
	mov cx, rLeftHi
	mov dx, rLeftLo					; Load 64-bit value into AX:BX:CX:DX

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 1 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov bp, lRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64							;<21> Rotate it

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 1, 2 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<3> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 3 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 1, 4 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<3> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 5 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 1, 6 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<3> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 7 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 1, 8 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<2> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 1 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 2, 2 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<3> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 3 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 2, 4 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<2> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 5 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<2> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 2, 6 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	xchg bx, bp						;<2> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	; lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 7 */
	; rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	; rotl( lRight, rRight );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lLeftHi, ax					;<3>
	xor bx, es:[si]					;<7>
	mov lLeftLo, bx					;<3>
	mov bx, bp						;<2> Get in correct register for later

	mov bp, rRightLo				;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rRight
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rLeftHi, cx					;<3>
	xor dx, es:[si+400h]			;<7>
	xchg dx, bp						;<3> Get in correct register

	mov ax, lRightHi				;<5>
	mov cx, rRightHi				;<5> Load remainder of 64-bit value
	rotl64

	; rRight ^= sBoxes2[ ( BYTE ) rLeft ];	/* 2, 8 */
	; lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	; rotl( lLeft, rLeft );
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of rLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor cx, es:[si+402h]			;<7>
	mov rRightHi, cx				;<3>
	xor dx, es:[si+400h]			;<7>
	mov rRightLo, dx				;<3>
	mov dx, bp						;<2> Get in correct register for later

	mov bp, lLeftLo					;<5>
	mov si, bp						;<2>
	and si, 0FFh					;<3> Get low byte of lLeft
	add si, si						;<2>
	add si, si						;<2> Scale up to longword
	xor ax, es:[si+2]				;<7>
	mov lRightHi, ax				;<3>
	xor bx, es:[si]					;<7>
	mov lRightLo, bx				;<3>
	mov bx, bp						;<2> Get in correct register

	mov ax, lLeftHi					;<5>
	mov cx, rLeftHi					;<5> Load remainder of 64-bit value
	rotl64

	mov lLeftHi, ax
	mov lLeftLo, bx
	mov rLeftHi, cx
	mov rLeftLo, dx					; Save 64-bit value to output buffer

	pop ds							; Pop DS
	pop di							; Restore register vars
	pop si
	pop bp
	ret
_encrypt ENDP

IFDEF DO_32BIT

; The 32-bit version of the NSEA core encryption routine.  This is written
; for a 32-bit CPU running in 16-bit mode, ie the number of 32-bit overrides
; on opcodes is minimised.  If moved to a CPU running in 32-bit mode some
; of the instruction should be changed to the 32-bit forms to eliminate
; unnecessary overrides to the 16-bit form (for example the manual scaling
; of si can be done automagically using the scaled index base addressing mode -
; in 16-bit mode this results in many more overrides + much longer 
; instructions, leading to a slight reduction in execution speed).

	.386

; Symbolic defines for registers

lLeft		EQU		eax
lLeftIndex	EQU		ax
rLeft		EQU		ebx
rLeftIndex	EQU		bx
lRight		EQU		ecx
lRightIndex	EQU		cx
rRight		EQU		edx
rRightIndex	EQU		dx

; Macros to handle the XOR's of various values.  The shl of di is no faster
; than the double add the 16-bit version uses, but saves 1 byte.  If running
; in 32-bit mode, it would probably be better to go entirely to 32-bit
; instructions, eg make the xxxIndex values 32-bit registers, set esi to
; 000000FFh, and use:
;	mov edi, index					;<2>
;	and edi, esi					;<2>
;   xor register, es:[edi*4]		;<7>

xorSBox1 MACRO register, index
	mov di, index					;<2>
	and di, 0FFh					;<2> Get low byte of index
	shl di, 2						;<2> Scale up to longword index
	xor register, es:[di]			;<7>
ENDM

xorSBox2 MACRO register, index
	mov di, index					;<2>
	and di, 0FFh					;<2> Get low byte of index
	shl di, 2						;<2> Scale up to longword index
	xor register, es:[di+400h]		;<7>
ENDM

; Macro to handle 64-bit rotate

rotl MACRO reg1, reg2
	rol reg1, 8						;<3>
	rol reg2, 8						;<3>
  IF reg1 EQ eax
	xchg al, bl						;<3>
  ELSE
	xchg cl, dl						;<3>
  ENDIF
ENDM

	PUBLIC	_encrypt32			; Make it externally visible

_encrypt32 PROC NEAR
	push bp
	mov bp, sp
	push di							; Save register var

	; Copy input data to output buffer
	les di, [bp+4]					; ES:DI = source pointer
	mov lLeft, es:[di]
	mov rLeft, es:[di+4]
	mov lRight, es:[di+8]
	mov rRight, es:[di+12]			; Get input data in registers
	mov di, _sBoxBase
	mov es, di
	xor di, di						; Point ES:DI at sBoxes

	xorSBox1 lLeft, lRightIndex		;<15>	/* 1, 1 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 1, 2 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 1, 3 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 1, 4 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 1, 5 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 1, 6 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 1, 7 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 1, 8 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 2, 1 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 2, 2 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 2, 3 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 2, 4 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 2, 5 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 2, 6 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	xorSBox1 lLeft, lRightIndex		;<15>	/* 2, 7 */
	xorSBox2 rLeft, rRightIndex		;<15>
	rotl lRight, rRight				;<9>

	xorSBox1 lRight, lLeftIndex		;<15>	/* 2, 8 */
	xorSBox2 rRight, rLeftIndex		;<15>
	rotl lLeft, rLeft				;<9>

	les di, [bp+8]					; ES:SI = dest pointer
	mov es:[di], lLeft
	mov es:[di+4], rLeft
	mov es:[di+8], lRight
	mov es:[di+12], rRight			; Put output data in buffer

	pop di							; Restore register vars
	pop bp
	ret
_encrypt32 ENDP
ENDIF ;DO_32BIT

	END
