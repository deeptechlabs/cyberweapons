This is an updated version of the tiny IDEA program (first posted to
sci.crypt in June 1995).

Tiny IDEA is a tiny file encryption program (608 bytes).
It uses the International Data Encryption Algorithm cipher (obviously)
which is the symmetric cipher used in PGP. The passphrase can be upto
128 characters long (it could be much longer, this limit is user-defined).

Because of the overwriting mechanism, tiny IDEA can also be used for
secure file wiping (removing files such that advanced data recovery
methods would be unable to retrieve the original file contents). Simply
encrypt the file using a random string as the key (tap the keyboard in
various places), then decrypt it using another random string, then
encrypt again, then decrypt, and so on. One encrypt-decrypt sequence is
sufficient to wipe the file, but will provide minimal security; I suggest
between four and eight. The really paranoid among you can use four hundred.

Technical details about the tiny IDEA program:
    Files are processed in place (effectively wiping the original).
    The passphrase is hashed using tandem Davies-Meyer (with IDEA).
    It uses 8 round IDEA in ciphertext feedback mode.
    The feedback is done on 8 byte blocks.
    The initialisation vector (IV) is set to zeros.
    Written in 8086 assembly (heavily optimised for size).

The main improvements over the previous version are longer passphrases,
byte ordering bug fixed, overwriting key and data information upon exit,
and a slight speed improvement. This version is not compatible with the
previous one. It is possible to implement a C program to decrypt tiny IDEA
encrypted files and vice versa (using PGP IDEA source for example).

Example IDEA 8086 source is available from:
    ftp://ftp.ox.ac.uk/pub/crypto/misc/idea86.zip

It should soon be replaced by the updated IDEA routines containing IDEA,
CFB, tandem DM, and a demo encryption program (ZIP file, 7387 bytes).

==========================cut here=============

; Last updated: Sun Oct 22 1995
Ô
; Copyright (C) Fauzan Mirza 1995

	.model  tiny
	.code

	org     100h

BuffLen equ     32768                   ; File buffer size
PassLen equ     128                     ; Passphrase length

Start:
	call    Burn

	mov     dx,offset Usage
	mov     si,80h
	lodsb
	or      al,al                   ; Check if parameters specified
	jz      PrintUsage

	lodsb
	lodsb                           ; Get mode switch
	cmp     al,'-'
	jz      DeMode
	cmp     al,'+'
	jz      EnMode
PrintUsage:
	jmp     Exit

DeMode:
	mov     byte ptr [Mode],255
EnMode:
	lodsw

AddZero:
	lodsb                           ; Find end of second parameter
	cmp     al,0dh
	jz      AddZ2
	cmp     al,20h
	jnz     AddZero
AddZ2:
	mov     byte ptr [si-1],0       ; Terminate it with NULL

	mov     ah,9
	mov     dx,offset Enterkey
	int     21h                     ; Print message requesting key

	mov     ah,0ah
	mov     dx,offset Password
	int     21h                     ; Get passphrase from user

	mov     cx,PassLen/8            ; Hash passphrase down to 128 bits
	mov     si,offset Passphrase

h       equ     Key
g       equ     Key+8

TandemDM:
	push    cx              ; push block counter    <0
	push    si              ; push data             <1

	mov     cl,4
	mov     si,offset g     ; -- Let first half of key = second half of hash (G)
	mov     di,offset hashKey
	repnz   movsw           ; after: di->key+8

	pop     si              ; si->data              1>
	push    si              ; push data             <1
	mov     cl,4            ; -- Let second half of key = data
copy1:
	lodsw
	xchg    ah,al           ; -- (Convert string to little-endian words)
	stosw
	loop    copy1

	mov     si,offset hashKey
	push    si              ; push key              <2
	mov     di,si
	call    Expandkey       ; -- Expand key : Key = {G, data}

	mov     cl,4
	mov     si,offset h
	mov     di,offset w
	push    di              ; push w                <3
	repnz   movsw           ; -- Let W = first half of hash (H)

	pop     di              ; di->w                 3>
	pop     si              ; si->key               2>
	push    si              ; push key              <2

	call    IDEA            ; -- W = IDEA encrypt (W, {G,data})

	mov     si,di           ; si->w
	mov     di,offset h
	mov     cx,4
doH:
	lodsw
	xor     ax,[di]
	stosw
	loop    doH             ; -- Update H with (H xor W)

	pop     di              ; di->key               2>
	pop     si              ; si->data              1>
	push    si              ; push data             <1
	push    di              ; push key              <2
	mov     cl,4            ; -- Let first half of key = data
copy2:
	lodsw
	xchg    ah,al           ; -- (Convert string to little-endian words)
	stosw
	loop    copy2

	mov     cl,4
	mov     si,offset w     ; di->key+8
	repnz   movsw           ; -- Let second half of key = W

	pop     si              ; si->key               2>
	mov     di,si
	call    Expandkey       ; -- Expand key : Key = {data, W}

	mov     cl,4
	mov     si,offset g
	mov     di,offset g0
	push    si              ; push g                <2
	push    di              ; push g0               <3
	repnz   movsw           ; -- Let G0 = G

	pop     di              ; di->g0                3>
	push    di              ; push g0               <3
	mov     si,offset hashKey
	call    IDEA            ; -- G0 = IDEA encrypt (G0, {data, W})

	pop     si              ; si->g0                3>
	pop     di              ; di->g                 2>
	mov     cx,4
doG:
	lodsw
	xor     ax,[di]
	stosw
	loop    doG             ; -- Update G with (G xor G0)

	pop     si              ; si->data              1>
	add     si,8            ; data+=8
	pop     cx              ; cx=block counter      0>
	loop    TandemDM        ; -- Continue hashing until no more blocks

	mov     di,offset Key   ; Expand hashed passphrase to IDEA key
	call    Expandkey

	mov     ax,3d02h
	mov     dx,0084h
	int     21h                     ; Open file with R/W access
	jc      Errstop
	mov     bx,ax

Again:
	mov     ah,3fh
	mov     cx,BuffLen
	mov     dx,offset Buffer
	int     21h                     ; Read upto 32k into buffer
Errstop:
	jc      Error

	or      ax,ax                   ; Check if we reached EOF
	jz      Done

	push    ax
	push    bx

; Encrypt Buffer

	mov     di,offset Buffer        ; DI -> data (start)
	add     ax,7
	mov     cl,3
	shr     ax,cl
	mov     cx,ax                   ; CX = number of blocks to encrypt
Block:
	mov     si,offset Key
	push    cx
	push    di                      ; Save current position

	push    di
	mov     di,offset CFBBuffer     ; Encrypt 8 byte CFB buffer (DI)
	call    IDEA

	cmp     byte ptr [Mode],0       ; Check mode switch
	jnz     Decrypt

; Cipher Feedback

Encrypt:
	pop     si                      ; SI -> data, DI -> CFB buffer
	mov     cx,4                    ; Process 4 words
EnFeedback:
	lodsw                           ; Get a word from file buffer
	xchg    ah,al                   ;   and convert it to little-endian
	xor     ax,word ptr [di]        ; XOR data with CFB buffer
	stosw                           ; Replace ciphertext in CFB buffer
	xchg    ah,al                   ; Convert back to big-endian
	mov     word ptr [si-2],ax      ;   and store in file buffer
	loop    EnFeedback

	jmp     short DoNextBlock       ; Skip over Decrypt routine

Decrypt:
	mov     si,di                   ; SI -> CFB buffer
	pop     di                      ; DI -> data
	mov     cx,4                    ; Process 4 words
DeFeedback:
	lodsw                           ; Get word from CFB buffer
	mov     bx,word ptr [di]        ; Get word from file buffer
	xchg    bh,bl                   ;   convert it to little-endian
	mov     word ptr [si-2],bx      ; Update CFB buffer
	xor     ax,bx                   ; XOR data with CFB buffer
	xchg    ah,al                   ; Convert back to big-endian
	stosw                           ;   and store in file buffer
	loop    DeFeedback

DoNextBlock:
	pop     di                      ; Get current file position
	add     di,8                    ; Add 8 bytes to counter (one block)
	pop     cx
	loop    Block                   ; Continue until all blocks processed

; Buffer Encrypted

	pop     bx
	pop     dx

	push    dx
	mov     ax,4201h
	mov     cx,0ffffh
	neg     dx
	int     21h                     ; Seek backwards
	pop     cx

	mov     ah,40h
	mov     dx,offset Buffer
	int     21h                     ; Write encrypted buffer
	jc      Error

	cmp     cx,BuffLen
	jz      Again                   ; Continue until no more data

Done:
	mov     ah,3eh
	int     21h                     ; Close file
	jmp     short Burn              ; Burn evidence and exit

Error:
	mov     dx,offset Message
Exit:
	mov     ah,09
	int     21h                     ; Display message

Burn:
	xor     ax,ax
	mov     di,offset Passphrase
	mov     cx,Buffer-Passphrase+BuffLen
	repnz   stosb                   ; Zero data area
	ret                             ; Exit

; Expand user key to IDEA encryption key
; Entry:  si -> userkey, di -> buffer for IDEA key (can equal si)
; Exit:   di -> IDEA key

Expandkey:
	add     di,16
	mov     bx,8
Rotate:
	mov     ax,bx                   ; Determine which two of the previous
	and     al,7                    ;  eight words are needed for this
	cmp     al,6                    ;  key expansion round
	ja      Above
	jb      Below
	mov     ax,word ptr [di-14]
	mov     dx,word ptr [di-28]
	jmp     short Update
Above:
	mov     ax,word ptr [di-30]
	mov     dx,word ptr [di-28]
	jmp     short Update
Below:
	mov     ax,word ptr [di-14]
	mov     dx,word ptr [di-12]
Update:
	mov     cl,9
	shl     ax,cl
	mov     cl,7
	shr     dx,cl                   ; Calculate the rotated value
	or      ax,dx                   ; ax = (ax << 9) | (dx >> 7)
	stosw                           ;   and save it
	inc     bl
	cmp     bl,52
	jnz     Rotate                  ; Continue until 52 words updated
	ret

; IDEA subroutine
; Entry:  si -> key, di -> input data
; Exit:   di -> output data, all other registers trashed

; Refer to the PGP IDEA source for a better explanation
; of the algorithm and the optimisations

; Thanks to Bill Couture <bcouture@cris.com> for speed optimisations

x0      equ     bx
x1      equ     cx
x2      equ     bp
x3      equ     di
s0      equ     word ptr [temp0]
s1      equ     word ptr [temp1]

IDEA:
	mov     byte ptr [Rounds],8     ; Eight rounds
	push    di
	mov     x0,word ptr [di]
	mov     x1,word ptr [di+2]
	mov     x2,word ptr [di+4]
	mov     x3,word ptr [di+6]      ; note that DI is over-written last
Round:
	mov     dx,x0
	call    MulMod
	mov     x0,ax                   ; x0 *= *key++
	lodsw
	add     x1,ax                   ; x1 += *key++
	lodsw
	add     x2,ax                   ; x2 += *key++
	mov     dx,x3
	call    MulMod
	mov     x3,ax                   ; x3 *= *key++

	mov     s0,x1                   ; s0 = x1
	mov     s1,x2                   ; s1 = x2
	mov     ax,x0
	xor     x2,ax                   ; x2 ^= x0
	mov     ax,x3
	xor     x1,ax                   ; x1 ^= x3

	mov     dx,x2
	call    MulMod
	mov     x2,ax                   ; x2 *= *key++
	add     x1,ax                   ; x1 += x2
	mov     dx,x1
	call    MulMod
	mov     x1,ax                   ; x1 *= *key++
	add     x2,ax                   ; x2 += x1

	mov     ax,x1
	xor     x0,ax                   ; x0 ^= x1
	mov     ax,x2
	xor     x3,ax                   ; x3 ^= x2
	xor     x1,s1                   ; x1 ^= s1
	xor     x2,s0                   ; x2 ^= s0

	dec     byte ptr [Rounds]       ; Continue until no more rounds
	jnz     Round

	mov     dx,x0
	call    MulMod
	mov     x0,ax                   ; x0 *= *key++
	lodsw
	add     x2,ax                   ; x2 += *key++
	lodsw
	add     x1,ax                   ; x1 += *key++
	mov     dx,x3
	call    MulMod
	mov     x3,ax                   ; x3 *= *key++

	pop     ax                      ; pop the original DI into AX
	xchg    ax,x3                   ; swap DI with AX
	mov     word ptr [di],x0
	mov     word ptr [di+2],x2      ; unswap x1, x2
	mov     word ptr [di+4],x1
	mov     word ptr [di+6],ax
	ret

; Multiplication modulo 65537
; ax = [si] * dx

MulMod:
	push    dx
	lodsw
	mul     dx
	sub     ax,dx
	pop     dx
	jnz     NotZero
	mov     ax,1
	sub     ax,word ptr [si-2]
	sub     ax,dx
	jmp     short MulDone
NotZero:
	adc     ax,0
MulDone:
	ret

; Data used by main program

Usage:
	db      "IDEA [+|-] <File>",36

EnterKey:
	db      "Enter key: ",36

Message:
	db      "File Error",36

Password:
	dw      PassLen

Passphrase:
	db      PassLen dup (?)

Mode:
	db      ?

; Data used by IDEA routine

temp0:
	dw      ?
temp1:
	dw      ?
Rounds:
	db      ?

; Data used by Tandem DM hashing routine

Key:
	dw      8 dup (?)
w:
	dw      4 dup (?)
g0:
	dw      4 dup (?)
hashKey:
	dw      52 dup (?)

; Data used by CFB routine

CFBBuffer:
	db      8 dup (?)

; Data buffer

Buffer:
	db      BuffLen dup (?)

	end     Start

--------------------------------------
Fauzan Mirza <fauzan@dcs.rhbnc.ac.uk>
Programming/Security DOS/NetWare/Linux
--------------------------------------


