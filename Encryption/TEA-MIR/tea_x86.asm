; Tiny Encryption Algorithm
; A public domain block cipher by David Wheeler and Roger Needham
; 80386 assembly implementation by Fauzan Mirza

; TEA uses a 128 bit key and operates on 64 bit data blocks

        .model  tiny
        .code
        .386

        org     100h
Start:
        mov     si,offset Key
        mov     di,offset Data
        call    Encrypt
        mov     si,offset Key
        mov     di,offset Data
        call    Decrypt
        ret

Key:
        db      "0000","0000","0000","0000"
Data:
        db      "0000","0000"

sum     equ     eax
y       equ     ebx
z       equ     ecx
delta   equ     edx
rounds  equ     di
t       equ     ebp
v0      equ     dword ptr [di]
v1      equ     dword ptr [di+4]
k0      equ     dword ptr [si]
k1      equ     dword ptr [si+4]
k2      equ     dword ptr [si+8]
k3      equ     dword ptr [si+12]

Encrypt:
        push    di
        mov     y,v0
        mov     z,v1
        xor     sum,sum
        mov     delta,9e3779b9h ; sqr(5)-1 * 2^31
        mov     rounds,32
ELoopR:
        add     sum,delta
        mov     t,z
        shl     t,4
        add     y,t
        mov     t,k0
        xor     t,z
        add     y,t
        mov     t,z
        shr     t,5
        xor     t,sum
        add     y,t
        add     y,k1
        ;
        mov     t,y
        shl     t,4
        add     z,t
        mov     t,k2
        xor     t,y
        add     z,t
        mov     t,y
        shr     t,5
        xor     t,sum
        add     z,t
        add     z,k3
        dec     rounds
        jnz     ELoopR

        pop     di
        mov     v0,y
        mov     v1,z
        ret


Decrypt:
        push    di
        mov     y,v0
        mov     z,v1
        mov     delta,9e3779b9h ; sqr(5)-1 * 2^31
        mov     sum,delta
        shl     sum,5
        mov     rounds,32
DLoopR:
        mov     t,y
        shl     t,4
        sub     z,t
        mov     t,k2
        xor     t,y
        sub     z,t
        mov     t,y
        shr     t,5
        xor     t,sum
        sub     z,t
        sub     z,k3
        ;
        mov     t,z
        shl     t,4
        sub     y,t
        mov     t,k0
        xor     t,z
        sub     y,t
        mov     t,z
        shr     t,5
        xor     t,sum
        sub     y,t
        sub     y,k1
        sub     sum,delta
        dec     rounds
        jnz     DLoopR

        pop     di
        mov     v0,y
        mov     v1,z
        ret

        end     Start