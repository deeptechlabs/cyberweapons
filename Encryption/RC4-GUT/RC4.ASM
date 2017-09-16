; Simple RC4 implementation, Peter Gutmann, 21 September 1995.
; This code was written in about 30 minutes as a testbed for an asm.RC4.  It
; uses a static data area as the key so it's not terribly practical as it
; stands.  In addition, the RC4 algorithm leads to an almost solid block of
; pipeline stalls on anything >= '486, so I wouldn't recommend using it on
; anything except perhaps 8-bit microcontrollers and smart cards.
 
                INCLUDE MISC.INC
                MODULE RC4
 
                PUBLIC _rc4expandKey, _rc4crypt
 
                DATA
 
; The RC4 keying information
 
rc4key  DB              256 DUP (?)
rc4x    DB              0
rc4y    DB              0
 
                CODE
 
; void rc4ExpandKey( unsigned char const *key, int keylen )
 
_rc4expandKey PROCEDURE
        push bp
        mov bp, sp
        push si
        push di                                                 ; Save register vars
        les si, [bp+4]                                  ; ES:SI = key
        mov dx, [bp+8]                                  ; DX = keylen
        mov dh, dl                                              ; keylenTmp = keylen
 
        ; rc4word y = 0;
        xor ax, ax                                              ; y = 0
        sub di, di                                              ; DI = AX as an index register
 
        ; for( x = 0; x < 256; x++ )
        ;       rc4key[ x ] = x;
        xor bx, bx                                              ; x = 0
@@initLoop:
        mov rc4key[bx], bl                              ; rc4key[ x ] = x
        inc bl                                                  ; x++
        jnz SHORT @@initLoop
 
        ; for( x = 0; x < 256; x++ )
        ;       {
        ;       sx = rc4key[ x ];
        ;       y += sx + key[ keypos ];
        ;       rc4key[ x ] = rc4key[ y ];
        ;       rc4key[ y ] = sx;
        ;
        ;       if( ++keypos == keylen )
        ;               keypos = 0;
        ;       }
@@keyLoop:
        mov cl, rc4key[bx]                              ; sx = rc4key[ x ]
        add al, es:[si]                                 ; y += key[ keypos ]
        add al, cl                                              ; y += sx
        mov di, ax
        mov ch, rc4key[di]                              ; temp = rc4key[ y ]
        mov rc4key[bx], ch                              ; rc4key[ x ] = temp
        mov rc4key[di], cl                              ; rc4key[ y ] = sx
        inc si                                                  ; ++keypos
        dec dh                                                  ; keylenTmp--
        jnz SHORT @@noResetKeypos               ; if( !keylenTmp )
        sub si, dx                                              ; keypos = 0
        mov dh, dl                                              ; keylenTmp = keylen
@@noResetKeypos:
        inc bl                                                  ; x++
        jnz SHORT @@keyLoop
 
        ; rc4->x = rc4->y = 0;
        mov rc4x, bl                                    ; rc4->x = 0
        mov rc4y, bl                                    ; rc4->y = 0
 
        pop di
        pop si                                                  ; Restore register vars
        pop bp
        ret
_rc4expandKey ENDP
 
; void rc4Crypt( unsigned char *data, int len )
 
_rc4crypt PROCEDURE
        push bp
        mov bp, sp
        push si
        push di                                                 ; Save register vars
        les si, [bp+4]                                  ; ES:SI = data
        mov dx, [bp+8]                                  ; DX = len
        test dx, dx                                             ; Check that len != 0
        jz SHORT @@exit                                 ; Yes, exit now
 
        xor bx, bx
        mov bl, rc4x                                    ; BX = rc4x
        xor ax, ax
        mov al, rc4y                                    ; AX = rc4y
        xor di, di                                              ; DI = AX as an index register
 
        ; while( len-- )
        ;       {
        ;       x++;
        ;       sx = rc4key[ x ];
        ;       y += sx;
        ;       sy = rc4key[ y ];
        ;       rc4key[ y ] = sx;
        ;       rc4key[ x ] = sy;
        ;       *data++ ^= rc4key[ ( sx + sy ) & 0xFF ];
        ;       }
@@rc4loop:
        inc bl                                                  ; x++
        mov cl, rc4key[bx]                              ; sx = rc4key[ x ]
        add al, cl                                              ; y += sx
        mov di, ax
        mov ch, rc4key[di]                              ; sy = rc4key[ y ]
        mov rc4key[di], cl                              ; rc4key[ y ] = sx
        mov rc4key[bx], ch                              ; rc4key[ x ] = sy
        add cl, ch
        xor ch, ch
        mov di, cx                                              ; temp = ( sx + sy ) & 0xFF
        mov cl, rc4key[di]
        xor es:[si], cl                                 ; *data ^= rc4key[ temp ]
        inc si                                                  ; data++
        dec dx                                                  ; len--
        jnz SHORT @@rc4loop
 
        mov rc4x, bl
        mov rc4y, al                                    ; Remember x and y values
 
@@exit:
        pop di
        pop si                                                  ; Restore register vars
        pop bp
        ret
_rc4crypt ENDP
ENDMODULE



