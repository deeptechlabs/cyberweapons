;BASLIB.ASM      Written for MASM 6.00b
        .model medium,c

extern  des_encrypt   : far
public  desencrypt
extern  des_set_key   : far
public  dessetkey
public  memcmp

        .code
desencrypt:  jmp des_encrypt  ; underscores not supported in Basic
dessetkey:   jmp des_set_key
memcmp:      mov ax,0         ; used in libdes set_key.c / des_is_weak_key
             ret              ; not supported in this library
        end

