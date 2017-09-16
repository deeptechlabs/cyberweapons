;; Detect processor type.
;; Code by Richard C. Leinecker, from Dr. Dobbs Journal, June 1993
;; Transcribed (with some deletions of code unnecessary for RIPEM 
;; by Mark Riordan on 24 June 1993.
;;
;; Usage:
;;
;; extern int ProcessorType(void);
;;
;; Returns 0 for 8088/8086, 2 for 80286, 3 for 80386 or above.

_PTEXT   SEGMENT PARA PUBLIC 'CODE'
	ASSUME CS:_PTEXT,DS:_PTEXT

	public _ProcessorType

_ProcessorType proc  far
	push  bp
	mov   bp,sp
	push  ds
	push  di
	mov   ax,cs
	mov   ds,ax
	call  IsItAn8088  ;Returns 0 (808x)  or 2 (at least 286)
	cmp   al,2
	jge   AtLeast286
	
	jmp short ExitProcessor
AtLeast286:
	call IsItA286
	
ExitProcessor:
	pop   di
	pop   ds
	pop   bp
	ret
_ProcessorType endp

; Returns ax=0 for 8088/8086 or ax=2 for 80286 and above

IsItAn8088  proc
	pushf
	pushf
	pop    bx
	and   bx,00ffh
	push  bx
	popf
	pushf
	pop   bx
	and   bx,0f000h   ;Mask out bits 12-15
	sub   ax,ax 
	cmp   bx,0f000h
	je    Not286
	mov   al,2
Not286:
	popf
	ret
IsItAn8088  endp

; Exit:  ax=2 for only 80286, else ax=3 for > 80286.

IsItA286 proc
	pushf
	mov   ax,7000h
	push  ax
	popf
	pushf
	pop   ax
	and   ah,70h
	mov   ax,2  
	jz    YesItISA286
	inc   ax ;ax=3 meaning at least 80386
YesItIsA286:
	popf
	ret
IsItA286 endp

_PTEXT   ENDS
	END   


