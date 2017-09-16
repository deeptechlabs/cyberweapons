	.386p
_TEXT	segment word public use32 'CODE'
_TEXT	ends
_DATA	segment dword public use32 'DATA'
_DATA	ends
_BSS	segment dword public use32 'BSS'
_BSS	ends
DGROUP	group	_DATA,_BSS
	assume	cs:_TEXT,ds:DGROUP
_TEXT	segment word public use32 'CODE'
	assume	cs:_TEXT
;
;	unsigned long _EXPORT
;	lmult(unsigned long *dst,unsigned long m,unsigned long *src,long N)
;
_LMULT	proc	near
	enter	4,0
	push	esi
	push	ebx
	mov	esi,dword ptr [ebp+8]      ; esi = dst
	mov	ebx,large 0                ; carry = 0
	mov	ecx,[ebp+20]               ; set loop counter to N
lmult1:
	mov	eax,dword ptr [ebp+12]     ; eax = m
	mov	edx,dword ptr [ebp+16]     ; edx = *src
	mul	dword ptr [edx]            ; m X *src
	add	eax,ebx                    ; low prod += carry
	adc	edx,0                      ; high prod += carry from previous add
	add	dword ptr [esi],eax        ; *dest ptr += low prod
	adc	edx,0                      ; high prod += carry from previous add
	mov	ebx,edx                    ; ebx = carry
	add	dword ptr [ebp+16],4       ; src++
	add	esi,4                      ; dst++
	loop	lmult1

	mov	eax,ebx  ; return carry
	pop	ebx
	pop	esi     	; cleanup
	leave
	ret
_LMULT	endp

;
;	void _EXPORT
;	buildDiag(unsigned long *dst,unsigned long *src,unsigned long N)
;
_BUILDDIAG	proc	near
	enter	4,0
	push	esi
	push	ebx
	mov	esi,dword ptr [ebp+12]     ; esi = src
	mov	ebx,dword ptr [ebp+8]      ; ebx = dst
	mov	ecx,[ebp+16]               ; set loop counter to N
bdiag1:
	mov	eax,[esi]				      ; eax = *src
	mul	eax            				; *src X *src
	mov	[ebx],eax						; *dst ptr = low prod
	mov	[ebx+4],edx						; *(dst ptr + 1) = high prod
	add	esi,4                      ; src++
	add	ebx,8								; dst ptr += 2
	loop	bdiag1

	pop	ebx
	pop	esi						     	; cleanup
	leave
	ret
_BUILDDIAG	endp

;
;  void _EXPORT
;	squareInnerLoop(Ulong *dst,Ulong m,Ulong *src,Ulong start,Ulong stop)
;
_SQUAREINNERLOOP	proc	near
	enter	4,0
	push	esi
	push	edi
	push	ebx
	xor	edi,edi						; zero high word of dst
	xor	ebx,ebx						; zero high word of src
	mov	ebx,[ebp+16]					; ebx = src
	mov	ecx,[ebp+20]					; ecx = start
	shl	ecx,2								; ecx *= 4
	add	ebx,ecx						; set src to starting pos
	mov	edi,[ebp+8]
	mov	ecx,[ebp+24]					; ecx = stop
	sub	ecx,[ebp+20]					; ecx -= start
	xor	esi,esi						; carry = 0
sqILp1:
	mov	eax,dword ptr [ebp+12]     			; eax = m
	mov	edx,[ebx]				      	; edx = *src
	mul	edx				            	; m X *src
	add	[edi+4],esi					; *(dst ptr + 1) += carry
	mov	esi,0						; carry = 0 (leave c bit alone!)
	adc	esi,0						; set new carry
	add	eax,eax						; 2*prodlo
	adc	edx,edx						; 2*prodhi + c-bit
	adc	esi,0						; update carry
	add	[edi],eax					; *dst += 2*prodlo
	adc	[edi+4],edx					; *(dst+1) += 2*prodhi + c
	adc	esi,0						; update carry
	add	ebx,4						; src++
	add	edi,4						; dst++
	loop	sqILp1

	add	[edi+4],esi					; add last carry to new *(dst+1)
	jnc	sqILpdone
sqILp2:
	add	edi,4						; dst++
	add	dword ptr [edi+4],1				; add a carry to *(dst+1)
	jc		sqILp2
sqILpdone:
	pop	ebx
	pop	edi						; cleanup
	pop	esi     					; cleanup
	leave
	ret
_SQUAREINNERLOOP  	endp

_TEXT	ends
_s@	equ	s@
	publicdll	_LMULT
	publicdll	_BUILDDIAG
	publicdll	_SQUAREINNERLOOP
_DATA	segment dword public use32 'DATA'
d@	label	byte
d@w	label	word
d@d	label	dword
s@	label	byte
_DATA	ends
_BSS	segment dword public use32 'BSS'
b@	label	byte
b@w	label	word
b@d	label	dword
_BSS	ends
end

