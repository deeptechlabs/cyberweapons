;	Static Name Aliases
;
	TITLE   lm.c
	.MODEL  LARGE
	.386p
	.387
INCLUDELIB      LLIBCE
INCLUDELIB	OLDNAMES.LIB
LM_TEXT	SEGMENT  WORD USE16 PUBLIC 'CODE'
LM_TEXT	ENDS
_DATA	SEGMENT  WORD USE16 PUBLIC 'DATA'
_DATA	ENDS
CONST	SEGMENT  WORD USE16 PUBLIC 'CONST'
CONST	ENDS
_BSS	SEGMENT  WORD USE16 PUBLIC 'BSS'
_BSS	ENDS
DGROUP	GROUP	CONST, _BSS, _DATA
	ASSUME DS: DGROUP, SS: DGROUP
EXTRN	__aFchkstk:FAR
;EXTRN	_mul32:FAR
LM_TEXT      SEGMENT
	ASSUME	CS: LM_TEXT
	PUBLIC	_LMULT
_LMULT	PROC FAR
; Line 25
	push	bp
	mov	bp,sp
	mov	ax,26	;001aH
	call	FAR PTR __aFchkstk
	push	si
;	sumh = -4
;	suml = -8
;	carry = -12
;	ap = -16
;	cp = -20
;	mm = -24
;	i = -26
;	N = 18
;	src = 14
;	m = 10
;	dst = 6
; Line 30
	mov	eax,DWORD PTR [bp+14]	;src
	mov	DWORD PTR [bp-16],eax	;ap
; Line 31
	mov	eax,DWORD PTR [bp+6]	;dst
	mov	DWORD PTR [bp-20],eax	;cp
; Line 32
	mov	eax,DWORD PTR [bp+10]	;m
	mov	DWORD PTR [bp-24],eax	;mm
; Line 34
	sub	eax,eax
	mov	DWORD PTR [bp-12],eax	;carry
; Line 35
	mov	WORD PTR [bp-26],ax	;i
	jmp	SHORT $F117
$L169:
	xor	ax,ax
$L170:
	cwd	
	add	WORD PTR [bp-4],ax	;sumh
	adc	WORD PTR [bp-2],dx
; Line 41
	mov	bx,WORD PTR [bp-26]	;i
	shl	bx,2
	les	si,DWORD PTR [bp-20]	;cp
	mov	eax,DWORD PTR [bp-8]	;suml
	add	DWORD PTR es:[bx][si],eax
; Line 42
	mov	bx,WORD PTR [bp-26]	;i
	shl	bx,2
	les	si,DWORD PTR [bp-20]	;cp
	mov	eax,DWORD PTR [bp-8]	;suml
	cmp	DWORD PTR es:[bx][si],eax
	jae	SHORT $L171
$L174:
	mov	ax,1
	jmp	SHORT $L172
$L171:
	xor	ax,ax
$L172:
	cwd	
	add	ax,WORD PTR [bp-4]	;sumh
	adc	dx,WORD PTR [bp-2]
	mov	WORD PTR [bp-12],ax	;carry
	mov	WORD PTR [bp-10],dx
; Line 44
	inc	WORD PTR [bp-26]	;i
$F117:
	mov	ax,WORD PTR [bp+18]	;N
	cmp	WORD PTR [bp-26],ax	;i
	jge	SHORT $FB119
; Line 36
	mov	bx,WORD PTR [bp-26]	;i
	shl	bx,2
	les	si,DWORD PTR [bp-16]	;ap
	mov eax, DWORD PTR es:[bx][si]
	mov edx, DWORD PTR [bp-24]
	mul edx
	mov DWORD PTR [bp-8], eax
	mov DWORD PTR [bp-4], edx
;	push	DWORD PTR es:[bx][si]
;	push	DWORD PTR [bp-24]	;mm
;	push	DWORD PTR [bp-8]	;suml
;	push	DWORD PTR [bp-4]	;sumh
;	call	FAR PTR _mul32
;	add	sp,16	;0010H
; Line 38
	mov	eax,DWORD PTR [bp-12]	;carry
	add	DWORD PTR [bp-8],eax	;suml
; Line 39
	mov	eax,DWORD PTR [bp-8]	;suml
	cmp	DWORD PTR [bp-12],eax	;carry
	jbe	SHORT $L169
$L173:
	mov	ax,1
	jmp	$L170
	nop	
$FB119:
; Line 46
	mov	ax,WORD PTR [bp-12]	;carry
	mov	dx,WORD PTR [bp-10]
; Line 48
	pop	si
	leave	
	ret	
	nop	

_LMULT	ENDP
	PUBLIC	_BUILDDIAG
_BUILDDIAG	PROC FAR
; Line 68
	push	bp
	mov	bp,sp
	mov	ax,14	;000eH
	call	FAR PTR __aFchkstk
	push	si
;	ap = -4
;	cp = -8
;	m = -12
;	i = -14
;	N = 14
;	src = 10
;	dst = 6
; Line 72
	mov	eax,DWORD PTR [bp+10]	;src
	mov	DWORD PTR [bp-4],eax	;ap
; Line 73
	mov	eax,DWORD PTR [bp+6]	;dst
	mov	DWORD PTR [bp-8],eax	;cp
; Line 75
	mov	WORD PTR [bp-14],0	;i
; Line 76
$D133:
; Line 77
	mov	bx,WORD PTR [bp-14]	;i
	shl	bx,2
	les	si,DWORD PTR [bp-4]	;ap
	mov	eax,DWORD PTR es:[bx][si]
;	mov	dx,WORD PTR es:[bx+2][si]
; Line 78
	mul eax
	les	bx,DWORD PTR [bp-8]	;cp
	mov	DWORD PTR es:[bx], eax
	mov	DWORD PTR es:[bx+4], edx
;	push	dx
;	push	ax
;	push	dx
;	push	ax
;	les	bx,DWORD PTR [bp-8]	;cp
;	push	DWORD PTR es:[bx]
;	push	DWORD PTR es:[bx+4]
;	call	FAR PTR _mul32
;	add	sp,16	;0010H
; Line 79
	add	WORD PTR [bp-8],8	;cp
; Line 80
	mov	ax,WORD PTR [bp+14]	;N
	inc	WORD PTR [bp-14]	;i
	cmp	WORD PTR [bp-14],ax	;i
	jl	SHORT $D133
; Line 82
	pop	si
	leave	
	ret	
	nop	

_BUILDDIAG	ENDP
	PUBLIC	_SQUAREINNERLOOP
_SQUAREINNERLOOP	PROC FAR
; Line 98
	push	bp
	mov	bp,sp
	mov	ax,34	;0022H
	call	FAR PTR __aFchkstk
	push	si
;	ap = -4
;	cp = -8
;	j = -10
;	prodhi = -14
;	prodlo = -18
;	sumh = -22
;	suml = -26
;	carry = -30
;	end = 20
;	start = 18
;	src = 14
;	m = 10
;	dst = 6
; Line 104
	mov	eax,DWORD PTR [bp+6]	;dst
	mov	DWORD PTR [bp-8],eax	;cp
; Line 105
	mov	eax,DWORD PTR [bp+14]	;src
	mov	DWORD PTR [bp-4],eax	;ap
; Line 106
	mov	DWORD PTR [bp-30],0	;carry
; Line 107
	mov	ax,WORD PTR [bp+18]	;start
	mov	WORD PTR [bp-10],ax	;j
; Line 109
$D156:
; Line 110
	mov	bx,WORD PTR [bp-10]	;j
	shl	bx,2
	les	si,DWORD PTR [bp-4]	;ap
	mov eax, DWORD PTR es:[bx][si]
	mov edx, DWORD PTR [bp+10]
	mul edx
	mov DWORD PTR [bp-18], eax
	mov DWORD PTR [bp-14], edx
;	push	DWORD PTR es:[bx][si]
;	push	DWORD PTR [bp+10]	;m
;	push	DWORD PTR [bp-18]	;prodlo
;	push	DWORD PTR [bp-14]	;prodhi
;	call	FAR PTR _mul32
;	add	sp,16	;0010H
; Line 112
;	__c = -34
	mov	eax,DWORD PTR [bp-18]	;prodlo
	add	eax,eax
	mov	DWORD PTR [bp-34],eax	;__c
	cmp	eax,DWORD PTR [bp-18]	;prodlo
	jae	SHORT $L175
$L177:
	mov	ax,1
	jmp	SHORT $L176
	nop	
$L175:
	xor	ax,ax
$L176:
	cwd	
	mov	WORD PTR [bp-22],ax	;sumh
	mov	WORD PTR [bp-20],dx
	mov	eax,DWORD PTR [bp-34]	;__c
	mov	DWORD PTR [bp-26],eax	;suml
; Line 113
;	__c = -34
	les	bx,DWORD PTR [bp-8]	;cp
	mov	eax,DWORD PTR es:[bx]
	add	eax,DWORD PTR [bp-26]	;suml
	mov	DWORD PTR [bp-34],eax	;__c
	cmp	eax,DWORD PTR [bp-26]	;suml
	jae	SHORT $L178
$L180:
	mov	ax,1
	jmp	SHORT $L179
	nop	
$L178:
	xor	ax,ax
$L179:
	cwd	
	add	ax,WORD PTR [bp-22]	;sumh
	adc	dx,WORD PTR [bp-20]
	add	WORD PTR [bp-30],ax	;carry
	adc	WORD PTR [bp-28],dx
	mov	eax,DWORD PTR [bp-34]	;__c
	mov	DWORD PTR es:[bx],eax
; Line 115
;	__c = -34
	mov	eax,DWORD PTR [bp-14]	;prodhi
	add	eax,eax
	mov	DWORD PTR [bp-34],eax	;__c
	cmp	eax,DWORD PTR [bp-14]	;prodhi
	jae	SHORT $L181
$L183:
	mov	ax,1
	jmp	SHORT $L182
	nop	
$L181:
	xor	ax,ax
$L182:
	cwd	
	mov	WORD PTR [bp-22],ax	;sumh
	mov	WORD PTR [bp-20],dx
	mov	eax,DWORD PTR [bp-34]	;__c
	mov	DWORD PTR [bp-26],eax	;suml
; Line 116
;	__c = -34
	les	bx,DWORD PTR [bp-8]	;cp
	mov	eax,DWORD PTR es:[bx+4]
	add	eax,DWORD PTR [bp-26]	;suml
	mov	DWORD PTR [bp-34],eax	;__c
	cmp	eax,DWORD PTR [bp-26]	;suml
	jae	SHORT $L184
$L186:
	mov	ax,1
	jmp	SHORT $L185
$L184:
	xor	ax,ax
$L185:
	cwd	
	add	WORD PTR [bp-22],ax	;sumh
	adc	WORD PTR [bp-20],dx
	mov	eax,DWORD PTR [bp-34]	;__c
	mov	DWORD PTR [bp-26],eax	;suml
; Line 117
;	__c = -34
	mov	eax,DWORD PTR [bp-30]	;carry
	add	eax,DWORD PTR [bp-26]	;suml
	mov	DWORD PTR [bp-34],eax	;__c
	cmp	eax,DWORD PTR [bp-26]	;suml
	jae	SHORT $L187
$L189:
	mov	ax,1
	jmp	SHORT $L188
$L187:
	xor	ax,ax
$L188:
	cwd	
	add	ax,WORD PTR [bp-22]	;sumh
	adc	dx,WORD PTR [bp-20]
	mov	WORD PTR [bp-30],ax	;carry
	mov	WORD PTR [bp-28],dx
	mov	eax,DWORD PTR [bp-34]	;__c
	mov	DWORD PTR es:[bx+4],eax
; Line 118
	add	WORD PTR [bp-8],4	;cp
; Line 119
	mov	ax,WORD PTR [bp+20]	;end
	inc	WORD PTR [bp-10]	;j
	cmp	WORD PTR [bp-10],ax	;j
	jl	$D156
; Line 120
	add	WORD PTR [bp-8],4	;cp
; Line 122
$FC165:
	cmp	DWORD PTR [bp-30],0	;carry
	je	SHORT $FB166
	mov	ax,WORD PTR [bp+20]	;end
	add	ax,ax
	cmp	ax,WORD PTR [bp-10]	;j
	jle	SHORT $FB166
; Line 123
;	__c = -34
	les	bx,DWORD PTR [bp-8]	;cp
	mov	eax,DWORD PTR es:[bx]
	add	eax,DWORD PTR [bp-30]	;carry
	mov	DWORD PTR [bp-34],eax	;__c
	cmp	DWORD PTR es:[bx],eax
	jbe	SHORT $L190
$L192:
	mov	ax,1
	jmp	SHORT $L191
$L190:
	xor	ax,ax
$L191:
	cwd	
	mov	WORD PTR [bp-30],ax	;carry
	mov	WORD PTR [bp-28],dx
	mov	eax,DWORD PTR [bp-34]	;__c
	mov	DWORD PTR es:[bx],eax
; Line 124
	add	WORD PTR [bp-8],4	;cp
; Line 125
	inc	WORD PTR [bp-10]	;j
; Line 126
	jmp	SHORT $FC165
$FB166:
; Line 127
	pop	si
	leave	
	ret	
	nop	

_SQUAREINNERLOOP	ENDP
LM_TEXT	ENDS
END
