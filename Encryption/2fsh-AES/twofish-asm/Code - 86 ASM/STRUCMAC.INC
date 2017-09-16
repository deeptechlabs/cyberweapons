;-----------------------------------------------------------------------------
;
;	STRUCMAC.INC  Copyright 1990 Houle Software, All Rights Reserved
;				(714) 557-1224
;
; This is a set of macros that allow structured programming constructs
; (if/endif...) to be used with Microsoft MASM 5.1+/Borland TASM 2.0+.
;
;
; Changes:
;	DLW	040194		32-bit code
;
;	DBR	081494		Changed "repeat" to "_rept" to avoid keyword
;				conflict with MASM 6.1.  Changed "." to "_"
;				throughout.  Removed "short" specification
;				to conditional jmps to __bb# for MASM6, since
;				this confused MASM6 and it gets it right
;				without the specification
;
;-----------------------------------------------------------------------------

  ifdef OFFSET32		;32-bit (386+) code
__386__	 equ	1		;386 opcodes OK
shortLim equ	07FFFFFFFH	;maximum "short" jump offset
  else
__386__	 equ	0		;doing 16-bit code only
shortLim equ	126		;limit for short jump in 16-bit code
  endif
 
jnna	equ	ja
jnnbe	equ	jbe
jnnae	equ	jae
jnnb	equ	jb
jnnc	equ	jc
jnne	equ	je
jnnz	equ	jz
jnng	equ	jg
jnnle	equ	jle
jnnge	equ	jge
jnnl	equ	jl
jnno	equ	jo
jnns	equ	js
jnnp	equ	jp
jnpe	equ	jpo
jnpo	equ	jpe
j	equ	jmp
jncxnz	equ	jcxz
jnecxnz	equ	<jecxz>
jn	macro
	endm
__blev	=	0
__ilev	=	0
__lbcnt	=	0



_rept	macro	cnd,sze
__blev	=	__blev+1
	irp	l,<%__blev>
__bf&&l	=	0
	ifnb	<cnd>
__lbcnt	=	__lbcnt+1
__bf&&l	=	__lbcnt
	irp	c,<%__lbcnt>
	 ifb	<sze>
	  jn&cnd short ?&&&c
	 elseif __386__
	  jn&cnd ?&&&c
	 else
	  j&cnd	$+5
	  jmp	?&&&c
	 endif
	endm
	endif
__bb&&l	=	this near
	endm
	endm

endr	macro
	irp	l,<%__blev>
	  jmp	__bb&&l
	  if	__bf&&l
	    irp	c,<%__bf&&l>
?&&&c:
	   endm
	  endif
	endm
__blev	=	__blev-1
	endm

until	macro	cnd
	irp	l,<%__blev>
	ifnb	<cnd>
	 if	(offset $-__bb&&l) le shortLim
	  ifdef MASM6
	   jn&cnd __bb&&l
	  else
	   jn&cnd __bb&&l
	  endif
	 elseif __386__
	  jn&cnd  __bb&&l
	 else
	  j&cnd	short $+5
	  jmp	__bb&&l
	 endif
	endif
	if	__bf&&l
	irp	c,<%__bf&&l>
?&&&c:
	endm
	endif
	endm
__blev	=	__blev-1
	endm

begin	macro	cnd,lvl
  ifb <lvl>
__bgLev	=	__blev
  else
__bgLev	=	__blev-lvl
  endif
	irp	l,<%__bgLev>
	if	(offset $-__bb&&l) le shortLim
	  j&cnd	__bb&&l
	else
	  jn&cnd short $+5
	  jmp	__bb&&l
	endif
	endm
	endm

break	macro	cnd,sze,lvl
  ifb <lvl>
__bkLev	=	__blev
  else
__bkLev	=	__blev-lvl
  endif
	irp	l,<%__bkLev>
	ife	__bf&&l
__lbcnt	=	__lbcnt+1
__bf&&l	=	__lbcnt
	endif
	irp	c,<%__bf&&l>
	ifb	<sze>
	  j&cnd short ?&&&c
	elseif __386__
	  j&cnd ?&&&c
	else
	  jn&cnd short $+5
	  jmp	?&&&c
	endif
	endm
	endm
	endm

iff	macro	cnd,sze
__ilev	=	__ilev+1
	irp	l,<%__ilev>
__lbcnt	=	__lbcnt+1
__if&&l	=	__lbcnt
__ib&&l	=	0
	irp	c,<%__lbcnt>
	ifb	<sze>
	  jn&cnd short ?&&&c
	elseif __386__
	  jn&cnd ?&&&c
	else
	  j&cnd	$+5
	  jmp	?&&&c
	endif
	endm
	endm
	endm

ifbrk	macro	cnd,sze,lvl
  ifb <lvl>
__ibLev	=	__ilev
  else
__ibLev	=	__ilev-lvl
  endif
	irp	l,<%__ibLev>
	ife	__ib&&l
__lbcnt	=	__lbcnt+1
__ib&&l	=	__lbcnt
	endif
	irp	c,<%__ib&&l>
	ifb	<sze>
	  j&cnd short ?&&&c
	elseif __386__
	  j&cnd   ?&&&c
	else
	  jn&cnd short $+5
	  jmp	?&&&c
	endif
	endm
	endm
	endm

elbrk	macro	cnd,sze,lvl
  ifb <lvl>
__ibLev	=	__ilev
  else
__ibLev	=	__ilev-lvl
  endif
	irp	l,<%__ibLev>
	irp	c,<%__if&&l>
	ifb	<sze>
	  j&cnd short ?&&&c
	elseif __386__
	  j&cnd  ?&&&c
	else
	  jn&cnd short $+5
	  jmp	 ?&&&c
	endif
	endm
	endm
	endm

elsef	macro	cnd,sze
__lbcnt	=	__lbcnt+1
	irp	l,<%__ilev>
	irp	c,<%__lbcnt>
	ifb	<sze>
	  j&cnd short ?&&&c
	elseif __386__
	  j&cnd   ?&&&c
	else
	  jn&cnd short $+5
	  jmp	?&&&c
	endif
	endm
	irp	c,<%__if&&l>
?&&&c:
	endm
__if&&l	=	__lbcnt
	endm
	endm

endi	macro
	irp	l,<%__ilev>
	irp	c,<%__if&&l>
?&&&c:
	endm
	if	__ib&&l
	irp	c,<%__ib&&l>
?&&&c:
	endm
	endif
	endm
__ilev	=	__ilev-1
	endm

doloop	macro	cnd,sze
	_rept	cnd,sze
	endm

endd	macro	cnd
	irp	l,<%__blev>
	loop&cnd __bb&&l
	if	__bf&&l
	irp	c,<%__bf&&l>
?&&&c:
	endm
	endif
	endm
__blev	=	__blev-1
	endm

;-----------------------------------------------------------------------------
;
;	End of STRUCMAC.INC.
;
;-----------------------------------------------------------------------------
