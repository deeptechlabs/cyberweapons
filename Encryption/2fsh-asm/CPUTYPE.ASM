	TITLE cpuid3a
	.386
	.model flat

; Filename: cpuid3a.asm
; Copyright 1993, 1994, 1995, 1996, 1997 by Intel Corp.
;
; This program has been developed by Intel Corporation. Intel
; has various intellectual property rights which it may assert
; under certain circumstances, such as if another
; manufacturer’s processor mis-identifies itself as being
; “GenuineIntel” when the CPUID instruction is executed.
;
; Intel specifically disclaims all warranties, express or
; implied, and all liability, including consequential and other
; indirect damages, for the use of this program, including
; liability for infringement of any proprietary rights,
; and including the warranties of merchantability and fitness
; for a particular purpose. Intel does not assume any
; responsibility for any errors which may appear in this program
; nor any responsibility to update it.
;
; This code contains two procedures:
; _get_cpu_type: Identifies processor type in _cpu_type:
;		0=8086/8088 processor
;		2=Intel 286 processor
;		3=Intel386(TM) family processor
;		4=Intel486(TM) family processor
;		5=Pentium(R) family processor
;		6=P6 family of processors (Pentium Pro/Pentium II)
;
; This program has been tested with the Microsoft Developer Studio.
; This code correctly detects the current Intel 8086/8088,
; 80286, 80386, 80486, Pentium(R), Pentium(R) Pro, and Pentium(R) II
; processors in the real-address mode only.
;
CPU_ID	macro
		db 0fh			; Hardcoded CPUID instruction
		db 0a2h
endm

CPU_ID_STRUC	struc
cpu_type		db		0
fpu_type		db		0
v86_flag		db		0
cpuid_flag		db		0
intel_CPU		db		0
sep_flag		db		0
vendor_id		dd		3 dup (?)
cpu_signature	dd		0
features_ecx	dd		0
features_edx	dd		0
features_ebx	dd		0
CPU_ID_STRUC	ends


	.code
	 public _get_cpu_type
;*********************************************************************
; This procedure determines the type of processor in a system
; and sets the ID.cpu_type variable with the appropriate
; value, then returns the value in EAX.
;
; If the CPUID instruction is available, it is used
; to determine more specific details about the processor.
; All registers are used by this procedure, none are preserved.
;
; To avoid AC faults, the AM bit in CR0 must not be set.
;
; This assumes the CPU is at least a 386, running in flat mode.
;
intel_id	label	dword
			db		'GenuineIntel'	; match signature

_get_cpu_type proc
	pushad						; save all regs on the stack
	sub		esp,size CPU_ID_STRUC
ID	equ		<[esp+BIAS]>		; use this as the struct ptr
BIAS =		0

check_80386:
	pushfd						; push original EFLAGS
	pop		eax					; get original EFLAGS
	mov		ecx, eax			; save original EFLAGS
	xor		eax, 40000h			; flip AC bit in EFLAGS
	push	eax					; save new EFLAGS value on stack
	popfd						; replace current EFLAGS value
	pushfd						; get new EFLAGS
	pop		eax					; store new EFLAGS in EAX
	xor		eax, ecx			; can’t toggle AC bit, processor=80386
	mov		ID.cpu_type, 3		; turn on 80386 processor flag
	jz		short end_cpu_type	; jump if 80386 processor
	push	ecx
	popfd						; restore AC bit in EFLAGS first

	; Intel486 processor check
	; Checking for ability to set/clear ID flag (Bit 21) in EFLAGS
	; which indicates the presence of a processor with the CPUID
	; instruction.
	.486
check_80486:
	mov		ID.cpu_type, 4		; turn on 80486 processor flag
	mov		eax, ecx			; get original EFLAGS
	xor		eax, 200000h		; flip ID bit in EFLAGS
	push	eax					; save new EFLAGS value on stack
	popfd						; replace current EFLAGS value
	pushfd						; get new EFLAGS
	pop		eax					; store new EFLAGS in EAX
	xor		eax, ecx			; can’t toggle ID bit,
	je		short end_cpu_type	; processor=80486

	; Execute CPUID instruction to not determine vendor, family,
	; model	stepping and features. For the purpose of this
	; code only the initial set of CPUID information is saved.
	mov		ID.cpuid_flag, 1	; flag indicating use of CPUID inst.
	push	ebx					; save registers
	push	esi
	push	edi
BIAS =		12
	mov		eax, 0				; set up for CPUID instruction
	CPU_ID						; get and save vendor ID
	mov		ID.vendor_id, ebx
	mov		ID.vendor_id[4], edx
	mov		ID.vendor_id[8], ecx
	cmp		intel_id, ebx
	jne		short end_cpuid_type
	cmp		intel_id[4], edx
	jne		short end_cpuid_type
	cmp		intel_id[8], ecx
	jne		short end_cpuid_type; if not equal, not an Intel processor

	mov		ID.intel_CPU, 1		; indicate an Intel processor
	cmp		eax, 1				; make sure 1 is valid input for CPUID
	jl		end_cpuid_type		; if not, jump to end
	mov		eax, 1
	CPU_ID						; get family/model/stepping/features
	mov		ID.cpu_signature, eax
	mov		ID.features_ebx, ebx
	mov		ID.features_edx, edx
	mov		ID.features_ecx, ecx
	shr		eax, 8				; isolate family
	and		eax, 0fh
	mov		ID.cpu_type, al		; set _cpu_type with family

end_cpuid_type:
	pop		edi					; restore registers
	pop		esi
	pop		ebx
BIAS = 0
	;
	; comment this line for 32-bit segments
	;
end_cpu_type:
	xor		eax,eax
	mov		al,ID.cpu_type
	add		esp,size CPU_ID_STRUC
	mov		[esp+28],eax		; let return value be on the stack
	popad
	ret
_get_cpu_type endp

	end