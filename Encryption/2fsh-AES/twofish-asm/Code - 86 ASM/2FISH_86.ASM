	page	60,160
	title	Twofish for 386+, Author: Doug Whiting, Hi/fn
;  
; WARNING: This module is written for speed, not clarity! 
;
	.386
	.MODEL FLAT, C 

	public	blockEncrypt_86,blockDecrypt_86,reKey_86

	.DATA
blockEncrypt_86 dd  E_SelectCPU				;first time thru, use get_cpu_type
blockDecrypt_86 dd  D_SelectCPU
reKey_86		dd	R_SelectCPU

	extrn	MDStab:dword					;MDS multiply matrix (pre-permuted)
	extrn	P8x8:byte						;two fixed 8x8 permutations

q0	equ		P8x8[0]
q1	equ		P8x8[256]

	.CODE
;
; ML syntax:
;  ml.exe -Flt2fish_86.lst -coff -Cx -Zi -Zm -c -DMASM6 2fish_86.asm
;----------------------------------------------------------------------------------
;			Useful general macros
;----------------------------------------------------------------------------------
OFFSET32		equ		1					;force 32-bit strucmac stuff
	.xlist									;don't expand strucmac defns
	include		strucmac.inc
	.list

KM_ZERO		=	1							;KEY_MODE bits
KM_MIN		=	2
KM_PART		=	4
KM_FULL		=	8
KM_COMPILE	=	16

  ifdef PART_KEY
  %out	Assembly with PART_KEY
KEY_MODE	=	KM_PART
  elseifdef MIN_KEY
  %out	Assembly with MIN_KEY
KEY_MODE	=	KM_MIN

  elseifdef ZERO_KEY
  %out	Assembly with ZERO_KEY
KEY_MODE	=	KM_ZERO
sboxK8		equ	<ks.fullSbox>				;use S-box to expand keys for PentiumPro
  elseifdef COMPILE_KEY
KEY_MODE	=	KM_COMPILE
  else	;default is full key
  %out	Assembly with FULL_KEY
KEY_MODE	=	KM_FULL
  endif

;
; where the permutations are used
;
P_00	equ		q1							;"outermost" permutation (in MDSmat)
P_01	equ		q0
P_02	equ		q0	
P_03	equ		q1
P_04	equ		q1

P_10	equ		q0
P_11	equ		q0
P_12	equ		q1
P_13	equ		q1
P_14	equ		q0

P_20	equ		q1
P_21	equ		q1
P_22	equ		q0
P_23	equ		q0
P_24	equ		q0

P_30	equ		q0
P_31	equ		q1
P_32	equ		q1
P_33	equ		q0
P_34	equ		q1
;
; useful in "splicing" names together
concat	macro	aa,bb,cc,dd,ee,ff,gg			;;__TRANSPARENT__ (signal to LST2ASM)
aa&bb&cc&dd&ee&ff&gg
endm

alloc	macro	varName,varType,varSize		;macro to help define parms/locals
	irp XX,<%varOffs>
varName equ varType ptr [esp+XX]
	endm
varOffs =	varOffs+varSize;
endm

; copy from src to dst (use eax,ebx)
Copy8	macro	dst,src
  ifnb <src>
		mov		eax,src						;load source dwords(if needed)
		mov		ebx,src+4
  endif	
		mov		dst,eax						;store new dst dwords
		mov		dst+4,ebx
endm

;
;dst = xorA ^ xorb ^ xorC	(8 bytes, xorC may be blank)
;returns two dst dwords in eax,ebx.  Trashes ecx,edx
;oldDst = where to copy dst (for CBC mode)
Xor8	macro	lbl,cpuName,dst,xorA,subKeyIndex,xorC,oldDst
  ifnb <xorA>
		mov		eax,xorA		;load both A dwords (unless already loaded)
		mov		ebx,xorA+4
  endif
  if (KEY_MODE and KM_COMPILE) eq 0
		mov		ecx,ks.subKeys[subKeyIndex]	;load both B dwords
		mov		edx,ks.subKeys[subKeyIndex+4]

		xor		eax,ecx			;compute A ^ B
		xor		ebx,edx
  else
		xor		eax,12345678h
concat lbl,_SK_,%((subKeyIndex)/4),<_>,cpuName,< label dword>
		xor		ebx,12345678h
concat lbl,_SK_,%((subKeyIndex)/4+1),<_>,cpuName,< label dword>
  endif
  ifnb <xorC>
		mov		ecx,xorC		;load both C dwords
		mov		edx,xorC+4

		xor		eax,ecx			;compute A ^ B ^ C
		xor		ebx,edx
  endif
  ifnb <dst>
    ifnb <oldDst>
		mov		ecx,dst			;pick up previous ciphertext value
		mov		edx,dst+4

		mov		oldDst,ecx		;and make copy (for next IV)
		mov		oldDst+4,edx
    endif
		mov		dst,eax			;save the result
		mov		dst+4,ebx		;(and return in eax,ebx)
  endif
endm
;
;----------------------------------------------------------------------------------
;			Definitions, Structures (AES.H)
;----------------------------------------------------------------------------------
;
BLOCK_SIZE		equ		128
MAX_KEY_BITS	equ		256
MAX_ROUNDS		equ		16

INPUT_WHITEN	equ		0
OUTPUT_WHITEN	equ		(BLOCK_SIZE/8)
ROUND_SUBKEYS	equ		(OUTPUT_WHITEN+BLOCK_SIZE/8)
TOTAL_SUBKEYS	equ		((ROUND_SUBKEYS/4)+2*MAX_ROUNDS)
SUBKEY_SIZE		equ		<4*TOTAL_SUBKEYS>

DIR_ENCRYPT		equ		0
DIR_DECRYPT		equ		1
MODE_ECB		equ		1
MODE_CBC		equ		2
MODE_CFB1		equ		3
  if KEY_MODE and KM_COMPILE
VALID_SIG		equ		504D4F43h	;'COMP'
  else
VALID_SIG		equ		48534946h	;'FISH'
  endif

cipherInstance struc
mode			db		4 dup  (?)			;MODE_ECB, MODE_CBC (Let C code handle MODE_CFB1)
CFB1_IV			db		BLOCK_SIZE/8 dup (?);CFB1 IV bytes
cipherSig		dd		?					;should be VALID_SIG
IV32			dd		BLOCK_SIZE/32 dup (?);CBC  IV dwords
cipherInstance ends

keyInstance struc
direction		db		4 dup (?)			;DIR_ENCRYPT or DIR_DECRYPT
keyLen			dd		?					;length of the key in bits
keyMaterial		db		68 dup (?)			;ASCII key material
keySig			dd		?					;should be VALID_SIG
numRounds		dd		?					;should be 16
key32			dd		MAX_KEY_BITS/32 dup (?) 
sboxKeys		dd		MAX_KEY_BITS/64 dup (?)
subKeys			dd		TOTAL_SUBKEYS	dup (?)
fullSbox		dd		4*256 dup (?)		;S-box plus MDS
  if KEY_MODE and KM_COMPILE
encryptFuncPtr	dd		(?)					;ptr to encrypt function
decryptFuncPtr	dd		(?)					;ptr to encrypt function
codeSize		dd		(?)					;sizeof cipherProcCode
cipherProcCode	dd		(4600/4) dup (?)	;compiled code itself
  endif
keyInstance ends

;
; To minimize code space, bias ebp to generate as many 8-bit offsets as possible
;
BIAS_VAL		=		(fullSbox-(TOTAL_SUBKEYS*2))
biasEBP			equ		<add ebp,BIAS_VAL>
ks				equ		<[ebp-BIAS_VAL]>

;
;----------------------------------------------------------------------------------
;	KeyMode-dependent definitions
;----------------------------------------------------------------------------------

SBOX_SIZE	equ		1024
  if KEY_MODE and (KM_FULL or KM_COMPILE)
S32_0		equ		<ks.fullSbox[0*SBOX_SIZE]>
S32_1		equ		<ks.fullSbox[0*SBOX_SIZE+4]>
S32_2		equ		<ks.fullSbox[2*SBOX_SIZE]>
S32_3		equ		<ks.fullSbox[2*SBOX_SIZE+4]>
SBS			=		8
EDX_ADJUST	=		100h		;optimize for Pentium code size!
else
S32_0		equ		<MDStab>
S32_1		equ		<MDStab[SBOX_SIZE]>
S32_2		equ		<MDStab[SBOX_SIZE*2]>
S32_3		equ		<MDStab[SBOX_SIZE*3]>
S8_0		equ		<byte ptr ks.fullSbox>
S8_1		equ		<byte ptr ks.fullSbox[100h]>
S8_2		equ		<byte ptr ks.fullSbox[200h]>
S8_3		equ		<byte ptr ks.fullSbox[300h]>
SBS			=		4
EDX_ADJUST	=		300h		;optimize for Pentium code size!
  endif

EAX_ADJUST	=		0			;these defns make handling EDX_ADJUST easier
EBX_ADJUST	=		0
ECX_ADJUST	=		0
;
;----------------------------------------------------------------------------------
;	Macros for dealing with non-full keying S-boxes
;----------------------------------------------------------------------------------
;
if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
lookupS8 macro	cpuName,R,i			;__TRANSPARENT__
  ifnb <R>
   ifdif <cpuName>,<PentiumPro>
	mov		R&L,S8_&i[E&R&X-E&R&X_ADJUST]
   else
	movzx	R,S8_&i[R]
   endif
  endif
endm

keyXor8	macro	cpuName,R,I			;__TRANSPARENT__
  ifnb <R>
   ifdif <cpuName>,<PentiumPro>
	xor		R&L,byte ptr ks.sboxKeys[I]
   else
	xor		R,sboxK8[4*I]			;the byte is expanded to 32 bits here
   endif
  endif
endm

lookupQ	macro	cpuName,R,i,j		;__TRANSPARENT__
  ifnb <R>
   ifdif <cpuName>,<PentiumPro>
    mov		R&L,P_&i&j[E&R&X-E&R&X_ADJUST]
   else
    movzx	R,P_&i&j[R]
   endif
  endif
endm

doS4	macro	cpuName,W,R1,R2,i1,i2,R3,R4,i3,i4	;__TRANSPARENT__
	lookupQ		cpuName,R1,i1,%(W)
	lookupQ		cpuName,R2,i2,%(W)
	lookupQ		cpuName,R3,i3,%(W)
	lookupQ		cpuName,R4,i4,%(W)

    keyXor8		cpuName,R1,%(i1+4*W-4)
    keyXor8		cpuName,R2,%(i2+4*W-4)
    keyXor8		cpuName,R3,%(i3+4*W-4)
    keyXor8		cpuName,R4,%(i4+4*W-4)
endm

; this macro is a nop for full keying
doSbox	macro	keySize,cpuName,R1,R2,i1,i2,R3,R4,i3,i4
 if KEY_MODE and (KM_PART or KM_MIN)	;use 8-bit precomputed S-box
	lookupS8	cpuName,R1,i1
	lookupS8	cpuName,R2,i2
	lookupS8	cpuName,R3,i3
	lookupS8	cpuName,R4,i4
 elseif KEY_MODE and KM_ZERO
  if keySize gt 128
   if keySize gt 192
	doS4		cpuName,4,R1,R2,i1,i2,R3,R4,i3,i4
   endif
	doS4		cpuName,3,R1,R2,i1,i2,R3,R4,i3,i4
  endif
	doS4		cpuName,2,R1,R2,i1,i2,R3,R4,i3,i4
 endif
 if KEY_MODE and (KM_MIN or KM_ZERO)	;run bytes thru "next-to-last" 8-bit permutation, key xor
	doS4		cpuName,1,R1,R2,i1,i2,R3,R4,i3,i4
 endif
endm
endif	;!(KM_FULL or KM_COMPILE)

GetSubkey	macro	lbl,dstReg,skOffs	;__TRANSPARENT__
  if KEY_MODE and KM_ZERO
	mov		dstReg,roundNum
	mov		dstReg,ks.subKeys[8*dstReg+8*4+skOffs]
  else
	mov		dstReg,ks.subKeys[skOffs]
  endif
endm

;
;----------------------------------------------------------------------------------
;		Round function macros
;----------------------------------------------------------------------------------
;
RoundFunc	macro	keySize,lbl,cpuName,z0,z1,z2,z3,R,S_INDEX
concat lbl,keySize,Round_,%(R+1),<_>,cpuName,<:>	;keep the listing easy to follow
 ifdif		<cpuName>,<PentiumPro>
	mov		z0,eax				;save previous round Feistel results (not on first round)
	mov		z1,ebx

	mov		cl,ah				;set up to access Sbox
	mov		dl,bh

	and		eax,0FFH
	and		ebx,0FFH

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,C,D,1,2,A,B,0,1
  endif

	mov		esi,S32_1[SBS*ecx]	;"interleave" even/odd Sboxes --> no cache bank problems
	mov		edi,S32_2[SBS*edx-SBS*EDX_ADJUST]

	mov		cl,byte ptr z0[2]
	mov		dl,byte ptr z1[2]

	mov		eax,S32_0[SBS*eax]
	mov		ebx,S32_1[SBS*ebx]

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,C,D,2,3
  endif

	xor		esi,eax
	xor		edi,ebx

	mov		eax,S32_2[SBS*ecx]
	mov		ebx,S32_3[SBS*edx-SBS*EDX_ADJUST]

	mov		dl,byte ptr z0[3]
	mov		cl,byte ptr z1[3]
	
	xor		esi,eax
	xor		edi,ebx

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,C,D,0,3
  endif

	mov		ebx,S32_0[SBS*ecx]
	mov		eax,S32_3[SBS*edx-SBS*EDX_ADJUST]

	xor		esi,eax
	xor		edi,ebx

  if (KEY_MODE and KM_COMPILE) eq 0
	add		esi,edi				;first half of the PHT
	GetSubkey lbl,eax,S_INDEX

	add		edi,esi				;complete the PHT
	GetSubkey lbl,ebx,S_INDEX+4

	add		esi,eax				;add in the round subkeys
	add		edi,ebx

	mov		eax,z2				;load z2,z3 to update them
	mov		ebx,z3
   ifdif <lbl>,<Enc>				;
	rol		eax,1				;Decryption: z2=ROL(z2,1)
	xor		ebx,edi				;half of Feistel xor

	ror		ebx,1				;Decryption: z3=ROR(z3,1)
	xor		eax,esi				;complete the Feistel xor
   else
	rol		ebx,1				;Encryption: z3=ROL(z3,1)
	xor		eax,esi				;half of Feistel xor

	ror		eax,1				;Encryption: z2=ROR(z2,1)
	xor		ebx,edi				;complete Feistel. eax,ebx=new z2,z3
   endif
  else ;--- do the compiled code thing
	mov		eax,z2				;load z2,z3 to update them
	mov		ebx,z3				;(and avoid AGI on lea opcodes below)
   ifdif <lbl>,<Enc>			;---do Decryption first
	rol		eax,1
	lea		ecx,[esi+2*edi+12345678h+4]
concat Dec_SK_,%((S_INDEX+4)/4),<_>,cpuName,<:>	;label so we can "patch" code

	xor		ebx,ecx
	lea		edi,[esi+edi+12345678h]
concat Dec_SK_,%((S_INDEX+0)/4),<_>,cpuName,<:>	;label so we can "patch" code

	ror		ebx,1
	xor		eax,edi
   else ;compile the encryption code
    rol		ebx,1
	lea		ecx,[esi+edi+12345678h]
concat Enc_SK_,%((S_INDEX+0)/4),<_>,cpuName,<:>	;label so we can "patch" code
   
	xor		eax,ecx
	lea		edi,[esi+2*edi+12345678h+4]
concat Enc_SK_,%((S_INDEX+4)/4),<_>,cpuName,<:>	;label so we can "patch" code
	
	ror		eax,1
	xor		ebx,edi
   endif
	xor		ecx,ecx
	inc		edi					;one byte opcode, NOP here
  endif
 else ; ----------------- the Pentium Pro/II version
	mov		z0,eax				;save previous round Feistel results (not on first round)
	movzx	esi,ah
	movzx	ecx,al

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,esi,ecx,1,0
  endif

	mov		z1,ebx
	mov		esi,S32_1[SBS*esi]
	shr		eax,16

	mov		ecx,S32_0[SBS*ecx]
	movzx	edi,bh
	movzx	edx,bl

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,edi,edx,2,1
  endif

	shr		ebx,16
	mov		edi,S32_2[SBS*edi]
	xor		esi,ecx

	mov		edx,S32_1[SBS*edx]
	movzx	ecx,ah
	movzx	eax,al

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,ecx,eax,3,2
  endif

	mov		ecx,S32_3[SBS*ecx]
	xor		edi,edx
	movzx	edx,bh

	mov		eax,S32_2[SBS*eax]
	movzx	ebx,bl
	xor		esi,ecx

  if (KEY_MODE and (KM_FULL or KM_COMPILE)) eq 0
	doSbox	keySize,cpuName,edx,ebx,0,3
  endif

	mov		edx,S32_0[SBS*edx]
	xor		esi,eax

	mov		ebx,S32_3[SBS*ebx]
	xor		edi,edx

  if (KEY_MODE and KM_COMPILE) eq 0
	GetSubkey lbl,eax,S_INDEX
	xor		edi,ebx

	GetSubkey lbl,ebx,S_INDEX+4
	add		esi,edi				;first half of the PHT

	add		edi,esi				;complete the PHT
	add		esi,eax				;add in the round subkeys
	mov		eax,z2				;load z2,z3 to update them

	add		edi,ebx
	mov		ebx,z3
   ifdif <lbl>,<Enc>
	rol		eax,1				;Decryption: z2=ROL(z2,1)
	xor		ebx,edi				;complete the Feistel xor

	ror		ebx,1				;Decryption: z3=ROR(z3,1)
	xor		eax,esi				;half of Feistel xor
   else
	xor		eax,esi				;half of Feistel xor

	rol		ebx,1				;Encryption: z3=ROL(z3,1)

	ror		eax,1				;Encryption: z2=ROR(z2,1)
	xor		ebx,edi				;complete Feistel. eax,ebx=new z2,z3
   endif
  else ;---"Compiled" constants code here
   ifdif <lbl>,<Enc>			;---do Decryption first
	xor		edi,ebx				;compute edi=final value of t1
	mov		eax,z2				;eax=x[2]

	mov		ebx,z3
	lea		edx,[esi+2*edi+12345678h]	;no AGI!
concat Dec_SK_,%((S_INDEX+4)/4),<_>,cpuName,<:>	;label so we can "patch" code
	rol		eax,1				;Decryption: z2=ROL(z2,1)
	
	lea		ecx,[esi+edi+12345678h+4]
concat Dec_SK_,%((S_INDEX+0)/4),<_>,cpuName,<:>
	xor		ebx,edx				;complete the Feistel xor

	ror		ebx,1				;Decryption: z3=ROR(z3,1)
	xor		eax,ecx				;half of Feistel xor
   else	 ;--- handle Encryption compilation here
	xor		edi,ebx		
	mov		ebx,z3

	mov		eax,z2
	lea		ecx,[esi+edi+12345678h+4]	;no AGI!
concat Enc_SK_,%((S_INDEX+0)/4),<_>,cpuName,<:>
	rol		ebx,1				;Encryption: z3=ROL(z3,1)
	
	lea		edx,[esi+2*edi+12345678h]
concat Enc_SK_,%((S_INDEX+4)/4),<_>,cpuName,<:>
	xor		eax,ecx				;half of Feistel xor

	ror		eax,1				;Encryption: z2=ROR(z2,1)
	xor		ebx,edx				;complete Feistel. eax,ebx=new z2,z3
   endif
  endif
 endif
endm

SetSboxK8 macro cpuName
 ifidn <cpuName>,<PentiumPro>	;split SboxKey into bytes...
  if KEY_MODE and KM_MIN		;and store as dwords	
	mov		edx,ks.sboxKeys[0]
	movzx	eax,dl					
	movzx	ebx,dh
	mov		sboxK8,eax
	shr		edx,16
	movzx	eax,dh
	mov		sboxK8+4,ebx
	movzx	edx,dl
	mov		sboxK8+12,eax
	mov		sboxK8+8,edx
  endif
 endif
endm

x0			equ		<x[0]>
x1			equ		<x[4]>
x2			equ		<x[8]>
x3			equ		<x[12]>

; do two rounds (subKeys are in reverse order)
Encrypt2Rounds	macro	roundNum,cpuName		;__TRANSPARENT__
	RoundFunc	,Enc,cpuName,x0,x1,x2,x3,%(roundNum)  ,%(ROUND_SUBKEYS+8*(MAX_ROUNDS-roundNum-1))
	RoundFunc	,Enc,cpuName,x2,x3,x0,x1,%(roundNum+1),%(ROUND_SUBKEYS+8*(MAX_ROUNDS-roundNum-2))
endm

; do two rounds
Decrypt2Rounds	macro	roundNum,cpuName		;__TRANSPARENT__
	RoundFunc	,Dec,cpuName,x2,x3,x0,x1,%(roundNum+1),%(ROUND_SUBKEYS+8*roundNum+8))
	RoundFunc	,Dec,cpuName,x0,x1,x2,x3,%(roundNum)  ,%(ROUND_SUBKEYS+8*roundNum))
endm
;
;----------------------------------------------------------------------------------
;		Encryption
;----------------------------------------------------------------------------------
;
	varOffs =	0
	alloc	x,dword,BLOCK_SIZE/8	;local copy of text
  if KEY_MODE and KM_MIN
	alloc	sboxK8,dword,4*4		;for Pentium Pro MIN_KEY mode
  endif
  if KEY_MODE and KM_ZERO
	alloc	roundNum,dword,4		;"soft" round number
	alloc	roundJmpPtr,dword,4		;dispatch based on key size
  endif
	alloc	IVptr,dword,4			;ptr to CBC IV (NULL --> ECB)
	localSize = varOffs
	alloc	regs,dword,8*4			;pushad puts regs here
	alloc	retAddr,dword,4			;esp --> here on entry
	alloc	cipherPtr,dword,4		;pointer to cipher (includes mode)
	alloc	ksPtr,dword,4			;pointer to initialized key schedule
	alloc	inputPtr,dword,4		;pointer to plaintext to encrypt
	alloc	inputLen,dword,4		;# bits to encrypt
	alloc	outBuffer,dword,4		;where to put ciphertext
retVal	equ regs[28]

cipherProc	macro	cpuName			;instantiate encrypt/decrypt functions
cipherProcStart_&cpuName:
TwoFishEncrypt_&cpuName proc
	pushad							;save all regs
	sub		esp,localSize			;set up local stack frame

	mov		ebp,ksPtr
	mov		edx,cipherPtr

	mov		esi,inputPtr			;is the text "in-place"?
	mov		edi,outBuffer

	mov		ecx,inputLen
	cmp		esi,edi

	mov		retVal,ecx				;save length as return value
	iff		nz						;if not, make it so
	  shr	ecx,5					;convert from bits to dwords
	 ifdif <cpuName>,<PentiumPro>
	  mov	eax,[edi]				;load some cache lines (for Pentium)
	  mov	ebx,[edi+32]
     endif
	  rep	movsd					;put the text in place
	endi

	biasEBP							;point EBP to Sbox 
	mov		al,[edx].mode			;figure out if we are in CBC mode

	cmp		al,MODE_CBC				;if so, make local copy of IV
	iff z
	  lea	edi,[edx+IV32]			;point edi directly to IV32
	elsef
	  xor	edi,edi					;NULL IVptr --> ECB mode
	endi

	SetSboxK8	cpuName
  if KEY_MODE and KM_ZERO
	mov		eax,ks.keyLen
	shr		eax,6					;divide by 64
	mov		eax,encJmpTab_&cpuName[4*eax-4]
	mov		roundJmpPtr,eax			;save dispatch address
  endif
	mov		esi,outBuffer			;set up for loop
	mov		IVptr,edi				;save IV ptr

	or		edi,edi
	iff nz
	  ;read plaintext block to x, add input whitening and IV input
	  ;edi == IVptr here
Enc_CBC_&cpuName:
	  Xor8	Enc_CBC,cpuName,x+8,[esi+8],INPUT_WHITEN+8,[edi+8]
	  Xor8	Enc_CBC,cpuName,   ,[esi]  ,INPUT_WHITEN  ,[edi]
	elsef
	align	4
Enc_ECB_&cpuName:
	  ;read plaintext block to x, add input whitening
	  Xor8	Enc,cpuName,x+8,[esi+8],INPUT_WHITEN+8
	  Xor8	Enc,cpuName,   ,[esi]  ,INPUT_WHITEN
	endi

	;whitening/IV merged in. Now we're ready to encrypt
	;eax=x0, ebx=x1. (already loaded from INPUT_WHITEN xor)
  ifdif		<cpuName>,<PentiumPro>
	xor		ecx,ecx					;zero out high bits
   if EDX_ADJUST
	mov		edx,EDX_ADJUST
   else
    xor		edx,edx
   endif
  endif

  if KEY_MODE and KM_ZERO
	mov		roundNum,14
	jmp		roundJmpPtr				;dispatch to appropriate handler
   irp _kSize,<256,192,128>
concat <encLoop_>,%(_kSize),<_>,cpuName:
	RoundFunc	_kSize,Enc,cpuName,x0,x1,x2,x3,0,8
	RoundFunc	_kSize,Enc,cpuName,x2,x3,x0,x1,1,0
	sub		roundNum,2
concat <jae encLoop_>,%(_kSize),<_>,cpuName
	if _kSize ne 128
	  jmp	encDone_&cpuName
	endif
   endm
encDone_&cpuName:
  else
	Encrypt2Rounds	0,cpuName
	Encrypt2Rounds	2,cpuName
	Encrypt2Rounds	4,cpuName
	Encrypt2Rounds	6,cpuName

	Encrypt2Rounds	8,cpuName
	Encrypt2Rounds	10,cpuName
	Encrypt2Rounds	12,cpuName
	Encrypt2Rounds	14,cpuName
  endif

	; here with eax=x0,ebx=x1, **unstored**.
	; done with encryption.	 Add output whitening
	mov		edi,IVptr				;get ready to test CBC mode below
	mov		esi,outBuffer

	Xor8	Enc,cpuName,[esi+8],   ,OUTPUT_WHITEN+8
	Xor8	Enc,cpuName,[esi]  ,x+8,OUTPUT_WHITEN

	add		esi,BLOCK_SIZE/8
	mov		ecx,inputLen

	mov		outBuffer,esi			;save updated buffer ptr
	sub		ecx,BLOCK_SIZE			;are we done yet?

	mov		inputLen,ecx			;save updated length

	or		edi,edi					;are we in CBC mode?
	iff z
	  or	ecx,ecx
	  jg	Enc_ECB_&cpuName		;we can only do 2Gbits per call!
	elsef
	  Copy8	[edi]					;if so, save new IV for next time
	  Copy8	[edi+8],[esi-8]			;[esi-8] because we just added 16 to esi

	  or	ecx,ecx
	  jg	Enc_CBC_&cpuName
	endi

	; clean up stack and return
	add		esp,localSize
	popad							;restore regs, including retVal to eax
	ret

  if KEY_MODE and KM_ZERO
encJmpTab_&cpuName	label	dword
		dd	encLoop_128_&cpuName,encLoop_128_&cpuName	
		dd	encLoop_192_&cpuName,encLoop_256_&cpuName
  endif

 if KEY_MODE and KM_COMPILE			;make a subkey compilation "patch" list
PatchList_Enc_&cpuName	label	dword
QQ=0
  rept	8
	irp SKn,<%QQ>
concat	<  dd Enc_SK_>,%(QQ),<_>,cpuName,<-4>
	endm
  QQ=QQ+1
  endm
QQ=0
  rept	TOTAL_SUBKEYS-8
	irp SKn,<%QQ>
concat	<  dd Enc_SK_>,%((39-QQ) xor 1),<_>,cpuName,<-4>
	endm
  QQ=QQ+1
  endm
 endif
	irp	cby,<%($-TwoFishEncrypt_&cpuName)>	;display code size at assemble time
	  %out	--- Encrypt assembly code size == cby bytes (cpuName)
	endm
TwoFishEncrypt_&cpuName endp

;
;----------------------------------------------------------------------------------
;		Decryption
;----------------------------------------------------------------------------------
;
; use same parameters and locals as blockEncrypt_86

TwoFishDecrypt_&cpuName proc	
	pushad							;save all regs
	sub		esp,localSize			;set up local stack frame

	mov		ebp,ksPtr
	mov		edx,cipherPtr

	mov		esi,inputPtr			;is the text "in-place"?
	mov		edi,outBuffer

	mov		ecx,inputLen
	cmp		esi,edi

	mov		retVal,ecx				;save length as return value
	iff		nz						;if not, make it so
	  shr	ecx,5					;convert from bits to dwords
	 ifdif <cpuName>,<PentiumPro>
	  mov	eax,[edi]				;load some cache lines (for Pentium)
	  mov	ebx,[edi+32]
     endif
	  rep	movsd					;put the text in place
	endi

	biasEBP							;point EBP to Sbox 
	mov		al,[edx].mode			;figure out if we are in CBC mode

	cmp		al,MODE_CBC				;if so, make local copy of IV
	iff z
	  add	edx,IV32				;point edx directly to IV32
	elsef
	  xor	edx,edx					;NULL --> in ECB mode
	endi

	mov		esi,outBuffer
	mov		IVptr,edx

	SetSboxK8	cpuName
  if KEY_MODE and KM_ZERO
	mov		eax,ks.keyLen
	shr		eax,6					;divide by 64
	mov		eax,decJmpTab_&cpuName[4*eax-4]
	mov		roundJmpPtr,eax			;save dispatch address
  endif

	; --- main Decryption block loop ---
decryptLoop_&cpuName:
	Xor8	Dec,cpuName,x,[esi+8],OUTPUT_WHITEN+8
	Xor8	Dec,cpuName, ,[esi]  ,OUTPUT_WHITEN

  ifdif		<cpuName>,<PentiumPro>
	xor		ecx,ecx					;zero out high bits
   if EDX_ADJUST
	mov		edx,EDX_ADJUST
   else
    xor		edx,edx
   endif
  endif

  if KEY_MODE and KM_ZERO
	mov		roundNum,14
	jmp		roundJmpPtr				;dispatch to appropriate handler
   irp		_kSize,<256,192,128>
concat decLoop_,%(_kSize),<_>,cpuName,<:>
	RoundFunc	_kSize,Dec,cpuName,x2,x3,x0,x1,0,8
	RoundFunc	_kSize,Dec,cpuName,x0,x1,x2,x3,1,0
	sub		roundNum,2
concat <jae decLoop_>,%(_kSize),<_>,cpuName
	if _kSize ne 128
	  jmp	decDone_&cpuName
	endif
   endm
decDone_&cpuName:
  else
	Decrypt2Rounds	14,cpuName		;do rounds in reverse order
	Decrypt2Rounds	12,cpuName
	Decrypt2Rounds	10,cpuName
	Decrypt2Rounds	8,cpuName

	Decrypt2Rounds	6,cpuName
	Decrypt2Rounds	4,cpuName
	Decrypt2Rounds	2,cpuName
	Decrypt2Rounds	0,cpuName
  endif
	mov		edi,IVptr
	mov		esi,outBuffer			;remove input whitening, store plaintext

	or		edi,edi					;are we in CBC mode?
	iff nz
	  Xor8	Dec_CBC,cpuName,[esi+8],   ,INPUT_WHITEN+8,[edi+8],[edi+8]
	  Xor8	Dec_CBC,cpuName,[esi]  ,x  ,INPUT_WHITEN  ,[edi]  ,[edi]
	elsef
	  Xor8	Dec,cpuName,[esi+8],   ,INPUT_WHITEN+8
	  Xor8	Dec,cpuName,[esi]  ,x  ,INPUT_WHITEN
	endi

	add		esi,BLOCK_SIZE/8
	mov		edi,inputLen

	mov		outBuffer,esi
	sub		edi,BLOCK_SIZE

	mov		inputLen,edi			;save updated length
	ja		decryptLoop_&cpuName	;are we done? if not, go back for more

	; clean up stack and return
	add		esp,localSize
	popad							;restore regs, including retVal to eax
	ret

  if KEY_MODE and KM_ZERO
decJmpTab_&cpuName	label	dword
		dd	decLoop_128_&cpuName,decLoop_128_&cpuName
		dd	decLoop_192_&cpuName,decLoop_256_&cpuName
  endif
	irp	cby,<%($-TwoFishDecrypt_&cpuName)>	;display code size at assemble time
	  %out	--- Decrypt assembly code size == cby bytes (cpuName)
	endm
cipherProcEnd_&cpuName	label	byte

 if KEY_MODE and KM_COMPILE			;make a subkey compilation "patch" list
PatchList_Dec_&cpuName	label	dword
QQ=0
  rept	TOTAL_SUBKEYS
	irp SKn,<%QQ>
concat	<  dd Dec_SK_>,%(QQ),<_>,cpuName,<-4>
	endm
  QQ=QQ+1
  endm
endif
TwoFishDecrypt_&cpuName endp
endm ;cipherProc 
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 
;
;-------------------------- Key schedule ----------------------- 
;
varOffs = 0 
	alloc	kLen64,dword,4					;keyLen in bits/64
	alloc	reKeyJmpPtr,dword,4				;key-size dependent function ptr
	alloc	SboxKey,dword,MAX_KEY_BITS/16	;Sbox keys (RS code over k32o,k32o) 
	alloc	tmp0,dword,4
	alloc	tmp1,dword,4
	alloc	tmp2,dword,4
	alloc	tmp3,dword,4
	alloc	localPool,dword,4*SUBKEY_SIZE+(MAX_KEY_BITS/8)+4
	localSize2 = varOffs 
	alloc	_regs,dword,8*4					;pushad puts regs here 
	alloc	_retAddr,dword,4				;esp --> here on entry 
	alloc	keyPtr,dword,4					;pointer to key schedule to initialize 
;
; localPool usage during subkey generation
lKey32		equ		<localPool>				;local copy of the key bits
lSubkey		equ		<lKey32[MAX_KEY_BITS/8]>;local copy of subkey material
; localPool usage during S-box generation
pPtr		equ		<localPool>
kPtr		equ		<localPool+4>
tmpSbox		equ		<localPool+8>
tmpSbox8	equ		<byte ptr tmpSbox>
;
;----------------------------------------------------------------
; RSrem
; Input:	edx	=	dword to be shifted 4 times
; Output:	edx =	dword shifted
;			ecx,edi unmodified
; Note:		Speed is not a very significant issue here. 
;			If it were, an 8x32 feedback table could be built.
;
;	g(x) = x^4 + A4 x^3 + 02 x^2 + A4 x + 1		;primitive polynomial = 14D
;
; This RSrem code runs equally well on a Pentium or Pentium Pro.  It is a little
; larger than Pentium-specific code (40 bytes), but not enough to worry about.
;
RSrem	proc
	push	ecx					;do not modify ecx here
	mov		ecx,4
remLoop:
	rol		edx,8				;put new byte into place

	mov		eax,0FEH
	mov		esi,1				;get ready to mask from new byte
	mov		ebx,0FFH

	and		eax,edx
	and		esi,edx				;esi=bit 0 of feedback byte
	and		ebx,edx				;ignore all but the important bits

	shl		eax,23
	xor		esi,1
	xor		ebx,80h

	xor		edx,eax
	dec		esi					;make esi = all zeroes or all ones
	sub		ebx,80h				;set upper 25 bits of ebx

	shr		eax,16
	and		esi,0A600A600H		;mask the position
	add		ebx,ebx				;shift ebx into position

	xor		edx,eax
	xor		edx,esi
	mov		esi,ebx

	shl		esi,24
	and		ebx,4D4D4D00H

	xor		edx,ebx
	mov		ebx,esi

	shr		esi,8
	xor		edx,ebx

	shr		ebx,16
	xor		edx,esi

	xor		edx,ebx

	dec		ecx
	jnz		remLoop
	pop		ecx
	ret
RSrem	endp

mdsOffsTab	dd	0,4,2*1024,2*1024+4
			;	    LSB            MSB
pTab		dd		P_01,P_11,P_21,P_31		;"last" stage (previous to MDSmat)
			dd		P_02,P_12,P_22,P_32
			dd		P_03,P_13,P_23,P_33	
			dd		P_04,P_14,P_24,P_34	
pPtrTab		dd		pTab,pTab+16,pTab+32,pTab+48

  if KEY_MODE AND (KM_PART or KM_MIN)
x8Tab		dd		0,100h,200h,300h
  endif
;
reKeySharedSize	=	$-RSrem

ldCache	macro addr,byteCnt,cpuName
  ifdif <cpuName>,<PentiumPro>
NN=0
  rept (byteCnt+63)/64			;force cache line load (Pentium only)
    irp QQ,<%(NN)>
    mov		eax,addr[QQ]
	endm
   if (NN+32) lt byteCnt
    irp QQ,<%(NN+36)>
      mov	ebx,addr[QQ]
	endm
   endif
NN=NN+64
  endm
  endif
endm

pXor8	macro	dst,src,reg,N
	mov		eax,src+N
	mov		ebx,src+N+4
	xor		eax,reg
	xor		ebx,reg
	mov		dst+N,eax
	mov		dst+N+4,ebx
endm

ld8		macro	dstReg,src,cpuName	;;__TRANSPARENT__
  ifdif <cpuName>,<PentiumPro>
	mov		dstReg&l,byte ptr src
  else
	movzx	e&dstReg&x,byte ptr src
  endif
endm

skLdKey	macro	keySize,N,cpuName	;;__TRANSPARENT__
  ifdif <cpuName>,<PentiumPro>
	mov		cl,byte ptr lKey32[N]
	mov		dl,byte ptr lKey32[N+8]
   if keySize eq 128
	mov		ebp,ecx
	mov		esi,edx					;load esi/ebp with key bytes
   elseif keySize eq 192
	mov		tmp1,ecx				;save these
	mov		cl,byte ptr lKey32[N+16]
	mov		ebp,edx
	mov		tmp3,ecx
	mov		esi,ecx
   else ;keySize eq 256
	mov		tmp0,ecx				;save copy on stack
	mov		cl,byte ptr lKey32[N+16]
	mov		tmp1,edx
	mov		dl,byte ptr lKey32[N+24]
	mov		tmp2,ecx
	mov		ebp,ecx
	mov		tmp3,edx
	mov		esi,edx
   endif
  else
   if keySize eq 128
	movzx	ebp,byte ptr lKey32[N]	;load esi/ebp with key bytes
	movzx	esi,byte ptr lKey32[N+8]
   elseif keySize eq 192
    movzx	esi,byte ptr lKey32[N]
	movzx	ebp,byte ptr lKey32[N+8]
	mov		tmp1,esi
    movzx	esi,byte ptr lKey32[N+16]
	mov		tmp3,esi
   else	;keySize eq 256
	movzx	ebp,byte ptr lKey32[N]	;load esi/ebp with key bytes
	movzx	esi,byte ptr lKey32[N+8]
	mov		tmp0,ebp
	mov		tmp1,esi
	movzx	ebp,byte ptr lKey32[N+16]
	movzx	esi,byte ptr lKey32[N+24]
	mov		tmp2,ebp
	mov		tmp3,esi
   endif
  endif
endm
;
;
DO_CALL_Pentium			=	0		;inline code, or use calls?
DO_CALL_PentiumPro		=	0

  irp cpuName,<Pentium,PentiumPro>
    if DO_CALL_&cpuName
	  irp XX,<0,1,2,3>
	    concat	<public ASM_ALIGN_>,%(XX),<_>,cpuName
	  endm
	endif
  endm

jmpRet	macro	cpuName
	 jmp reKeyDone_&cpuName			;comment this line to do full testing
endm	
;
; precompute first step in 32-bit chunks??  Nope -- only saves ~ 40 clocks
;
; Input:	edi = i
;			esi = byte to xor with s0[] output
;			ebp = byte to xor with s1[] output
;
subKey8x32Proc	macro	keySize,N,cpuName,s0,s1,s2,s3
  if DO_CALL_&cpuName
	align	4
LSK_OFFS	=	4
  else
LSK_OFFS	=	0
  endif
skProc_&keySize&_&N&_&cpuName:
	xor		ecx,ecx					;keep Pentium pairing properly aligned
	ld8		<a>,s0[edi],cpuName		;run through first 8x8 permutation

	xor		eax,esi					;xor with first key byte
	ld8		<b>,s0[edi+2],cpuName

	xor		ebx,esi
	ld8		<c>,s0[edi+4],cpuName

	xor		ecx,esi
	ld8		<d>,s0[edi+6],cpuName

	xor		edx,esi
	ld8		<a>,s1[eax],cpuName		;run through second 8x8

	xor		eax,ebp					;xor with second key byte
	ld8		<b>,s1[ebx],cpuName

	xor		ebx,ebp
	ld8		<c>,s1[ecx],cpuName

	xor		ecx,ebp
	ld8		<d>,s1[edx],cpuName
 ifnb <s2>
	xor		edx,ebp
	ld8		<a>,s2[eax],cpuName		;run through 3rd 8x8

	mov		esi,tmp1+4*DO_CALL_&cpuName
  if keySize gt 192
	mov		ebp,tmp0+4*DO_CALL_&cpuName
  endif
	xor		eax,esi					;xor with 3rd key byte
	ld8		<b>,s2[ebx],cpuName

	xor		ebx,esi
	ld8		<c>,s2[ecx],cpuName

	xor		ecx,esi
	ld8		<d>,s2[edx],cpuName

	xor		edx,esi
   ifnb <s3>
	ld8		<a>,s3[eax],cpuName		;run through 4th 8x8

	xor		eax,ebp					;xor with 4th key byte
	ld8		<b>,s3[ebx],cpuName

	xor		ebx,ebp
	ld8		<c>,s3[ecx],cpuName

	xor		ecx,ebp
	ld8		<d>,s3[edx],cpuName

	xor		edx,ebp	
   endif
	mov		eax,MDStab[4*eax+N*1024];do final 8x8 and MDS multiply lookup

	mov		esi,tmp3+4*DO_CALL_&cpuName	;reload old key bytes
   if keySize gt 192
	mov		ebp,tmp2+4*DO_CALL_&cpuName	;(for next time)
   endif
  else
	xor		edx,ebp	
	mov		eax,MDStab[4*eax+N*1024];do final 8x8 and MDS multiply lookup
  endif

concat <    mov     lSubkey[4*edi+N*SUBKEY_SIZE][>,%LSK_OFFS,<],eax>
	mov		eax,MDStab[4*ebx+N*1024]

concat <    mov     lSubkey[4*edi+N*SUBKEY_SIZE+8][>,%LSK_OFFS,<],eax>
	mov		eax,MDStab[4*ecx+N*1024]

concat <    mov     lSubkey[4*edi+N*SUBKEY_SIZE+16][>,%LSK_OFFS,<],eax>
	mov		eax,MDStab[4*edx+N*1024]

concat <    mov     lSubkey[4*edi+N*SUBKEY_SIZE+24][>,%LSK_OFFS,<],eax>
	xor		eax,eax

	sub		edi,8
	jae		skProc_&keySize&_&N&_&cpuName

  if DO_CALL_&cpuName
	ret	0
	db		((1 + (15-(($-skProc_&N&_&cpuName) AND 15))) AND 15) dup (0)
  endif
endm

skProc	macro	keySize,N,cpuName		;;__TRANSPARENT__
  if keySize eq 128
	subKey8x32Proc	keySize,N,cpuName,P_&N&2,P_&N&1
  elseif keySize eq 192
	subKey8x32Proc	keySize,N,cpuName,P_&N&3,P_&N&2,P_&N&1
  elseif keySize eq 256
	subKey8x32Proc	keySize,N,cpuName,P_&N&4,P_&N&3,P_&N&2,P_&N&1
  else
	Invalid_KeySize_Error;;
  endif
endm

skEvenOdd	macro	keySize,N,cpuName
  if N eq 0
	mov		edi,TOTAL_SUBKEYS-8		;do the even ones first (backwards)
  else
	add		edi,TOTAL_SUBKEYS-1
  endif
	skLdKey	keySize,N,cpuName
  if DO_CALL_&cpuName
	call	skProc_&keySize&_&N&_&cpuName
	add		edi,TOTAL_SUBKEYS+1		;go back for the odd ones
	skLdKey	keySize,N+4,cpuName
	call	skProc_&keySize&_&N&_&cpuName
  else
	skProc	keySize,N,cpuName		;instantiate the code inline
	test	edi,1					;and loop twice for even/odd subkeys
	jnz		short sk&keySize&_&N&_done_&cpuName
	  add	edi,TOTAL_SUBKEYS+1		;go back for the odd ones
	  skLdKey	keySize,N+4,cpuName
	  jmp	skProc_&keySize&_&N&_&cpuName
	  align	4
sk&keySize&_&N&_done_&cpuName:
  endif
endm

;
_S_	equ		<tmpSbox8[12]>			;use this to reference tmpSbox
;
; int reKey(keyInstance *keyPtr);	// build the key schedule
;
reKeyProc	macro	cpuName
reKey_Start_&cpuName:
  if DO_CALL_&cpuName
	db		1 dup (0)				;align
	irp		kSize,<256,192,128>
ASM_ALIGN_&kSize&_0_&cpuName:	skProc %kSize,0,cpuName
ASM_ALIGN_&kSize&_1_&cpuName:	skProc %kSize,1,cpuName
ASM_ALIGN_&kSize&_2_&cpuName:	skProc %kSize,2,cpuName
ASM_ALIGN_&kSize&_3_&cpuName:	skProc %kSize,3,cpuName
	endm
bigKeyCode_&cpuName = (ASM_ALIGN_128_0_&cpuName-ASM_ALIGN_256_0_&cpuName)
   endif
;
TwoFishReKey_&cpuName proc 
	pushad 
	mov		ebp,keyPtr-localSize2
	sub		esp,localSize2 

	xor		edi,edi	
	biasEBP

	mov		ecx,ks.keyLen			;should be 128, 192, or 256
	shr		ecx,6					;divide by 64
	ldCache	[esp],localSize2,cpuName
	ldCache	[ks.key32],%(fullSbox-key32),cpuName
;	jmpRet  cpuName    ;;  ??? to here (MMX: 160)(Pro:  160) ["Nothing"]

	;copy over key material, do the Reed-Solomon thing
	mov		kLen64,ecx				;store key length
rsLoop_&cpuName:
	mov		edx,ks.key32[8*edi+4]
	mov		lKey32[8*edi+4],edx		;build a local copy of key bytes
	call	RSrem					;process the first four bytes
	mov		eax,ks.key32[8*edi]		;get next two key material dwords
	mov		lKey32[8*edi],eax		;(local copy)
	inc		edi						;bump ptr
	xor		edx,eax
	call	RSrem					;now process the final four
	mov		SboxKey[4*ecx-4],edx	;store result in reverse order
	mov		ks.sboxKeys[4*ecx-4],edx
 if KEY_MODE and KM_ZERO	
  ifidn <cpuName>,<PentiumPro>
	lea		esi,[4*ecx-4]
	movzx	eax,dl					;expand Pentium Pro keys: dword --> four bytes
	movzx	ebx,dh
	mov		sboxK8[4*esi],eax
	shr		edx,16
	mov		sboxK8[4*esi+4],ebx
	movzx	eax,dh
	mov		sboxK8[4*esi+12],eax
	movzx	edx,dl
	mov		sboxK8[4*esi+8],edx
  endif
 endif
	dec		ecx
	jg		rsLoop_&cpuName

	mov		esi,skJmpTab_&cpuName[4*edi-4]
	; compute all the subkey s-box results
	xor		edi,edi					;edi = i in subKey loop
	xor		eax,eax
	xor		ebx,ebx
	xor		ecx,ecx
	xor		edx,edx
;	jmpRet  cpuName    ;;  487 to here (MMX: 451)(Pro:  315) ["RSrem"]
	jmp		esi

  irp kBits,<256,192,128>
concat <sk>,%(kBits),<_>,cpuName:
	skEvenOdd	%(kBits),0,cpuName
	skEvenOdd	%(kBits),1,cpuName
	skEvenOdd	%(kBits),2,cpuName
	skEvenOdd	%(kBits),3,cpuName
   if (kBits ne 128)
    jmp		sk8Done_&cpuName		;put 128-bit key last to fall through!
   endif
  endm
  ife DO_CALL_&cpuName				;show how big the 192/256 bit code is
bigKeyCode_&cpuName = (sk128_&cpuName-sk256_&cpuName)
  endif

sk8Done_&cpuName:
;	jmpRet  cpuName    ;; 1850 to here (MMX:1100)(Pro:  959) ["4skEvenOdd"]
	add		edi,TOTAL_SUBKEYS-1+6	;build in reverse order
	mov		ebp,keyPtr				;put final stuff here
	biasEBP

	; now run subkey s-box bytes through MDS and rotate/PHT/combine
subkeyLp_&cpuName:
	mov		eax,lSubkey[4*edi]
	mov		ebx,lSubkey[4*edi+4]

	mov		ecx,lSubkey[4*edi+SUBKEY_SIZE]
	mov		edx,lSubkey[4*edi+SUBKEY_SIZE+4]

	xor		eax,ecx
	mov		ecx,lSubkey[4*edi+SUBKEY_SIZE*2]

	xor		ebx,edx
	mov		edx,lSubkey[4*edi+SUBKEY_SIZE*2+4]

	xor		eax,ecx
	mov		ecx,lSubkey[4*edi+SUBKEY_SIZE*3]

	xor		ebx,edx
	mov		edx,lSubkey[4*edi+SUBKEY_SIZE*3+4]

	xor		eax,ecx
	xor		ebx,edx

	rol		ebx,8
	add		eax,ebx
	add		ebx,eax
	mov		ks.subKeys[4*edi  ],eax
	rol		ebx,9
	mov		ks.subKeys[4*edi+4],ebx

	sub		edi,2
	jae		subkeyLp_&cpuName
;	jmpRet  cpuName    ;; 2207 to here (MMX:1370)(Pro: 1182) ["subKey"]
 if (KEY_MODE and KM_ZERO) eq 0
	; now build the 8x32 S-boxes (including MDS matrix)
	lea		esi,tmpSbox+128
	mov		ecx,kLen64
	add		edi,2+3					;set edi == 3 (use 8-bit "offset")
	mov		edx,mdsJmpTab_&cpuName[4*ecx-4]
	mov		esi,pPtrTab[4*ecx-4]
	mov		reKeyJmpPtr,edx
	lea		ecx,SboxKey[4*ecx-4]	;point to first dword of key used
	mov		pPtr,esi
	mov		kPtr,ecx
SboxLp_&cpuName:
	; here with edi = byte number, esi = pointer into pTab "first" used entry
	;	ecx = kPtr
	xor		edx,edx
	mov		esi,[esi+4*edi]			;get ptr to first of q0/q1 to be used
	mov		dl,[ecx+edi]			;get the key byte
  ifdif <cpuName>,<PentiumPro>
    mov		dh,dl
	mov		eax,edx
	shl		edx,16
	mov		ecx,256-32
	or		edx,eax
  else
    mov		eax,1010101h
	mul		edx
	mov		ecx,256-32
	mov		edx,eax
  endif
p1stLp_&cpuName:					;do the first level of perm8x8/xor
   irp _K_,<0,8,16,24>
	pXor8	tmpSbox[ecx],[esi+ecx],edx,%(_K_)
   endm
	sub		ecx,32
	jae		p1stLp_&cpuName
	xor		ebx,ebx					;clear upper bits
	jmp		reKeyJmpPtr				;go handle the remaining levels
mds256_&cpuName:
	ld8		<b>,<byte ptr SboxKey[edi+8]>,cpuName
	mov		esi,pTab[4*edi+32]
	call	permXor_&cpuName
mds192_&cpuName:
	ld8		<b>,<byte ptr SboxKey[edi+4]>,cpuName
	mov		esi,pTab[4*edi+16]
	call	permXor_&cpuName
mds128_&cpuName:
 if KEY_MODE and (KM_FULL or KM_PART or KM_COMPILE)
	ld8		<b>,<byte ptr SboxKey[edi]>,cpuName
	mov		esi,pTab[4*edi]
	call	permXor_&cpuName		;compute final stage of 8-bit S-box
 endif
 if KEY_MODE and (KM_FULL or KM_COMPILE);---------;now expand from 8-bit to 32 via MDStab
	mov		tmp0,ebp
	lea		ebp,ks.fullSbox
	mov		tmp1,edi
	mov		eax,mdsOffsTab[4*edi]
	shl		edi,10
	add		ebp,eax					;ebp --> base of output table
	xor		eax,eax					;clear upper bits of eax
	mov		al,tmpSbox8[256-1]
	xor		ebx,ebx
	mov		bl,tmpSbox8[256-1-4]
	add		edi,offset MDStab		;base of this table in MDStab
	mov		esi,256-8
mds64Lp_&cpuName:
  ifdif <cpuName>,<PentiumPro>
	mov		ecx,[ebp+8*esi]			;force cache line load for writes
	mov		edx,[ebp+8*esi+32]		;(no need for Pro)
  endif
  irp NN,<3,2,1,0>
	mov		ecx,[edi+4*eax]			;get the MDS table entry
	mov		edx,[edi+4*ebx]
   if NN 
	ld8		<a>,tmpSbox8[esi+NN-1+4],cpuName	;load from different cache banks
	ld8		<b>,tmpSbox8[esi+NN-1],cpuName
   else		
	ld8		<a>,tmpSbox8[esi-1],cpuName			;get set for next time
	ld8		<b>,tmpSbox8[esi-1-4],cpuName
  endif
	mov		[ebp+8*esi+8*NN+8*4],ecx;store it in the Sbox under construction
	mov		[ebp+8*esi+8*NN],edx
  endm
	sub		esi,8
	jns		mds64Lp_&cpuName

	mov		edi,tmp1				;restore regs
	mov		ebp,tmp0
 elseif  KEY_MODE and (KM_PART or KM_MIN)	;-------;just copy the 8-bit Sbox
	mov		ecx,x8Tab[edi*4]
	mov		esi,256-64
	lea		ecx,ks.fullSbox[ecx]
pk_CopyLp_&cpuName:
  ifdif <cpuName>,<PentiumPro>		;force load cache line before writing
	mov		eax,[ecx+esi]
	mov		ebx,[ecx+esi+36]
  endif
  irp NN,<7,6,5,4,3,2,1,0>
	mov		eax,tmpSbox[esi+NN*8]
	mov		ebx,tmpSbox[esi+NN*8+4]
	mov		[ecx+esi+NN*8],eax
	mov		[ecx+esi+NN*8+4],ebx
  endm
	sub		esi,64
	jae		pk_CopyLp_&cpuName
 endif	
	mov		ecx,kPtr				;get ready for next time
	mov		esi,pPtr
	dec		edi						;decrement byte number
	jns		SboxLp_&cpuName			;keep going  until all bytes processed
;	jmpRet  cpuName    ;;10000 to here (MMX:6410)(Pro: 7711) ["All"]
  if KEY_MODE and KM_COMPILE		;copy the code over and "compile" it
	cmp		ks.keySig,VALID_SIG		;must be correct C model as well
	jnz		badKeyLen_&cpuName		;hang if not
	cld	
	lea		esi,cipherProcStart_&cpuName
	lea		ecx,cipherProcEnd_&cpuName+63
	mov		edx,esi
	lea		edi,ks.cipherProcCode[63]
	and		esi,NOT 63				;put on 64 byte boundaries
	and		ecx,NOT 63
	and		edi,NOT 63				;keep on paragraph boundaries
	sub		ecx,esi
	sub		edx,esi					;edx=how much we moved down
	add		edx,edi					;edx=where cipherProcStart is in cipherProcCode
	cmp		ecx,ks.codeSize			;is there room?
	ja		badKeyLen_&cpuName		;hang if not	
	shr		ecx,2					;do it one dword at a time
	sub		edx,offset cipherProcStart_&cpuName	;edx=value to add to translate offsets
  ifdif <cpuName>,<PentiumPro>
cpyLp:  
	mov		eax,[edi]				;load cache lines to speed things up
	mov		ebx,[edi+36]
   irp QQ,<0,8,16,24,32,40,48,56>
	mov		eax,[esi+QQ]			;move 8 bytes at a time
	mov		ebx,[esi+QQ+4]
	mov		[edi+QQ],eax
	mov		[edi+QQ+4],ebx
   endm
    add		esi,64
    add		edi,64
	sub		ecx,16
	jae		cpyLp
  else
	rep		movsd					;copy over the code
  endif
	; now cipherProcStart is at edx!  Patch in the 
	lea		eax,TwoFishEncrypt_&cpuName[edx]
	lea		ebx,TwoFishDecrypt_&cpuName[edx]
	mov		ks.encryptFuncPtr,eax	;set up the function pointers
	mov		ks.decryptFuncPtr,ebx
	xor		ecx,ecx

	mov		eax,ks.subKeys[INPUT_WHITEN]
	mov		ebx,ks.subKeys[INPUT_WHITEN+4]
	mov		dword ptr Enc_CBC_SK_0_&cpuName[edx-4],eax
	mov		dword ptr Enc_CBC_SK_1_&cpuName[edx-4],ebx
	mov		dword ptr Dec_CBC_SK_0_&cpuName[edx-4],eax
	mov		dword ptr Dec_CBC_SK_1_&cpuName[edx-4],ebx
	mov		eax,ks.subKeys[INPUT_WHITEN+8]
	mov		ebx,ks.subKeys[INPUT_WHITEN+12]
	mov		dword ptr Enc_CBC_SK_2_&cpuName[edx-4],eax
	mov		dword ptr Enc_CBC_SK_3_&cpuName[edx-4],ebx
	mov		dword ptr Dec_CBC_SK_2_&cpuName[edx-4],eax
	mov		dword ptr Dec_CBC_SK_3_&cpuName[edx-4],ebx
patchLp_&cpuName:
	mov		eax,PatchList_Enc_&cpuName[4*ecx]	;now patch in the subkeys
	mov		ebx,PatchList_Dec_&cpuName[4*ecx]
	mov		edi,ks.subKeys[4*ecx];
	inc		ecx
	mov		[eax+edx],edi
	mov		[ebx+edx],edi
	cmp		ecx,TOTAL_SUBKEYS
	jb		patchLp_&cpuName
  endif
endif ;!KM_ZERO
reKeyDone_&cpuName:
	add		esp,localSize2
	popad
	mov		eax,1					;success
	ret
;
; Input:	tmpSbox permutation (at _S_, due to call return address)
;			esi    -->	q0 or q1, permutation through which to pass tmpSbox
;			ebx	    =	key byte to xor into data after q0/q1
; Output:	tmpSbox updated
;			edi,ebp unmodified
permXor_&cpuName:
  ifdif <cpuName>,<PentiumPro>
	push	edi						;save edi on stack so we don't modify it
	mov		bh,bl

	push	ebp
	mov		ebp,ebx

	shl		ebx,16
	xor		eax,eax

	mov		edi,256-8
	mov		al,_S_[256-1]

	or		ebp,ebx					;ebp=four bytes replicated from original ebx
	xor		ebx,ebx

	mov		bl,_S_[256-1-4]
pxLoop_Pentium:
  irp NN,<0>
	mov		ch,[esi+eax]
	mov		al,_S_[edi+6+NN]

	mov		dh,[esi+ebx]
	mov		bl,_S_[edi+2+NN]

	mov		cl,[esi+eax]
	mov		al,_S_[edi+5+NN]

	shl		ecx,16
	mov		dl,[esi+ebx]

	shl		edx,16
	mov		bl,_S_[edi+1+NN]

	mov		ch,[esi+eax]
	mov		al,_S_[edi+4+NN]

	mov		dh,[esi+ebx]
	mov		bl,_S_[edi+NN]

	mov		cl,[esi+eax]
	mov		al,_S_[edi-1+NN]

	mov		dl,[esi+ebx]
	mov		bl,_S_[edi-5+NN]

	xor		ecx,ebp
	xor		edx,ebp

	mov		dword ptr _S_[edi+4+NN],ecx
	mov		dword ptr _S_[edi+NN],edx
  endm
	sub		edi,8
	jae		pxLoop_Pentium
  else
    push	edi
	push	ebp
	mov		ebp,ebx
	mov		edi,256-8
	shl		ebp,8
	or		ebp,ebx
	mov		ebx,ebp
	shl		ebp,16
	mov		ecx,dword ptr _S_[edi+4];pick up next four bytes of permutation
	or		ebp,ebx					;ebp=four bytes replicated from original ebx
	mov		eax,ecx
	movzx	edx,ch
pxLoop_PentiumPro:
  irp ZZ,<4,0>
	movzx	ecx,cl

	shr		eax,16
	movzx	edx,byte ptr [esi+edx]

	shl		edx,8
	movzx	ecx,byte ptr [esi+ecx]
	movzx	ebx,ah

	movzx	ebx,byte ptr [esi+ebx]
	movzx	eax,al
	xor		ecx,ebp

	shl		ebx,24
	movzx	eax,byte ptr [esi+eax]
	xor		edx,ecx

	shl		eax,16
	xor		ebx,edx
	mov		ecx,dword ptr _S_[edi+ZZ-4]	;get ready for next loop

	xor		ebx,eax
	mov		eax,ecx
	movzx	edx,ch

	mov		dword ptr _S_[edi+ZZ],ebx
  endm
	sub		edi,8
	jae		pxLoop_PentiumPro
  endif
	pop		ebp
	pop		edi
	ret
;
badKeyLen_&cpuName:	; will only come here if there is an invalid keyLen parameter
int 3
	add		esp,localSize2
	popad
	xor		eax,eax
	ret
  if (KEY_MODE and KM_ZERO) eq 0
					dd	badKeyLen_&cpuName
mdsJmpTab_&cpuName	dd	badKeyLen_&cpuName
					dd	mds128_&cpuName,mds192_&cpuName,mds256_&cpuName
  endif
skJmpTab_&cpuName	dd	badKeyLen_&cpuName
					dd	sk128_&cpuName,sk192_&cpuName,sk256_&cpuName

reKeyCode_&cpuName = ($-reKey_Start_&cpuName)+reKeySharedSize
	irp	cby,<%(reKeyCode_&cpuName)>
	  %out	--- ReKey   assembly code size == cby bytes (cpuName)
	endm
	irp	cby,<%(bigKeyCode_&cpuName)>
	   %out	--- Big key assembly code size == cby bytes (cpuName)
    endm
	irp	cby,<%(reKeyCode_&cpuName-bigKeyCode_&cpuName)>
	   %out	--- 128 key assembly code size == cby bytes (cpuName)
    endm
	irp cby,<%($-asmStart_&cpuName+reKeySharedSize)>
	   %out --- Total assembly code size   == cby bytes (cpuName)
	   %out
	endm

TwoFishReKey_&cpuName endp
endm	;reKeyProc
;
;__MACRO_DEF_DONE__		;sign to LST2ASM that macro definitions are done
;
;
;-------------------- Pentium (and 486) optimized ------------- 
;
asmStart_Pentium:
cipherProc	Pentium 
reKeyProc	Pentium
asmEnd_Pentium:
;
;----------------- Pentium Pro/Pentium II optimized ------------ 
;
asmStart_PentiumPro:
cipherProc	PentiumPro 
reKeyProc	PentiumPro
asmEnd_PentiumPro:
;
;----------------- Select which routines to use ---------------
;
; useAsm:	bit 0		--> enable encryption in ASM
;			bit	1		--> enable decryption in ASM
;			bit 2		--> enable reKey in ASM
;		If any other bits are set (e.g., useAsm >= 8),
;		the low three bits get discarded here (SHR), and
;		the remaining value is used as a pseudo-return
;		value from get_cpu_type, to allow command-line
;		override of the cpu type:
;			useAsm=8..47--> force Pentium    code
;			useASM > 47	--> force PentiumPro code
;
	extrn	get_cpu_type:near
	extrn	useAsm:byte
;
	public	TwoFishEncrypt_Pentium,TwoFishDecrypt_Pentium,TwoFishReKey_Pentium
	public	TwoFishEncrypt_PentiumPro,TwoFishDecrypt_PentiumPro,TwoFishReKey_PentiumPro
	public	TwofishAsmCodeSize

setProcPtrs	proc
	pushad
	; set default (Pentium) addresses
	mov			blockEncrypt_86,offset TwoFishEncrypt_Pentium
	mov			blockDecrypt_86,offset TwoFishDecrypt_Pentium
	mov			reKey_86	   ,offset TwoFishReKey_Pentium
	
	call		get_cpu_type
	xor			al,5
	iff nz
	  mov		al,1
	endi

	test		useAsm,8		;command line override of CPU type?
	iff nz
	  xor		al,1
	endi

	or			al,al
	iff nz
	  mov		blockEncrypt_86,offset TwoFishEncrypt_PentiumPro
	  mov		blockDecrypt_86,offset TwoFishDecrypt_PentiumPro
	  mov		reKey_86	   ,offset TwoFishReKey_PentiumPro
	endi
	popad
	ret
setProcPtrs endp

E_SelectCPU	proc				;only come here once
	call		setProcPtrs
	jmp			blockEncrypt_86	;use the ptr we just set up
E_SelectCPU	endp
;
D_SelectCPU	proc
	call		setProcPtrs
	jmp			blockDecrypt_86
D_SelectCPU	endp

R_SelectCPU	proc
	call		setProcPtrs
	jmp			reKey_86
R_SelectCPU	endp

; code size functions
TwofishAsmCodeSize	proc
	call	setProcPtrs
	mov		eax,offset asmEnd_Pentium-asmStart_Pentium
	cmp		blockEncrypt_86,offset TwoFishEncrypt_PentiumPro
	iff z
	  mov	eax,offset asmEnd_PentiumPro-asmStart_PentiumPro
	endi
	add		eax,reKeySharedSize
	ret
TwofishAsmCodeSize	endp

	end
