	.file	1 "longmult.c"
	.set	nobopt
	.option pic2

 # GNU C 2.5.8 [AL 1.1, MM 40] SGI running IRIX 5.0 compiled by GNU C

 # Cc1 defaults:
 # -mabicalls

 # Cc1 arguments (-G value = 8, Cpu = default, ISA = 1):
 # -quiet -dumpbase -O4 -o

gcc2_compiled.:
__gnu_compiled_c:
	.text
	.align	2
	.globl	LMULT

	.loc	1 92
LM1:
	.ent	LMULT
LMULT:
	.frame	$sp,24,$31		# vars= 8, regs= 1/0, args= 0, extra= 8
	.mask	0x10000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	subu	$sp,$sp,24
	.cprestore 0
	sw	$28,16($sp)
	move	$10,$0
	.set	noreorder
	.set	nomacro
	blez	$7,$L3
	move	$8,$0
	.set	macro
	.set	reorder

	move	$9,$4
$L5:
	lw	$11,0($6)
 #APP
	multu $5,$11
	mflo $3
	mfhi $4
 #NO_APP
	addu	$3,$3,$8
	sltu	$2,$3,$8
	addu	$4,$4,$2
	lw	$2,0($9)
	addu	$6,$6,4
	addu	$10,$10,1
	addu	$2,$3,$2
	sw	$2,0($9)
	sltu	$2,$2,$3
	addu	$8,$4,$2
	slt	$2,$10,$7
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L5
	addu	$9,$9,4
	.set	macro
	.set	reorder

$L3:
	move	$2,$8
	addu	$sp,$sp,24
	j	$31
	.end	LMULT
	.align	2
	.globl	BUILDDIAG

	.loc	1 135
LM2:
	.ent	BUILDDIAG
BUILDDIAG:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, extra= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	move	$3,$0
$L7:
	lw	$8,0($5)
	lw	$7,0($5)
 #APP
	multu $8,$7
	mflo $8
	mfhi $7
 #NO_APP
	sw	$8,0($4)
	sw	$7,4($4)
	addu	$4,$4,8
	addu	$3,$3,1
	slt	$2,$3,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L7
	addu	$5,$5,4
	.set	macro
	.set	reorder

	j	$31
	.end	BUILDDIAG
	.align	2
	.globl	SQUAREINNERLOOP

	.loc	1 165
LM3:
	.ent	SQUAREINNERLOOP
SQUAREINNERLOOP:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, extra= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	reorder
	move	$11,$5
	lw	$12,16($sp)
	move	$8,$4
	move	$9,$0
	sll	$2,$7,2
	addu	$10,$2,$6
	addu	$6,$8,4
$L11:
	lw	$13,0($10)
 #APP
	multu $11,$13
	mflo $3
	mfhi $5
 #NO_APP
	addu	$10,$10,4
	addu	$7,$7,1
	addu	$2,$3,$3
	lw	$4,0($8)
	sltu	$3,$2,$3
	addu	$3,$3,$9
	addu	$4,$2,$4
	sltu	$2,$4,$2
	addu	$9,$3,$2
	sw	$4,0($8)
	addu	$8,$8,4
	lw	$3,0($6)
	addu	$2,$5,$5
	sltu	$5,$2,$5
	addu	$3,$2,$3
	sltu	$2,$3,$2
	addu	$5,$5,$2
	addu	$2,$3,$9
	sltu	$3,$2,$3
	addu	$9,$5,$3
	sw	$2,0($6)
	slt	$2,$7,$12
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L11
	addu	$6,$6,4
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$9,$0,$L15
	addu	$8,$8,4
	.set	macro
	.set	reorder

	sll	$4,$12,1
	slt	$2,$7,$4
	beq	$2,$0,$L15
$L16:
	lw	$3,0($8)
	addu	$7,$7,1
	addu	$2,$9,$3
	sltu	$9,$2,$3
	sw	$2,0($8)
	.set	noreorder
	.set	nomacro
	beq	$9,$0,$L15
	addu	$8,$8,4
	.set	macro
	.set	reorder

	slt	$2,$7,$4
	bne	$2,$0,$L16
$L15:
	j	$31
	.end	SQUAREINNERLOOP
