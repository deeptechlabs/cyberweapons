gcc2_compiled.:
___gnu_compiled_c:
.text
	.align 4
	.global _LMULT
	.proc	017
_LMULT:
	!#PROLOGUE# 0
	save %sp,-104,%sp
	!#PROLOGUE# 1
	mov 0,%i5
	cmp %i5,%i3
	bge L3
	mov 0,%g4
	mov %i0,%i4
L5:
	ld [%i2],%o7
	
	mov	%o7, %y
	andcc	%g0,%g0,%g1
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%i1,%g1;	mulscc	%g1,%i1,%g1;
	mulscc	%g1,%g0,%g1
	tst	%i1
	bge	1f
	nop
	add	%g1, %o7, %g1
1:
	rd	%y,%g3
	andcc	%g1, %g1, %i0
	add %g3,%i5,%g3
	cmp %g3,%i5
	addx %g0,%i0,%i0
	add %i2,4,%i2
	ld [%i4],%g2
	add %g4,1,%g4
	add %g3,%g2,%g2
	st %g2,[%i4]
	cmp %g2,%g3
	addx %g0,%i0,%i5
	cmp %g4,%i3
	bl L5
	add %i4,4,%i4
L3:
	ret
	restore %g0,%i5,%o0
	.align 4
	.global _BUILDDIAG
	.proc	020
_BUILDDIAG:
	!#PROLOGUE# 0
	!#PROLOGUE# 1
	mov 0,%g3
	sll %o2,2,%o2
L7:
	ld [%g3+%o1],%o4
	ld [%g3+%o1],%o3
	
	mov	%o3, %y
	andcc	%g0,%g0,%g1
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%o4,%g1;	mulscc	%g1,%o4,%g1;
	mulscc	%g1,%g0,%g1
	tst	%o4
	bge	1f
	nop
	add	%g1, %o3, %g1
1:
	rd	%y,%o3
	andcc	%g1, %g1, %o4
	st %o4,[%o0+4]
	st %o3,[%o0]
	add %g3,4,%g3
	cmp %g3,%o2
	bl L7
	add %o0,8,%o0
	retl
	nop
	.align 4
	.global _SQUAREINNERLOOP
	.proc	020
_SQUAREINNERLOOP:
	!#PROLOGUE# 0
	save %sp,-104,%sp
	!#PROLOGUE# 1
	mov %i1,%o7
	mov %i4,%o0
	mov %i0,%i5
	mov 0,%g4
	mov %i3,%i4
	sll %i4,2,%g2
	add %g2,%i2,%i3
	add %i5,4,%i2
L11:
	ld [%i3],%o1
	
	mov	%o1, %y
	andcc	%g0,%g0,%g1
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%o7,%g1;	mulscc	%g1,%o7,%g1;
	mulscc	%g1,%g0,%g1
	tst	%o7
	bge	1f
	nop
	add	%g1, %o1, %g1
1:
	rd	%y,%g3
	andcc	%g1, %g1, %i1
	add %g3,%g3,%i0
	cmp %i0,%g3
	add %i3,4,%i3
	add %i4,1,%i4
	ld [%i5],%g2
	addx %g0,%g4,%g3
	add %i0,%g2,%g2
	cmp %g2,%i0
	addx %g0,%g3,%g4
	st %g2,[%i5]
	add %i1,%i1,%g3
	cmp %g3,%i1
	add %i5,4,%i5
	ld [%i2],%g2
	addx %g0,0,%i0
	add %g3,%g2,%g2
	cmp %g2,%g3
	addx %g0,%i0,%i0
	add %g2,%g4,%g3
	cmp %g3,%g2
	addx %g0,%i0,%g4
	st %g3,[%i2]
	cmp %i4,%o0
	bl L11
	add %i2,4,%i2
	cmp %g4,0
	be L15
	add %i5,4,%i5
	sll %o0,1,%i0
	cmp %i4,%i0
	bge L15
	nop
	ld [%i5],%g2
L17:
	add %i4,1,%i4
	add %g4,%g2,%g3
	cmp %g3,%g2
	addx %g0,0,%g4
	st %g3,[%i5]
	cmp %g4,0
	be L15
	add %i5,4,%i5
	cmp %i4,%i0
	bl,a L17
	ld [%i5],%g2
L15:
	ret
	restore
