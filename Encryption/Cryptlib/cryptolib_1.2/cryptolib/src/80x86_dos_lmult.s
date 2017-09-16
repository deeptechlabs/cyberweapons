	.file	"longmult.c"
gcc2_compiled.:
___gnu_compiled_c:
.text
	.align 2
.globl _LMULT
_LMULT:
	pushl %ebp
	movl %esp,%ebp
	subl $4,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 20(%ebp),%edx
	movl 12(%ebp),%edi
	xorl %ebx,%ebx
	cmpl %edx,%ebx
	jge L11
	movl 8(%ebp),%ecx
	movl 16(%ebp),%esi
	leal (%ecx,%edx,4),%edx
	movl %edx,-4(%ebp)
	.align 2,0x90
L13:
	movl %edi,%eax
/APP
	mull (%esi)
/NO_APP
	addl %ebx,%eax
	cmpl %ebx,%eax
	jae L14
	incl %edx
L14:
	addl %eax,(%ecx)
	movl %edx,%ebx
	cmpl %eax,(%ecx)
	jae L12
	incl %ebx
L12:
	addl $4,%ecx
	addl $4,%esi
	cmpl %ecx,-4(%ebp)
	jg L13
L11:
	movl %ebx,%eax
	leal -16(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
	.align 2
.globl _BUILDDIAG
_BUILDDIAG:
	pushl %ebp
	movl %esp,%ebp
	subl $4,%esp
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%esi
	movl 12(%ebp),%ecx
	movl 16(%ebp),%edx
	sall $2,%edx
	movl %edx,%ebx
	addl %ecx,%ebx
	.align 2,0x90
L23:
	movl (%ecx),%eax
/APP
	mull %eax
/NO_APP
	movl %eax,(%esi)
	movl %edx,4(%esi)
	addl $8,%esi
	addl $4,%ecx
	cmpl %ebx,%ecx
	jl L23
	leal -12(%ebp),%esp
	popl %ebx
	popl %esi
	leave
	ret
	.align 2
.globl _SQUAREINNERLOOP
_SQUAREINNERLOOP:
	pushl %ebp
	movl %esp,%ebp
	subl $12,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%esi
	xorl %ebx,%ebx
	movl 20(%ebp),%edx
	movl %edx,-4(%ebp)
	sall $2,%edx
	movl %edx,-12(%ebp)
	addl 16(%ebp),%edx
	movl %edx,-8(%ebp)
	.align 2,0x90
L41:
	movl 12(%ebp),%eax
	movl -8(%ebp),%edx
/APP
	mull (%edx)
/NO_APP
	movl %edx,%edi
	leal 0(,%eax,2),%ecx
	cmpl %eax,%ecx
	setb %dl
	movzbl %dl,%edx
	movl %edx,-12(%ebp)
	movl %ecx,%eax
	addl (%esi),%eax
	addl %edx,%ebx
	cmpl %ecx,%eax
	jae L44
	incl %ebx
L44:
	movl %eax,(%esi)
	leal 0(,%edi,2),%ecx
	cmpl %edi,%ecx
	setb %dl
	movzbl %dl,%edx
	movl %edx,-12(%ebp)
	movl %ecx,%eax
	addl 4(%esi),%eax
	cmpl %ecx,%eax
	jae L45
	incl -12(%ebp)
L45:
	movl %eax,%ecx
	leal (%ebx,%ecx),%eax
	movl -12(%ebp),%ebx
	cmpl %ecx,%eax
	jae L46
	incl %ebx
L46:
	movl %eax,4(%esi)
	addl $4,%esi
	addl $4,-8(%ebp)
	incl -4(%ebp)
	movl 24(%ebp),%edx
	cmpl %edx,-4(%ebp)
	jl L41
	addl $4,%esi
	testl %ebx,%ebx
	je L49
	leal 0(,%edx,2),%eax
	.align 2,0x90
L52:
	cmpl %eax,-4(%ebp)
	jge L49
	movl %ebx,%ecx
	addl (%esi),%ecx
	cmpl %ecx,(%esi)
	seta %dl
	movzbl %dl,%ebx
	movl %ecx,(%esi)
	addl $4,%esi
	incl -4(%ebp)
	testl %ebx,%ebx
	jne L52
L49:
	leal -24(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
