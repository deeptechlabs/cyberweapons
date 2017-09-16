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
	movl 20(%ebp),%eax
	movl 12(%ebp),%edi
	xorl %ebx,%ebx
	cmpl %eax,%ebx
	jge L11
	movl 8(%ebp),%ecx
	movl 16(%ebp),%esi
	leal (%ecx,%eax,4),%eax
	movl %eax,-4(%ebp)
	.align 2,0x90
L13:
	movl %edi,%eax
#APP
	mull (%esi)
#NO_APP
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
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%ecx
	movl 12(%ebp),%esi
	movl 16(%ebp),%edx
	leal 0(,%edx,4),%eax
	leal (%esi,%eax),%ebx
	.align 2,0x90
L23:
	movl (%esi),%eax
#APP
	mull %eax
#NO_APP
	movl %eax,(%ecx)
	movl %edx,4(%ecx)
	addl $8,%ecx
	addl $4,%esi
	cmpl %ebx,%esi
	jl L23
	leal -8(%ebp),%esp
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
	leal 0(,%edx,4),%eax
	addl 16(%ebp),%eax
	movl %eax,-8(%ebp)
	.align 2,0x90
L41:
	movl 12(%ebp),%eax
	movl -8(%ebp),%edx
#APP
	mull (%edx)
#NO_APP
	movl %edx,%edi
	leal 0(,%eax,2),%edx
	cmpl %eax,%edx
	setb %al
	andl $255,%eax
	movl %edx,-12(%ebp)
	movl %edx,%ecx
	addl (%esi),%ecx
	addl %eax,%ebx
	cmpl %edx,%ecx
	jae L44
	incl %ebx
L44:
	movl %ecx,(%esi)
	leal 0(,%edi,2),%edx
	cmpl %edi,%edx
	setb %al
	andl $255,%eax
	movl %edx,-12(%ebp)
	movl %edx,%ecx
	addl 4(%esi),%ecx
	cmpl %edx,%ecx
	jae L45
	incl %eax
L45:
	movl %ecx,-12(%ebp)
	addl %ebx,%ecx
	movl %eax,%ebx
	cmpl %ecx,-12(%ebp)
	jbe L46
	incl %ebx
L46:
	movl %ecx,4(%esi)
	addl $4,%esi
	addl $4,-8(%ebp)
	incl -4(%ebp)
	movl 24(%ebp),%edx
	cmpl %edx,-4(%ebp)
	jl L41
	addl $4,%esi
	testl %ebx,%ebx
	je L49
	leal 0(,%edx,2),%ecx
	.align 2,0x90
L52:
	cmpl %ecx,-4(%ebp)
	jge L49
	movl %ebx,%edx
	addl (%esi),%edx
	cmpl %edx,(%esi)
	seta %al
	movzbl %al,%ebx
	movl %edx,(%esi)
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

