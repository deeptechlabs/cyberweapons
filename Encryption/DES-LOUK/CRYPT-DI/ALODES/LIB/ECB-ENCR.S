	.file	"ecb-encrypt.c"
gcc2_compiled.:
.globl _des_using_inlining
.data
	.align 2
_des_using_inlining:
	.long 1
.text
	.align 2
.globl _des_ecb_encrypt
_des_ecb_encrypt:
	pushl %ebp
	movl %esp,%ebp
	subl $48,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%edx
	movl $_des_spe_table,%ebx
	movl 20(%ebp),%esi
	testl $256,%esi
	jne L2
	testl $1024,%esi
	je L3
	leal -8(%ebp),%eax
	pushl %eax
	pushl %edx
	call _des_do_iperm_rev
	addl $8,%esp
	jmp L5
	.align 2,0x90
L3:
	leal -8(%ebp),%eax
	pushl %eax
	pushl %edx
	call _des_do_iperm
	addl $8,%esp
	jmp L5
	.align 2,0x90
L2:
	movl 20(%ebp),%edi
	testl $1024,%edi
	je L6
	leal -8(%ebp),%eax
	pushl %eax
	pushl %edx
	call _des_bitrev
	addl $8,%esp
	jmp L5
	.align 2,0x90
L6:
	movl (%edx),%esi
	movl %esi,-8(%ebp)
	movl 4(%edx),%edx
	movl %edx,-4(%ebp)
L5:
	movl 20(%ebp),%edi
	andl $1,%edi
	movl %edi,-44(%ebp)
	xorb $1,-44(%ebp)
	leal -16(%ebp),%eax
	pushl %eax
	leal -8(%ebp),%eax
	pushl %eax
	call _des_expand
	leal -24(%ebp),%eax
	pushl %eax
	leal -4(%ebp),%eax
	pushl %eax
	call _des_expand
	movl -24(%ebp),%ecx
	movl -20(%ebp),%edx
	movl $0,-48(%ebp)
	addl $16,%esp
	.align 2,0x90
L13:
	movl %ecx,-40(%ebp)
	movl %edx,-36(%ebp)
	cmpl $0,-44(%ebp)
	je L11
	movl -48(%ebp),%eax
	jmp L12
	.align 2,0x90
L11:
	movl $15,%eax
	subl -48(%ebp),%eax
L12:
	movl 16(%ebp),%esi
	leal (%esi,%eax,8),%eax
	movl %ecx,-32(%ebp)
	movl %edx,-28(%ebp)
	movl (%eax),%edi
	xorl %edi,-32(%ebp)
	movl 4(%eax),%eax
	xorl %eax,-28(%ebp)
	movzbl -32(%ebp),%edx
	movzbl -31(%ebp),%eax
	movl (%ebx,%edx,4),%ecx
	xorl 512(%ebx,%eax,4),%ecx
	movl 256(%ebx,%edx,4),%edx
	xorl 768(%ebx,%eax,4),%edx
	movzbl -30(%ebp),%eax
	xorl 1024(%ebx,%eax,4),%ecx
	xorl 1280(%ebx,%eax,4),%edx
	movzbl -29(%ebp),%eax
	xorl 1536(%ebx,%eax,4),%ecx
	xorl 1792(%ebx,%eax,4),%edx
	movzbl -28(%ebp),%eax
	xorl 2048(%ebx,%eax,4),%ecx
	xorl 2304(%ebx,%eax,4),%edx
	movzbl -27(%ebp),%eax
	xorl 2560(%ebx,%eax,4),%ecx
	xorl 2816(%ebx,%eax,4),%edx
	movzbl -26(%ebp),%eax
	xorl 3072(%ebx,%eax,4),%ecx
	xorl 3328(%ebx,%eax,4),%edx
	movzbl -25(%ebp),%eax
	xorl 3584(%ebx,%eax,4),%ecx
	xorl 3840(%ebx,%eax,4),%edx
	xorl -16(%ebp),%ecx
	xorl -12(%ebp),%edx
	movl -40(%ebp),%esi
	movl %esi,-16(%ebp)
	movl -36(%ebp),%edi
	movl %edi,-12(%ebp)
	incl -48(%ebp)
	cmpl $15,-48(%ebp)
	jle L13
	movl %ecx,-24(%ebp)
	movl %edx,-20(%ebp)
	leal -24(%ebp),%eax
	pushl %eax
	call _des_unexpand
	movl %eax,-8(%ebp)
	leal -16(%ebp),%eax
	pushl %eax
	call _des_unexpand
	movl %eax,-4(%ebp)
	addl $8,%esp
	movl 20(%ebp),%esi
	testl $512,%esi
	jne L14
	testl $1024,%esi
	je L15
	pushl 12(%ebp)
	leal -8(%ebp),%eax
	pushl %eax
	call _des_do_fperm_rev
	jmp L17
	.align 2,0x90
L15:
	pushl 12(%ebp)
	leal -8(%ebp),%eax
	pushl %eax
	call _des_do_fperm
	jmp L17
	.align 2,0x90
L14:
	movl 20(%ebp),%edi
	testl $1024,%edi
	je L18
	pushl 12(%ebp)
	leal -8(%ebp),%eax
	pushl %eax
	call _des_bitrev
	jmp L17
	.align 2,0x90
L18:
	movl -8(%ebp),%edi
	movl 12(%ebp),%esi
	movl %edi,(%esi)
	movl -4(%ebp),%edi
	movl %edi,4(%esi)
L17:
	leal -60(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret
