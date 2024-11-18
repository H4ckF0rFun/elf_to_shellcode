	.text
	.align	4
	.globl	x_trampo
	.type	x_trampo,@function
x_trampo:
	mov 0x4(%esp),%eax
	mov 0x8(%esp),%esp

	xor %ebx,%ebx
	xor %ecx,%ecx
	xor %edx,%edx
	
	xor %esi,%esi
	xor %edi,%edi
	xor %ebp,%ebp
	
	push %eax
	xor %eax,%eax
	ret

