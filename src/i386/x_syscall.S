.text
.align	4
.globl	x_syscall
x_syscall:

	push    %ebp
	push    %edi
	push    %esi
	push    %ebx

	mov     0x2c(%esp), %ebp
	mov     0x28(%esp), %edi
	mov     0x24(%esp), %esi
	mov     0x20(%esp), %edx
	mov     0x1C(%esp), %ecx
	mov     0x18(%esp), %ebx
	mov     0x14(%esp), %eax

	int $0x80

	pop     %ebx
	pop     %esi
	pop     %edi
	pop     %ebp
	
	ret

