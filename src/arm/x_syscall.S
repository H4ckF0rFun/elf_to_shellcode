.text
.align	4
.globl	x_syscall
x_syscall:
	mov 	%ip,%sp
	push    {%r4,%r5,%r6,%r7}
	mov	%r7,%r0
	mov	%r0,%r1
	mov	%r1,%r2
	mov	%r2,%r3
	ldm	ip,{%r3,%r4,%r5,%r6}
	svc     $0
	pop	{%r4,%r5,%r6,%r7}
	bx    %lr

