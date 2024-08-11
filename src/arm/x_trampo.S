.text
.align	4
.globl	x_trampo
x_trampo:
	mov	%sp,%r1
	mov %lr,%r0

	mov	%r0,$0
	mov %r1,%r0
	mov	%r2,%r0
	mov	%r3,%r0
	mov	%r4,%r0
	mov	%r5,%r0
	mov	%r6,%r0
	mov	%r7,%r0
	mov	%r8,%r0
	mov	%r9,%r0

	bx	%lr
