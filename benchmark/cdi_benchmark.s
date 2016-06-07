	.file	"cdi_benchmark.c"
	.local	num
	.comm	num,16,16
	.local	count
	.comm	count,8,8
	.text
	.type	mov, @function
mov:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movl	%edi, -20(%rbp)
	movl	%esi, -24(%rbp)
	movl	%edx, -28(%rbp)
	cmpl	$1, -20(%rbp)
	jne	.L2
	movl	-24(%rbp), %eax
	cltq
	movl	num(,%rax,4), %eax
	leal	-1(%rax), %edx
	movl	-24(%rbp), %eax
	cltq
	movl	%edx, num(,%rax,4)
	movl	-28(%rbp), %eax
	cltq
	movl	num(,%rax,4), %eax
	leal	1(%rax), %edx
	movl	-28(%rbp), %eax
	cltq
	movl	%edx, num(,%rax,4)
	movq	count(%rip), %rax
	addq	$1, %rax
	movq	%rax, count(%rip)
	movl	$0, %eax
	jmp	.L3
.L2:
	movl	-24(%rbp), %edx
	movl	-28(%rbp), %eax
	addl	%edx, %eax
	movl	$6, %edx
	subl	%eax, %edx
	movl	%edx, %eax
	movl	%eax, -4(%rbp)
	movl	-20(%rbp), %eax
	leal	-1(%rax), %ecx
	movl	-4(%rbp), %edx
	movl	-24(%rbp), %eax
	movl	%eax, %esi
	movl	%ecx, %edi
	call	mov
mov_mov_1:
	movl	-28(%rbp), %edx
	movl	-24(%rbp), %eax
	movl	%eax, %esi
	movl	$1, %edi
	call	mov
mov_mov_2:
	movl	-20(%rbp), %eax
	leal	-1(%rax), %ecx
	movl	-28(%rbp), %edx
	movl	-4(%rbp), %eax
	movl	%eax, %esi
	movl	%ecx, %edi
	call	mov
mov_mov_3:
	movl	$0, %eax
.L3:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	mov, .-mov
	.section	.rodata
	.align 8
.LC0:
	.string	"Towers of Hanoi Puzzle Test Program\n"
.LC1:
	.string	"Disks     Moves\n"
.LC2:
	.string	"%3d  %05d%05d\n"
	.text
	.globl	hanoi_main
	.type	hanoi_main, @function
hanoi_main:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	$0, -4(%rbp)
	movl	$.LC0, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_hanoi_main_1:
	movl	$.LC1, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_hanoi_main_2:
	movl	$0, -8(%rbp)
.L7:
	addl	$1, -8(%rbp)
	movl	$0, num(%rip)
	movl	-8(%rbp), %eax
	movl	%eax, num+4(%rip)
	movl	$0, num+8(%rip)
	movl	$0, num+12(%rip)
	movq	$0, count(%rip)
	movl	-8(%rbp), %eax
	movl	$3, %edx
	movl	$1, %esi
	movl	%eax, %edi
	call	mov
mov_hanoi_main_1:
	addl	$1, -4(%rbp)
	movq	count(%rip), %rax
	movzwl	%ax, %edx
	movq	count(%rip), %rax
	sarq	$16, %rax
	movq	%rax, %rsi
	movl	-8(%rbp), %eax
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movl	%eax, %esi
	movl	$.LC2, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_hanoi_main_3:
	cmpl	$30, -8(%rbp)
	je	.L10
	jmp	.L7
.L10:
	nop
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	hanoi_main, .-hanoi_main
	.globl	encipher
	.type	encipher, @function
encipher:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -56(%rbp)
	movq	%rsi, -64(%rbp)
	movq	%rdx, -72(%rbp)
	movq	-56(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -36(%rbp)
	movq	-56(%rbp), %rax
	movl	4(%rax), %eax
	movl	%eax, -32(%rbp)
	movl	$0, -28(%rbp)
	movl	$-1640531527, -20(%rbp)
	movq	-72(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -16(%rbp)
	movq	-72(%rbp), %rax
	movl	4(%rax), %eax
	movl	%eax, -12(%rbp)
	movq	-72(%rbp), %rax
	movl	8(%rax), %eax
	movl	%eax, -8(%rbp)
	movq	-72(%rbp), %rax
	movl	12(%rax), %eax
	movl	%eax, -4(%rbp)
	movl	$32, -24(%rbp)
	jmp	.L12
.L13:
	movl	-20(%rbp), %eax
	addl	%eax, -28(%rbp)
	movl	-32(%rbp), %eax
	sall	$4, %eax
	movl	%eax, %edx
	movl	-16(%rbp), %eax
	leal	(%rdx,%rax), %ecx
	movl	-32(%rbp), %edx
	movl	-28(%rbp), %eax
	addl	%edx, %eax
	xorl	%eax, %ecx
	movl	%ecx, %edx
	movl	-32(%rbp), %eax
	shrl	$5, %eax
	movl	%eax, %ecx
	movl	-12(%rbp), %eax
	addl	%ecx, %eax
	xorl	%edx, %eax
	addl	%eax, -36(%rbp)
	movl	-36(%rbp), %eax
	sall	$4, %eax
	movl	%eax, %edx
	movl	-8(%rbp), %eax
	leal	(%rdx,%rax), %ecx
	movl	-36(%rbp), %edx
	movl	-28(%rbp), %eax
	addl	%edx, %eax
	xorl	%eax, %ecx
	movl	%ecx, %edx
	movl	-36(%rbp), %eax
	shrl	$5, %eax
	movl	%eax, %ecx
	movl	-4(%rbp), %eax
	addl	%ecx, %eax
	xorl	%edx, %eax
	addl	%eax, -32(%rbp)
.L12:
	movl	-24(%rbp), %eax
	leal	-1(%rax), %edx
	movl	%edx, -24(%rbp)
	testl	%eax, %eax
	jne	.L13
	movq	-64(%rbp), %rax
	movl	-36(%rbp), %edx
	movl	%edx, (%rax)
	movq	-64(%rbp), %rax
	leaq	4(%rax), %rdx
	movl	-32(%rbp), %eax
	movl	%eax, (%rdx)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	encipher, .-encipher
	.globl	decipher
	.type	decipher, @function
decipher:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -56(%rbp)
	movq	%rsi, -64(%rbp)
	movq	%rdx, -72(%rbp)
	movq	-56(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -36(%rbp)
	movq	-56(%rbp), %rax
	movl	4(%rax), %eax
	movl	%eax, -32(%rbp)
	movl	$-957401312, -28(%rbp)
	movl	$-1640531527, -20(%rbp)
	movq	-72(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -16(%rbp)
	movq	-72(%rbp), %rax
	movl	4(%rax), %eax
	movl	%eax, -12(%rbp)
	movq	-72(%rbp), %rax
	movl	8(%rax), %eax
	movl	%eax, -8(%rbp)
	movq	-72(%rbp), %rax
	movl	12(%rax), %eax
	movl	%eax, -4(%rbp)
	movl	$32, -24(%rbp)
	jmp	.L15
.L16:
	movl	-36(%rbp), %eax
	sall	$4, %eax
	movl	%eax, %edx
	movl	-8(%rbp), %eax
	leal	(%rdx,%rax), %ecx
	movl	-36(%rbp), %edx
	movl	-28(%rbp), %eax
	addl	%edx, %eax
	xorl	%eax, %ecx
	movl	%ecx, %edx
	movl	-36(%rbp), %eax
	shrl	$5, %eax
	movl	%eax, %ecx
	movl	-4(%rbp), %eax
	addl	%ecx, %eax
	xorl	%edx, %eax
	subl	%eax, -32(%rbp)
	movl	-32(%rbp), %eax
	sall	$4, %eax
	movl	%eax, %edx
	movl	-16(%rbp), %eax
	leal	(%rdx,%rax), %ecx
	movl	-32(%rbp), %edx
	movl	-28(%rbp), %eax
	addl	%edx, %eax
	xorl	%eax, %ecx
	movl	%ecx, %edx
	movl	-32(%rbp), %eax
	shrl	$5, %eax
	movl	%eax, %ecx
	movl	-12(%rbp), %eax
	addl	%ecx, %eax
	xorl	%edx, %eax
	subl	%eax, -36(%rbp)
	movl	-20(%rbp), %eax
	subl	%eax, -28(%rbp)
.L15:
	movl	-24(%rbp), %eax
	leal	-1(%rax), %edx
	movl	%edx, -24(%rbp)
	testl	%eax, %eax
	jne	.L16
	movq	-64(%rbp), %rax
	movl	-36(%rbp), %edx
	movl	%edx, (%rax)
	movq	-64(%rbp), %rax
	leaq	4(%rax), %rdx
	movl	-32(%rbp), %eax
	movl	%eax, (%rdx)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	decipher, .-decipher
	.globl	keytext
	.data
	.align 16
	.type	keytext, @object
	.size	keytext, 16
keytext:
	.long	358852050
	.long	311606025
	.long	739108171
	.long	861449956
	.globl	plaintext
	.align 8
	.type	plaintext, @object
	.size	plaintext, 8
plaintext:
	.long	765625614
	.long	14247501
	.globl	cipherref
	.align 8
	.type	cipherref, @object
	.size	cipherref, 8
cipherref:
	.long	-1612527516
	.long	-673559132
	.comm	ciphertext,8,8
	.comm	newplain,8,8
	.section	.rodata
.LC3:
	.string	"TEA Cipher results:\n"
	.align 8
.LC4:
	.string	"  plaintext:  0x%04X%04X 0x%04X%04X\n"
	.align 8
.LC5:
	.string	"  ciphertext: 0x%04X%04X 0x%04X%04X\n"
	.align 8
.LC6:
	.string	"  newplain:   0x%04X%04X 0x%04X%04X\n"
	.text
	.globl	cipher_main
	.type	cipher_main, @function
cipher_main:
.LFB4:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	$encipher, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	$keytext, %edx
	movl	$ciphertext, %esi
	movl	$plaintext, %edi
	/*Sled 1*/
	cmpq 	$encipher, %rax
	jne		else1
	call 	encipher
encipher_cipher_main_1:
	jmp 	1f
	else1:
	cmpq 	$decipher, %rax
	jne 	1f
	call	decipher
decipher_cipher_main_1:
1:
	/*Sled 1 ends*/
	movl	ciphertext(%rip), %edx
	movl	cipherref(%rip), %eax
	cmpl	%eax, %edx
	jne	.L18
	movl	ciphertext+4(%rip), %edx
	movl	cipherref+4(%rip), %eax
	cmpl	%eax, %edx
	je	.L19
.L18:
	movl	$1, %eax
	jmp	.L20
.L19:
	movq	$decipher, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	$keytext, %edx
	movl	$newplain, %esi
	movl	$ciphertext, %edi
	/*Sled 2*/
	cmpq 	$encipher, %rax
	jne		else2
	call 	encipher
encipher_cipher_main_2:
	jmp 	1f
	else2:
	cmpq 	$decipher, %rax
	jne 	1f
	call	decipher
decipher_cipher_main_2:
1:
	/*Sled 2 ends*/
	movl	newplain(%rip), %edx
	movl	plaintext(%rip), %eax
	cmpl	%eax, %edx
	jne	.L21
	movl	newplain+4(%rip), %edx
	movl	plaintext+4(%rip), %eax
	cmpl	%eax, %edx
	je	.L22
.L21:
	movl	$1, %eax
	jmp	.L20
.L22:
	movl	$.LC3, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_cipher_main_1:
	movl	plaintext+4(%rip), %eax
	movzwl	%ax, %ecx
	movl	plaintext+4(%rip), %eax
	shrl	$16, %eax
	movl	%eax, %edx
	movl	plaintext(%rip), %eax
	movzwl	%ax, %eax
	movl	plaintext(%rip), %esi
	shrl	$16, %esi
	movl	%ecx, %r8d
	movl	%edx, %ecx
	movl	%eax, %edx
	movl	$.LC4, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_cipher_main_2:
	movl	ciphertext+4(%rip), %eax
	movzwl	%ax, %ecx
	movl	ciphertext+4(%rip), %eax
	shrl	$16, %eax
	movl	%eax, %edx
	movl	ciphertext(%rip), %eax
	movzwl	%ax, %eax
	movl	ciphertext(%rip), %esi
	shrl	$16, %esi
	movl	%ecx, %r8d
	movl	%edx, %ecx
	movl	%eax, %edx
	movl	$.LC5, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_cipher_main_3:
	movl	newplain+4(%rip), %eax
	movzwl	%ax, %ecx
	movl	newplain+4(%rip), %eax
	shrl	$16, %eax
	movl	%eax, %edx
	movl	newplain(%rip), %eax
	movzwl	%ax, %eax
	movl	newplain(%rip), %esi
	shrl	$16, %esi
	movl	%ecx, %r8d
	movl	%edx, %ecx
	movl	%eax, %edx
	movl	$.LC6, %edi
	movl	$0, %eax
	call	tfp_printf
tfp_printf_cipher_main_4:
	movl	$0, %eax
.L20:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	cipher_main, .-cipher_main
	.globl	main
	.type	main, @function
main:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	call	hanoi_main
hanoi_main_main_1:
	call	cipher_main
cipher_main_main_1:
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 5.2.1-22ubuntu2) 5.2.1 20151010"
	.section	.note.GNU-stack,"",@progbits
