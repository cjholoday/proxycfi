	.file	"printf.c"
	.text
	.globl	outchar
	.type	outchar, @function
outchar:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, %eax
	movb	%al, -4(%rbp)
	leaq	-4(%rbp), %rax
	movl	$1, %edx
	movq	%rax, %rsi
	movl	$1, %edi
	movq 	$1, %rax
	movq	$1, %rdi
	movq 	$1, %rdx
    syscall
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	outchar, .-outchar
	.local	bf
	.comm	bf,8,8
	.local	buf
	.comm	buf,12,8
	.local	num
	.comm	num,4,4
	.local	uc
	.comm	uc,1,1
	.local	zs
	.comm	zs,1,1
	.type	out, @function
out:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, %eax
	movb	%al, -4(%rbp)
	movq	bf(%rip), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, bf(%rip)
	movzbl	-4(%rbp), %edx
	movb	%dl, (%rax)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	out, .-out
	.type	outDgt, @function
outDgt:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$8, %rsp
	movl	%edi, %eax
	movb	%al, -4(%rbp)
	cmpb	$9, -4(%rbp)
	jle	.L4
	movzbl	uc(%rip), %eax
	testb	%al, %al
	je	.L5
	movl	$55, %eax
	jmp	.L7
.L5:
	movl	$87, %eax
	jmp	.L7
.L4:
	movl	$48, %eax
.L7:
	movzbl	-4(%rbp), %edx
	addl	%edx, %eax
	movsbl	%al, %eax
	movl	%eax, %edi
	call	out
out_outDgt_1:
	movb	$1, zs(%rip)
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	outDgt, .-outDgt
	.type	divOut, @function
divOut:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$24, %rsp
	movl	%edi, -20(%rbp)
	movb	$0, -1(%rbp)
	movl	num(%rip), %eax
	movzwl	%ax, %eax
	movl	%eax, num(%rip)
	jmp	.L9
.L10:
	movl	num(%rip), %eax
	subl	-20(%rbp), %eax
	movl	%eax, num(%rip)
	movzbl	-1(%rbp), %eax
	addl	$1, %eax
	movb	%al, -1(%rbp)
.L9:
	movl	num(%rip), %eax
	cmpl	-20(%rbp), %eax
	jnb	.L10
	movzbl	zs(%rip), %eax
	testb	%al, %al
	jne	.L11
	cmpb	$0, -1(%rbp)
	je	.L13
.L11:
	movzbl	-1(%rbp), %eax
	movsbl	%al, %eax
	movl	%eax, %edi
	call	outDgt
outDgt_divOut_1:
.L13:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	divOut, .-divOut
	.globl	tfp_printf
	.type	tfp_printf, @function
tfp_printf:
.LFB4:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$240, %rsp
	movq	%rdi, -232(%rbp)
	movq	%rsi, -168(%rbp)
	movq	%rdx, -160(%rbp)
	movq	%rcx, -152(%rbp)
	movq	%r8, -144(%rbp)
	movq	%r9, -136(%rbp)
	testb	%al, %al
	je	.L15
	movaps	%xmm0, -128(%rbp)
	movaps	%xmm1, -112(%rbp)
	movaps	%xmm2, -96(%rbp)
	movaps	%xmm3, -80(%rbp)
	movaps	%xmm4, -64(%rbp)
	movaps	%xmm5, -48(%rbp)
	movaps	%xmm6, -32(%rbp)
	movaps	%xmm7, -16(%rbp)
.L15:
	movq	%fs:40, %rax
	movq	%rax, -184(%rbp)
	xorl	%eax, %eax
	movl	$8, -208(%rbp)
	movl	$48, -204(%rbp)
	leaq	16(%rbp), %rax
	movq	%rax, -200(%rbp)
	leaq	-176(%rbp), %rax
	movq	%rax, -192(%rbp)
	jmp	.L16
.L51:
	cmpb	$37, -219(%rbp)
	je	.L17
	movsbl	-219(%rbp), %eax
	movl	%eax, %edi
	call	outchar
outchar_tfp_printf_1:
	jmp	.L16
.L17:
	movb	$0, -218(%rbp)
	movb	$0, -217(%rbp)
	movq	-232(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -232(%rbp)
	movzbl	(%rax), %eax
	movb	%al, -219(%rbp)
	cmpb	$48, -219(%rbp)
	jne	.L18
	movq	-232(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -232(%rbp)
	movzbl	(%rax), %eax
	movb	%al, -219(%rbp)
	movb	$1, -218(%rbp)
.L18:
	cmpb	$47, -219(%rbp)
	jle	.L19
	cmpb	$57, -219(%rbp)
	jg	.L19
	movb	$0, -217(%rbp)
	jmp	.L20
.L21:
	movzbl	-217(%rbp), %eax
	leal	0(,%rax,4), %edx
	movzbl	-217(%rbp), %eax
	addl	%edx, %eax
	leal	(%rax,%rax), %edx
	movzbl	-219(%rbp), %eax
	addl	%edx, %eax
	subl	$48, %eax
	movb	%al, -217(%rbp)
	movq	-232(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -232(%rbp)
	movzbl	(%rax), %eax
	movb	%al, -219(%rbp)
.L20:
	cmpb	$47, -219(%rbp)
	jle	.L19
	cmpb	$57, -219(%rbp)
	jle	.L21
.L19:
	movq	$buf, bf(%rip)
	movq	bf(%rip), %rax
	movq	%rax, -216(%rbp)
	movb	$0, zs(%rip)
	movsbl	-219(%rbp), %eax
	cmpl	$99, %eax
	je	.L23
	cmpl	$99, %eax
	jg	.L24
	cmpl	$37, %eax
	je	.L25
	cmpl	$88, %eax
	je	.L26
	testl	%eax, %eax
	je	.L53
	jmp	.L54
.L24:
	cmpl	$115, %eax
	je	.L28
	cmpl	$115, %eax
	jg	.L29
	cmpl	$100, %eax
	je	.L30
	jmp	.L54
.L29:
	cmpl	$117, %eax
	je	.L30
	cmpl	$120, %eax
	je	.L26
	jmp	.L54
.L30:
	movl	-208(%rbp), %eax
	cmpl	$48, %eax
	jnb	.L32
	movq	-192(%rbp), %rax
	movl	-208(%rbp), %edx
	movl	%edx, %edx
	addq	%rdx, %rax
	movl	-208(%rbp), %edx
	addl	$8, %edx
	movl	%edx, -208(%rbp)
	jmp	.L33
.L32:
	movq	-200(%rbp), %rax
	leaq	8(%rax), %rdx
	movq	%rdx, -200(%rbp)
.L33:
	movl	(%rax), %eax
	movl	%eax, num(%rip)
	cmpb	$100, -219(%rbp)
	jne	.L34
	movl	num(%rip), %eax
	testl	%eax, %eax
	jns	.L34
	movl	num(%rip), %eax
	negl	%eax
	movl	%eax, num(%rip)
	movl	$45, %edi
	call	out
out_tfp_printf_1:
.L34:
	movl	$10000, %edi
	call	divOut
divOut_tfp_printf_1:
	movl	$1000, %edi
	call	divOut
divOut_tfp_printf_2:
	movl	$100, %edi
	call	divOut
divOut_tfp_printf_3:
	movl	$10, %edi
	call	divOut
divOut_tfp_printf_4:
	movl	num(%rip), %eax
	movsbl	%al, %eax
	movl	%eax, %edi
	call	outDgt
outDgt_tfp_printf_1:
	jmp	.L35
.L26:
	cmpb	$88, -219(%rbp)
	sete	%al
	movb	%al, uc(%rip)
	movl	-208(%rbp), %eax
	cmpl	$48, %eax
	jnb	.L36
	movq	-192(%rbp), %rax
	movl	-208(%rbp), %edx
	movl	%edx, %edx
	addq	%rdx, %rax
	movl	-208(%rbp), %edx
	addl	$8, %edx
	movl	%edx, -208(%rbp)
	jmp	.L37
.L36:
	movq	-200(%rbp), %rax
	leaq	8(%rax), %rdx
	movq	%rdx, -200(%rbp)
.L37:
	movl	(%rax), %eax
	movl	%eax, num(%rip)
	movl	$4096, %edi
	call	divOut
divOut_tfp_printf_5:
	movl	$256, %edi
	call	divOut
divOut_tfp_printf_6:
	movl	$16, %edi
	call	divOut
divOut_tfp_printf_7:
	movl	num(%rip), %eax
	movsbl	%al, %eax
	movl	%eax, %edi
	call	outDgt
outDgt_tfp_printf_2:
	jmp	.L35
.L23:
	movl	-208(%rbp), %eax
	cmpl	$48, %eax
	jnb	.L38
	movq	-192(%rbp), %rax
	movl	-208(%rbp), %edx
	movl	%edx, %edx
	addq	%rdx, %rax
	movl	-208(%rbp), %edx
	addl	$8, %edx
	movl	%edx, -208(%rbp)
	jmp	.L39
.L38:
	movq	-200(%rbp), %rax
	leaq	8(%rax), %rdx
	movq	%rdx, -200(%rbp)
.L39:
	movl	(%rax), %eax
	movsbl	%al, %eax
	movl	%eax, %edi
	call	out
out_tfp_printf_2:
	jmp	.L35
.L28:
	movl	-208(%rbp), %eax
	cmpl	$48, %eax
	jnb	.L40
	movq	-192(%rbp), %rax
	movl	-208(%rbp), %edx
	movl	%edx, %edx
	addq	%rdx, %rax
	movl	-208(%rbp), %edx
	addl	$8, %edx
	movl	%edx, -208(%rbp)
	jmp	.L41
.L40:
	movq	-200(%rbp), %rax
	leaq	8(%rax), %rdx
	movq	%rdx, -200(%rbp)
.L41:
	movq	(%rax), %rax
	movq	%rax, -216(%rbp)
	jmp	.L35
.L25:
	movl	$37, %edi
	call	out
out_tfp_printf_3:
.L54:
	nop
.L35:
	movq	bf(%rip), %rax
	movb	$0, (%rax)
	movq	-216(%rbp), %rax
	movq	%rax, bf(%rip)
	jmp	.L42
.L44:
	movzbl	-217(%rbp), %eax
	subl	$1, %eax
	movb	%al, -217(%rbp)
.L42:
	movq	bf(%rip), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, bf(%rip)
	movzbl	(%rax), %eax
	testb	%al, %al
	je	.L45
	cmpb	$0, -217(%rbp)
	jg	.L44
	jmp	.L45
.L48:
	cmpb	$0, -218(%rbp)
	je	.L46
	movl	$48, %eax
	jmp	.L47
.L46:
	movl	$32, %eax
.L47:
	movl	%eax, %edi
	call	outchar
outchar_tfp_printf_2:
.L45:
	movzbl	-217(%rbp), %eax
	movl	%eax, %edx
	subl	$1, %edx
	movb	%dl, -217(%rbp)
	testb	%al, %al
	jg	.L48
	jmp	.L49
.L50:
	movsbl	-219(%rbp), %eax
	movl	%eax, %edi
	call	outchar
outchar_tfp_printf_3:
.L49:
	movq	-216(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -216(%rbp)
	movzbl	(%rax), %eax
	movb	%al, -219(%rbp)
	cmpb	$0, -219(%rbp)
	jne	.L50
.L16:
	movq	-232(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -232(%rbp)
	movzbl	(%rax), %eax
	movb	%al, -219(%rbp)
	cmpb	$0, -219(%rbp)
	jne	.L51
	jmp	.L31
.L53:
	nop
.L31:
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	tfp_printf, .-tfp_printf
	.ident	"GCC: (Ubuntu 5.2.1-22ubuntu2) 5.2.1 20151010"
	.section	.note.GNU-stack,"",@progbits
