#<deff>
# as_spec --64 -o has_indir_call.o has_indir_call.s
# as_spec_no_io --64 
# source_directory /home/colton/research/cdi/tests/verifier/basic
# dependencies has_indir_call.c 
# typeinfo has_indir_call.c.ftypes
# has_indir_call.c:1:5:add _CDIi_Z3addii
# has_indir_call.c:5:5:subtract _CDIi_Z8subtractii
# has_indir_call.c:9:5:multiply _CDIi_Z8multiplyii
# has_indir_call.c:13:5:divide _CDIi_Z6divideii
# has_indir_call.c:17:5:main _CDIi_Z4mainv

# typeinfo has_indir_call.c.fptypes
# has_indir_call.c:19:5:main _CDIi_Zii

# assembly
	.file	"has_indir_call.c"
	.text
.Ltext0:
	.globl	add
	.type	add, @function
add:
.globl	"has_indir_call.fake.o.add"
"has_indir_call.fake.o.add":
.LFB0:
	.file 1 "has_indir_call.c"
	.loc 1 1 0
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	.loc 1 2 0
	movl	-4(%rbp), %edx
	movl	-8(%rbp), %eax
	addl	%edx, %eax
	.loc 1 3 0
	popq	%rbp
	.cfi_def_cfa 7, 8
	addq $8, %rsp
	cmpq	$"_CDI_has_indir_call.fake.o.add_TO_has_indir_call.fake.o.main_1", -8(%rsp)
	je	"_CDI_has_indir_call.fake.o.add_TO_has_indir_call.fake.o.main_1"
	movq	 $.CDI_sled_id_1, %rsi
	movq	$.CDI_sled_id_1_len, %rdx
	call	_CDI_abort
.CDI_sled_id_1:
	.string	"has_indir_call.c:3:0:has_indir_call.fake.o id=1"
	.set	.CDI_sled_id_1_len, .-.CDI_sled_id_1
	.cfi_endproc
.LFE0:
	.size	add, .-add
	.globl	subtract
	.type	subtract, @function
subtract:
.globl	"has_indir_call.fake.o.subtract"
"has_indir_call.fake.o.subtract":
.LFB1:
	.loc 1 5 0
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	.loc 1 6 0
	movl	-4(%rbp), %eax
	subl	-8(%rbp), %eax
	.loc 1 7 0
	popq	%rbp
	.cfi_def_cfa 7, 8
	addq $8, %rsp
	cmpq	$"_CDI_has_indir_call.fake.o.subtract_TO_has_indir_call.fake.o.main_1", -8(%rsp)
	je	"_CDI_has_indir_call.fake.o.subtract_TO_has_indir_call.fake.o.main_1"
	movq	 $.CDI_sled_id_2, %rsi
	movq	$.CDI_sled_id_2_len, %rdx
	call	_CDI_abort
.CDI_sled_id_2:
	.string	"has_indir_call.c:7:0:has_indir_call.fake.o id=2"
	.set	.CDI_sled_id_2_len, .-.CDI_sled_id_2
	.cfi_endproc
.LFE1:
	.size	subtract, .-subtract
	.globl	multiply
	.type	multiply, @function
multiply:
.globl	"has_indir_call.fake.o.multiply"
"has_indir_call.fake.o.multiply":
.LFB2:
	.loc 1 9 0
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	.loc 1 10 0
	movl	-4(%rbp), %eax
	imull	-8(%rbp), %eax
	.loc 1 11 0
	popq	%rbp
	.cfi_def_cfa 7, 8
	addq $8, %rsp
	cmpq	$"_CDI_has_indir_call.fake.o.multiply_TO_has_indir_call.fake.o.main_1", -8(%rsp)
	je	"_CDI_has_indir_call.fake.o.multiply_TO_has_indir_call.fake.o.main_1"
	movq	 $.CDI_sled_id_3, %rsi
	movq	$.CDI_sled_id_3_len, %rdx
	call	_CDI_abort
.CDI_sled_id_3:
	.string	"has_indir_call.c:11:0:has_indir_call.fake.o id=3"
	.set	.CDI_sled_id_3_len, .-.CDI_sled_id_3
	.cfi_endproc
.LFE2:
	.size	multiply, .-multiply
	.globl	divide
	.type	divide, @function
divide:
.globl	"has_indir_call.fake.o.divide"
"has_indir_call.fake.o.divide":
.LFB3:
	.loc 1 13 0
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	.loc 1 14 0
	movl	-4(%rbp), %eax
	cltd
	idivl	-8(%rbp)
	.loc 1 15 0
	popq	%rbp
	.cfi_def_cfa 7, 8
	addq $8, %rsp
	cmpq	$"_CDI_has_indir_call.fake.o.divide_TO_has_indir_call.fake.o.main_1", -8(%rsp)
	je	"_CDI_has_indir_call.fake.o.divide_TO_has_indir_call.fake.o.main_1"
	movq	 $.CDI_sled_id_4, %rsi
	movq	$.CDI_sled_id_4_len, %rdx
	call	_CDI_abort
.CDI_sled_id_4:
	.string	"has_indir_call.c:15:0:has_indir_call.fake.o id=4"
	.set	.CDI_sled_id_4_len, .-.CDI_sled_id_4
	.cfi_endproc
.LFE3:
	.size	divide, .-divide
	.globl	main
	.type	main, @function
main:
.globl	"has_indir_call.fake.o.main"
"has_indir_call.fake.o.main":
.LFB4:
	.loc 1 17 0
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	.loc 1 18 0
	movq	$add, -8(%rbp)
	.loc 1 19 0
	movq	-8(%rbp), %rax
	movl	$2, %esi
	movl	$1, %edi
        call    *%rax
1:
	cmpq	$"has_indir_call.fake.o.multiply", %rax
	jne	1f
	call	"has_indir_call.fake.o.multiply"
"_CDI_has_indir_call.fake.o.multiply_TO_has_indir_call.fake.o.main_1":
	jmp	2f
1:
	cmpq	$"has_indir_call.fake.o.divide", %rax
	jne	1f
	call	"has_indir_call.fake.o.divide"
"_CDI_has_indir_call.fake.o.divide_TO_has_indir_call.fake.o.main_1":
	jmp	2f
1:
	cmpq	$"has_indir_call.fake.o.add", %rax
	jne	1f
	call	"has_indir_call.fake.o.add"
"_CDI_has_indir_call.fake.o.add_TO_has_indir_call.fake.o.main_1":
	jmp	2f
1:
	cmpq	$"has_indir_call.fake.o.subtract", %rax
	jne	1f
	call	"has_indir_call.fake.o.subtract"
"_CDI_has_indir_call.fake.o.subtract_TO_has_indir_call.fake.o.main_1":
	jmp	2f
1:
	movq	 $.CDI_sled_id_5, %rsi
	movq	$.CDI_sled_id_5_len, %rdx
	call	_CDI_abort
.CDI_sled_id_5:
	.string	"has_indir_call.c:19:0:has_indir_call.fake.o id=5"
	.set	.CDI_sled_id_5_len, .-.CDI_sled_id_5
2:
.LVL0:
	movl	$0, %eax
	.loc 1 20 0
	leave
	.cfi_def_cfa 7, 8
	.cfi_endproc
.LFE4:
	.size	main, .-main
.Letext0:
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x15f
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF4
	.byte	0xc
	.long	.LASF5
	.long	.LASF6
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	.LASF3
	.byte	0x1
	.byte	0x11
	.long	0x5d
	.quad	.LFB4
	.quad	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.long	0x5d
	.uleb128 0x3
	.long	.LASF7
	.byte	0x1
	.byte	0x12
	.long	0x78
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x5
	.long	0x5d
	.long	0x78
	.uleb128 0x6
	.long	0x5d
	.uleb128 0x6
	.long	0x5d
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x64
	.uleb128 0x8
	.long	.LASF0
	.byte	0x1
	.byte	0xd
	.long	0x5d
	.quad	.LFB3
	.quad	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0xb8
	.uleb128 0x9
	.string	"x"
	.byte	0x1
	.byte	0xd
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x9
	.string	"y"
	.byte	0x1
	.byte	0xd
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x8
	.long	.LASF1
	.byte	0x1
	.byte	0x9
	.long	0x5d
	.quad	.LFB2
	.quad	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0xf2
	.uleb128 0x9
	.string	"x"
	.byte	0x1
	.byte	0x9
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x9
	.string	"y"
	.byte	0x1
	.byte	0x9
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x8
	.long	.LASF2
	.byte	0x1
	.byte	0x5
	.long	0x5d
	.quad	.LFB1
	.quad	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x12c
	.uleb128 0x9
	.string	"x"
	.byte	0x1
	.byte	0x5
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x9
	.string	"y"
	.byte	0x1
	.byte	0x5
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0xa
	.string	"add"
	.byte	0x1
	.byte	0x1
	.long	0x5d
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x9
	.string	"x"
	.byte	0x1
	.byte	0x1
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x9
	.string	"y"
	.byte	0x1
	.byte	0x1
	.long	0x5d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x2c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF1:
	.string	"multiply"
.LASF5:
	.string	"has_indir_call.c"
.LASF0:
	.string	"divide"
.LASF4:
	.string	"GNU C11 6.1.0 -mtune=generic -march=x86-64 -g -fno-jump-tables"
.LASF7:
	.string	"calc_oper"
.LASF2:
	.string	"subtract"
.LASF3:
	.string	"main"
.LASF6:
	.string	"/home/colton/research/cdi/tests/verifier/basic"
	.ident	"GCC: (GNU) 6.1.0"
	.section	.note.GNU-stack,"",@progbits
	.type	_CDI_RLT_JUMP_TABLE, @function
_CDI_RLT_JUMP_TABLE:
	.size	_CDI_RLT_JUMP_TABLE, .-_CDI_RLT_JUMP_TABLE
