#<deff>
# as_spec --64 -o main.o main.s
# as_spec_no_io --64 
# source_directory /home/colton/research/cdi/tests/verifier/catches_jump_tables
# dependencies main.c <built-in> 
# typeinfo main.c.ftypes
# main.c:1:5:main _CDIi_Z4mainv

# warning no_type_info <built-in>
# assembly
	.file	"main.c"
	.text
.Ltext0:
	.section	.rodata
.LC0:
	.string	"case 0"
.LC1:
	.string	"case 1"
.LC2:
	.string	"case 2"
.LC3:
	.string	"case 3"
.LC4:
	.string	"case 4"
.LC5:
	.string	"case 5"
.LC6:
	.string	"case 6"
.LC7:
	.string	"case 7"
.LC8:
	.string	"case 8"
.LC9:
	.string	"case 9"
.LC10:
	.string	"case 10"
.LC11:
	.string	"case 11"
.LC12:
	.string	"case 12"
.LC13:
	.string	"case 13"
.LC14:
	.string	"case 14"
.LC15:
	.string	"case 15"
.LC16:
	.string	"case 16"
.LC17:
	.string	"case 17"
.LC18:
	.string	"case 18"
.LC19:
	.string	"case 19"
.LC20:
	.string	"case 20"
	.text
	.globl	main
	.type	main, @function
main:
.globl	"main.fake.o.main"
"main.fake.o.main":
.LFB0:
	.file 1 "main.c"
	.loc 1 1 0
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	.loc 1 2 0
	movl	$8, -4(%rbp)
	.loc 1 3 0
	movl	-4(%rbp), %eax
	cmpl	$10, %eax
	je	.L3
	cmpl	$10, %eax
	jg	.L4
	cmpl	$4, %eax
	je	.L5
	cmpl	$4, %eax
	jg	.L6
	cmpl	$1, %eax
	je	.L7
	cmpl	$1, %eax
	jg	.L8
	testl	%eax, %eax
	je	.L9
	jmp	.L2
.L8:
	cmpl	$2, %eax
	je	.L10
	cmpl	$3, %eax
	je	.L11
	jmp	.L2
.L6:
	cmpl	$7, %eax
	je	.L12
	cmpl	$7, %eax
	jg	.L13
	cmpl	$5, %eax
	je	.L14
	cmpl	$6, %eax
	je	.L15
	jmp	.L2
.L13:
	cmpl	$8, %eax
	je	.L16
	cmpl	$9, %eax
	je	.L17
	jmp	.L2
.L4:
	cmpl	$15, %eax
	je	.L18
	cmpl	$15, %eax
	jg	.L19
	cmpl	$12, %eax
	je	.L20
	cmpl	$12, %eax
	jl	.L21
	cmpl	$13, %eax
	je	.L22
	cmpl	$14, %eax
	je	.L23
	jmp	.L2
.L19:
	cmpl	$18, %eax
	je	.L24
	cmpl	$18, %eax
	jg	.L25
	cmpl	$16, %eax
	je	.L26
	cmpl	$17, %eax
	je	.L27
	jmp	.L2
.L25:
	cmpl	$19, %eax
	je	.L28
	cmpl	$20, %eax
	je	.L29
	jmp	.L2
.L9:
.LBB2:
	.loc 1 5 0
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_1:
	.loc 1 6 0
	jmp	.L2
.L7:
	.loc 1 8 0
	movl	$.LC1, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_2:
	.loc 1 9 0
	jmp	.L2
.L10:
	.loc 1 11 0
	movl	$.LC2, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_3:
	.loc 1 12 0
	jmp	.L2
.L11:
	.loc 1 14 0
	movl	$.LC3, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_4:
	.loc 1 15 0
	jmp	.L2
.L5:
	.loc 1 17 0
	movl	$.LC4, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_5:
	.loc 1 18 0
	jmp	.L2
.L14:
	.loc 1 20 0
	movl	$.LC5, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_6:
	.loc 1 21 0
	jmp	.L2
.L15:
	.loc 1 23 0
	movl	$.LC6, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_7:
	.loc 1 24 0
	jmp	.L2
.L12:
	.loc 1 26 0
	movl	$.LC7, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_8:
	.loc 1 27 0
	jmp	.L2
.L16:
	.loc 1 29 0
	movl	$.LC8, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_9:
	.loc 1 30 0
	jmp	.L2
.L17:
	.loc 1 32 0
	movl	$.LC9, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_10:
	.loc 1 33 0
	jmp	.L2
.L3:
	.loc 1 35 0
	movl	$.LC10, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_11:
	.loc 1 36 0
	jmp	.L2
.L21:
	.loc 1 38 0
	movl	$.LC11, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_12:
	.loc 1 39 0
	jmp	.L2
.L20:
	.loc 1 41 0
	movl	$.LC12, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_13:
	.loc 1 42 0
	jmp	.L2
.L22:
	.loc 1 44 0
	movl	$.LC13, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_14:
	.loc 1 45 0
	jmp	.L2
.L23:
	.loc 1 47 0
	movl	$.LC14, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_15:
	.loc 1 48 0
	jmp	.L2
.L18:
	.loc 1 50 0
	movl	$.LC15, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_16:
	.loc 1 51 0
	jmp	.L2
.L26:
	.loc 1 53 0
	movl	$.LC16, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_17:
	.loc 1 54 0
	jmp	.L2
.L27:
	.loc 1 56 0
	movl	$.LC17, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_18:
	.loc 1 57 0
	jmp	.L2
.L24:
	.loc 1 59 0
	movl	$.LC18, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_19:
	.loc 1 60 0
	jmp	.L2
.L28:
	.loc 1 62 0
	movl	$.LC19, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_20:
	.loc 1 63 0
	jmp	.L2
.L29:
	.loc 1 65 0
	movl	$.LC20, %edi
	movl	$0, %eax
	call	printf
_CDI_printf_TO_main.fake.o.main_21:
	.loc 1 66 0
	nop
.L2:
.LBE2:
	movl	$0, %eax
	.loc 1 68 0
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	main, .-main
.Letext0:
	.file 2 "<built-in>"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x96
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF1
	.byte	0xc
	.long	.LASF2
	.long	.LASF3
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	.LASF4
	.byte	0x1
	.byte	0x1
	.long	0x80
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0x80
	.uleb128 0x3
	.string	"id"
	.byte	0x1
	.byte	0x2
	.long	0x80
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x4
	.quad	.LBB2
	.quad	.LBE2-.LBB2
	.uleb128 0x5
	.long	.LASF5
	.byte	0x2
	.byte	0
	.long	0x80
	.uleb128 0x6
	.long	0x87
	.uleb128 0x7
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x9
	.byte	0x8
	.long	0x94
	.uleb128 0xa
	.byte	0x1
	.byte	0x6
	.long	.LASF0
	.uleb128 0xb
	.long	0x8d
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
	.uleb128 0x4
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x5
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
	.uleb128 0x3c
	.uleb128 0x19
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
	.uleb128 0x18
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x8
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
	.uleb128 0x9
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
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
	.string	"GNU C11 6.1.0 -mtune=generic -march=x86-64 -g -fno-jump-tables"
.LASF5:
	.string	"printf"
.LASF3:
	.string	"/home/colton/research/cdi/tests/verifier/catches_jump_tables"
.LASF2:
	.string	"main.c"
.LASF4:
	.string	"main"
.LASF0:
	.string	"char"
	.ident	"GCC: (GNU) 6.1.0"
	.section	.note.GNU-stack,"",@progbits
	.type	_CDI_RLT_JUMP_TABLE, @function
_CDI_RLT_JUMP_TABLE:
	jmp "_CDI_RLT_printf"
	.size	_CDI_RLT_JUMP_TABLE, .-_CDI_RLT_JUMP_TABLE
	.type "_CDI_RLT_printf", @function
"_CDI_RLT_printf":
	cmpq	$_CDI_printf_TO_main.fake.o.main_1, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_1
	cmpq	$_CDI_printf_TO_main.fake.o.main_2, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_2
	cmpq	$_CDI_printf_TO_main.fake.o.main_3, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_3
	cmpq	$_CDI_printf_TO_main.fake.o.main_4, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_4
	cmpq	$_CDI_printf_TO_main.fake.o.main_5, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_5
	cmpq	$_CDI_printf_TO_main.fake.o.main_6, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_6
	cmpq	$_CDI_printf_TO_main.fake.o.main_7, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_7
	cmpq	$_CDI_printf_TO_main.fake.o.main_8, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_8
	cmpq	$_CDI_printf_TO_main.fake.o.main_9, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_9
	cmpq	$_CDI_printf_TO_main.fake.o.main_10, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_10
	cmpq	$_CDI_printf_TO_main.fake.o.main_11, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_11
	cmpq	$_CDI_printf_TO_main.fake.o.main_12, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_12
	cmpq	$_CDI_printf_TO_main.fake.o.main_13, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_13
	cmpq	$_CDI_printf_TO_main.fake.o.main_14, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_14
	cmpq	$_CDI_printf_TO_main.fake.o.main_15, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_15
	cmpq	$_CDI_printf_TO_main.fake.o.main_16, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_16
	cmpq	$_CDI_printf_TO_main.fake.o.main_17, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_17
	cmpq	$_CDI_printf_TO_main.fake.o.main_18, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_18
	cmpq	$_CDI_printf_TO_main.fake.o.main_19, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_19
	cmpq	$_CDI_printf_TO_main.fake.o.main_20, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_20
	cmpq	$_CDI_printf_TO_main.fake.o.main_21, -8(%rsp)
	je	_CDI_printf_TO_main.fake.o.main_21
	movq	 $.CDI_sled_id_1, %rsi
	movq	$.CDI_sled_id_1_len, %rdx
	call	_CDI_abort
.CDI_sled_id_1:
	.string	" id=1"
	.set	.CDI_sled_id_1_len, .-.CDI_sled_id_1
	.size "_CDI_RLT_printf", .-"_CDI_RLT_printf"
