# hardcoded_typeinfo
# typeinfo add.s.ftypes
# add.s:0:0:add i_ii
# add.s:1:0:do_add i_ii

# typeinfo add.s.fptypes
# add.s:2:0:do_add i_ii

# assembly

.globl add
.type add,@function
.file 1 "add.s"

add:
.LFB0:
	.loc 1 0 0
	mov %rdi, %rax
	add %rsi, %rax
	ret
.LFE0:
	.size add, .-add

.globl do_add
.type do_add,@function
do_add:
.LFB1:
	.loc 1 1 0
	mov $add, %rax
	.loc 1 2 0
	call *%rax
	ret
.LFE1:
	.size do_add, .-do_add
	.section    .debug_info,"",@progbits                                        
	.section    .note.GNU-stack,"",@progbits           

