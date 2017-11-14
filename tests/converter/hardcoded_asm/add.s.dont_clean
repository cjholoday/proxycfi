# hardcoded_typeinfo
# typeinfo add.s.ftypes
# add.s:0:0:add i_ii
# add.s:1:0:do_add i_ii

# typeinfo add.s.fptypes
# add.s:2:0:do_add i_ii

# assembly

# hardcoding checklist:
#	1. Begin and end with '#hardcoded_typeinfo\n' and '# assembly\n' respectively
#	2. Add funct/fptr type info with dummy line numbers
#	3. Add a dummy '.file' directive for this file
#	4. Use '.loc' commands with the dummy line numbers to associate assembly with type info
#	5. Begin and end each function .LFBX: and .LFEX: where X is a unique number to within this file
#	6. Change all .global directives to .globl
#	7. Add the debug_info and gnu stack sections EXACTLY as they are in this file
#	8. Add '.size' directives so that function symbols have a size
#	9. If you run into problems, you're probably doing something slight differnt
#      and unfortunately the hardcoding process is currently brittle. Try to 
#	   follow this example more closely

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
