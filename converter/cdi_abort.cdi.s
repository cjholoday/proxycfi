	.text
	.globl	_CDI_abort
	.type	_CDI_abort, @function
.generic_msg:
        .string "cdi: unsafe movement, aborting...\ncdi: sled: "
        .set .generic_msg_len, .-.generic_msg
.newline_char:
        .string "\n"

# parameters:
#   %rsi: pointer to [unsigned int len][string of len size]
# 
#   TODO: make this position independent
_CDI_abort:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
        pushq   %rsi                        # save specific sled info for later
        movq    $.generic_msg, %rsi
        movq    $.generic_msg_len, %rdx
        movq    $1, %rax                    # write
        movq    $2, %rdi                    # to stderr
        syscall                             # print debug msg
        movq    $1, %rax                    
        movq    $2, %rdi                   
        popq    %rsi
        movl    (%rsi), %edx                # get string length
        lea     4(%rsi), %rsi               # get address of string
        syscall                             # print sled specific info
        movq    $1, %rax                    
        movq    $2, %rdi                   
        movq    $1, %rdx
        movq    $.newline_char, %rsi
        syscall                             # print newline
.abort:
        movq    $39, %rax                  
        syscall                             # get pid
        movq    %rax, %rdi
        movq    $62, %rax
        movq    $11, %rsi                    
        syscall                             # kill this process
	.cfi_endproc
.LFE0:
	.size	_CDI_abort, .-_CDI_abort
