	.text
	.globl	_CDI_abort
	.type	_CDI_abort, @function
.generic_msg:
        .string "cdi: unsafe movement, aborting...\n"
        .set .generic_msg_len, .-.generic_msg
.debug_msg:
        .string "cdi: sled: "
        .set .debug_msg_len, .-.debug_msg
.newline_char:
        .string "\n"
# parameters:
#   %rdx: length of message passed 
#   %rsi: pointer to string that will be printed
#
#   if %rdx contains 0, then only the generic string will be printed
_CDI_abort:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
        pushq   %rsi
        pushq   %rdx
        movq    $.generic_msg, %rsi
        movq    $.generic_msg_len, %rdx
        movq    $1, %rax                    # write
        movq    $2, %rdi                    # to stderr
        syscall                             # print generic message
        popq    %rdx
        cmpq    $0, %rdx
        je .abort
        pushq   %rdx
        movq    $1, %rax
        movq    $2, %rdi
        movq    $.debug_msg_len, %rdx
        movq    $.debug_msg, %rsi
        syscall                             # print debug msg
        movq    $1, %rax                    
        movq    $2, %rdi                   
        popq    %rdx
        popq    %rsi
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
