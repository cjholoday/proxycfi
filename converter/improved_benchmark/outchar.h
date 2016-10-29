#ifndef OUTCHAR_H
#define OUTCHAR_H

/* avoid libc by using a system call */
void outchar(char c) {  
    asm volatile ("syscall"
            : /* ignoring output */
            : "a" (1), "D" (1), "S" (&c), "d" (1)
       );
}        

#endif
