/* Specify permissions for CDI metadata sections added by cdi-ld.py 
 * The sections are replaced and resized accordingly
 */
    .text

    /* Any executable or shared library that has this section claims to be CDI */
    .section .cdi_header, "a", @progbits
    .align 4
    .quad 0xdeadbeefefbeadde

    /* Contains info to calculate SLT size at load time */
    .section .cdi_multtab, "a", @progbits
    .align 4
    .quad 0xdeadbeefefbeadde

    /* Contains names of each library referenced in the .cdi_multtab */
    .section .cdi_libstrtab, "a", @progbits
    .quad 0xdeadbeefefbeadde

