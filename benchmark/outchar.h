#ifndef OUTCHAR_H
#define OUTCHAR_H

/*
 * Custom putchar() function for x86
 */
void outchar(char c) {                                                          
    extern long write(int, const char *, unsigned long);                        
    write(1, &c, 1);                                                            
}        

#endif
