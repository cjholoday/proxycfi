#include <stdio.h>

/* Test function pointer type dropping thoroughly. The syntax sure is confusing */

typedef void (*int_printer_p)(int);
typedef void (*int_printer_printer_p)(int_printer_p, int);
typedef void (*int_printer_printer_printer_p)(int_printer_printer_p, int_printer_p, int);

void print_num(int i) {
    printf("num: %d\n", i);
}

void int_printer_printer(int_printer_p p, int i) {
    p(i);
}

void int_printer_printer_printer1(int_printer_printer_p pp, int_printer_p p, int i) {
    pp(p, i);
}

void int_printer_printer_printer2(void (*pp)(void (*)(int), int), void (*p)(int), int i) {
    pp(p, i);
}


int main() {
    void (*fptr1)(void (*)(int), int) = int_printer_printer;
    void (*fptr2)(void (*)(void (*)(int), int), void (*)(int), int) 
        = int_printer_printer_printer1;
    int_printer_printer_printer_p fptr3 = int_printer_printer_printer2;

    fptr1(print_num, 1);
    fptr2(fptr1, print_num, 2);
    fptr3(fptr1, print_num, 3);
}
