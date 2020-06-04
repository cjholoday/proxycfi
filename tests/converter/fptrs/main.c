#include <stdio.h>
#include "calc.h"
#include "formulas.h"

void print_char(char c) {
    putc(c, stdout);
}


int main() {
    int (*fptr1)(int) = area_square;
    void (*fptr2)(char) = print_char;
    int (*fptr3)(int, int) = add;

    printf("area_square(1) = %d", fptr1(3));
    fptr2('\n');
    printf("area_square(2) = %d\n", fptr1(2));
    printf("1 + 2 = %d\n", fptr3(1, 2));

    fptr1 = area_circle;
    fptr3 = subtract;

    printf("area_circle(4) = %d\n", fptr1(4));
    printf("9 - 4 = %d\n", fptr3(9, 4));
}



