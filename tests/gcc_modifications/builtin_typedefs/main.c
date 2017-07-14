#include <stdio.h>

typedef int int_t;
typedef int int_T;
typedef int* int_ptr;
typedef int int_arr_t[10];
typedef void (*int_printer)(int);

void print_num1(int_t i) {
    printf("num: %d\n", i);
}
void print_num2(int_ptr ptr) {
    printf("num: %d\n", *ptr);
}
void print_num3(int_arr_t arr) {
    printf("num: %d\n", arr[3]);
}
void print_num4(int_printer p, int i) {
    p(i);
}


int main() {
    void (*fptr1)(int_T) = print_num1;
    void (*fptr2)(int *) = print_num2;
    void (*fptr3)(int[]) = print_num3;
    void (*fptr4)(void (*)(int), int) = print_num4;


    fptr1(1);

    int x = 2;
    int *p = &x;
    fptr2(p);

    int arr[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    fptr3(arr);

    fptr4(print_num1, 4);
}
