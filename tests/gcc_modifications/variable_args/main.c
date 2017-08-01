#include <stdio.h>
#include <stdarg.h>

int add(int num_inputs, ...) {
    va_list a_list;
    va_start(a_list, num_inputs);

    int sum = 0;
    for (int i = 0; i < num_inputs; i++) {
        sum += va_arg(a_list, int);
    }

    va_end(a_list);

    return sum;
}
typedef int (*int_handler_p)(int, ...);


int foo(int_handler_p p, int x, int y, int z) {
    return p(3, x, y, z);
}
int bar(int (*p)(int, ...), int x, int y, int z) {
    return p(3, x, y, z);
}

int main() {
    int (*fptr1)(int (*)(int, ...), int, int, int) = foo;
    int (*fptr2)(int_handler_p, int, int, int) = bar;

    printf("1 + 2 + 3 = %d\n", fptr1(add, 1, 2, 3));
    printf("4 + 5 + 6 = %d\n", fptr2(add, 4, 5, 6));
    printf("1 + 2 + 3 + 5 + 6 = %d\n", add(6, 1, 2, 3, 4 , 5, 6));
}
    
