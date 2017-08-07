#include <stdio.h>
#include "calc.h"
#include "formulas.h"

int main() {
    printf("1 + 2 = %d\n", add(1, 2));
    printf("area of square(3) = %d\n", area_square(3));
    printf("area of circle(2) = %d\n", area_circle(2));
    printf("fib(5) = %d\n", nth_fibonacci(5));
    printf("fib(15) = %d\n", nth_fibonacci(15));
    printf("area of rectangle(2, 3) = %d\n", area_rectangle(2, 3));
}


