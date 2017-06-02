#include <stdio.h>

int add(int x, int y) {
    return x + y;
}

int subtract(int x, int y) { 
    return x - y;
}

int multiply(int x, int y) {
    return x * y;
}

int divide(int x, int y) {
    return x / y;
}

int main() {
    printf("2+3=%d\n", call_it(&add, 2, 3));
    printf("2-3=%d\n", call_it(&subtract, 2, 3));
    printf("2*3=%d\n", call_it(&multiply, 2, 3));
}

