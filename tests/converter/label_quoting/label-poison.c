#include <stdio.h>

int add(int x, int y) {
    return x + y;
}

int subtract(int x, int y) {
    return x - y;
}

int main() {
    int (*oper)(int, int) = add;
    printf("1+2=%d\n", oper(1, 2));
}



