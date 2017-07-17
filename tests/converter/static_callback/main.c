#include <stdio.h>

typedef int (*add_func_t)(int, int);
add_func_t get_callback();

void main() {
    add_func_t add = get_callback();
    printf("1 + 2 = %d\n", add(1, 2));
}
