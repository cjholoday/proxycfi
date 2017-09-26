#include <stdio.h>

void hello(const char *str) {
    printf(str);
}

// this should never be called. We only care about the code that's generated
void bad_call(void) {
    int (*fp)(int, int) = 0;
    fp(1, 2);
}
