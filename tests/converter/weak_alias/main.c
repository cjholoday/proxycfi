#include <stdio.h>

#define weak_alias(old, new) \
    extern __typeof(old) new __attribute__((weak, alias(#old)))

void hello() {
    printf("Hello world\n");
}
weak_alias(hello, hi);

weak_alias(hello, greetings);
int main() {
    greetings();
    hi();
}

