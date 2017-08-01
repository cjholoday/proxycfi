#include <stdio.h>

typedef struct {
    const char *str;
} custom_type;

typedef const volatile custom_type * const volatile restrict * const volatile restrict qualified_custom_type;
void foo(const volatile custom_type  * const volatile restrict * const volatile restrict c) {
    printf("%s", (**c).str);
}

int main() {
    void (*fptr)(qualified_custom_type) = foo;

    custom_type x;
    x.str = "Hello World\n";
    custom_type* x_p = &x;
    custom_type** x_p_p = &x_p;
    fptr(x_p_p);
}
