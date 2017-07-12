#include <stdio.h>


typedef struct {
    char *str;
} custom_type;
typedef custom_type custom_type_t;


void foo(custom_type t) {
    printf("%s", t.str);
}
void bar(custom_type_t t) {
    printf("%s", t.str);
}


int main() {
    custom_type x;
    void (*fptr1)(custom_type_t) = foo;
    void (*fptr2)(custom_type) = bar;

    x.str = "Hello ";
    fptr1(x);

    x.str = "World!\n";
    fptr2(x);
}

