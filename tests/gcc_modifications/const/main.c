#include <stdio.h>

typedef struct {
    char *str;
} custom_type;


void foo(const char *str) {
    printf("%s", str);
}
void bar(char *str) {
    printf("%s", str);
}
void baz(const custom_type t) {
    printf("%s", t.str);
}


int main() {
    void (*fptr1)(unsigned const char *) = foo;
    void (*fptr2)(signed char *) = bar;
    void (*fptr3)(const custom_type) = baz;

    custom_type x;
    x.str = "\n";
    fptr3(x);

    fptr1("Hello ");

    char *str = "World!";
    fptr2(str);

}
