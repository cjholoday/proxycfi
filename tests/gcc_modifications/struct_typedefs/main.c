#include <stdio.h>


typedef struct tag {
    char *str;
} type;
typedef struct tag tag_t;
typedef type type_t;

typedef struct {
    char *str;
} tagless_type;
typedef tagless_type tagless_type_t;


void foo(tag_t t) {
    printf("%s", t.str);
}
void bar(tagless_type_t t) {
    printf("%s", t.str);
}
void baz(type_t t) {
    printf("%s", t.str);
}

int main() {
    void (*fptr1)(type_t) = foo;
    void (*fptr2)(tagless_type) = bar;
    void (*fptr3)(type) = baz;

    type_t x;
    x.str = "Hello ";
    fptr1(x);

    tagless_type y;
    y.str = "World";
    fptr2(y);

    type_t z;
    z.str = "!\n";
    fptr3(z);
}
