#include <stdio.h>

typedef struct {
    const char *str;
} custom_type;


void f1(char * restrict str) {}
void f2(char * restrict * restrict str) {}
void f3(custom_type  * restrict * restrict c) {
    printf("%s", (**c).str);
}

int main() {

    void (*f1_fp)(char * restrict) = f1;
    void (*f2_fp)(char * restrict * restrict) = f2;
    void (*f3_fp)(custom_type * restrict * restrict) = f3;

    // call the fptrs so that we can test the fptr type detection. 
    // We don't care if the functions do anything useful though
    f1_fp("---");
    f2_fp("---");

    custom_type x;
    x.str = "Hello World\n";
    custom_type* x_p = &x;
    custom_type** x_p_p = &x_p;
    f3_fp(x_p_p);
}
