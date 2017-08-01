#include <stdio.h>

typedef struct {
    const char *str;
} custom_type;


void f1(char * volatile str) {}
void f2(char * volatile * volatile str) {}
void f3(custom_type  * volatile * volatile c) {
    printf("%s", (**c).str);
}

int main() {

    void (*f1_fp)(char * volatile) = f1;
    void (*f2_fp)(char * volatile * volatile) = f2;
    void (*f3_fp)(custom_type * volatile * volatile) = f3;

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
