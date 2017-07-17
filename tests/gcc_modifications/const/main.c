#include <stdio.h>

typedef struct {
    const char *str;
} custom_type;


void f1(const char *str) {}
void f2(char * const str) {}
void f3(const char * const str) {}

void b1(char **arr) {}
void b2(const char **arr) {}
void b3(char * const *arr) {}
void b4(char ** const arr) {}
void b5(const char * const * const arr) {}

typedef const char * const * const const_arr;
void b5_typedef(const_arr arr) {}

void foo(const custom_type t) {
    printf("%s", t.str);
}


int main() {
    void (*fptr1)(const custom_type) = foo;

    custom_type x;
    x.str = "Hello World\n";
    fptr1(x);

    void (*f1_fp)(const char *) = f1;
    void (*f2_fp)(char * const) = f2;
    void (*f3_fp)(const char * const) = f3;

    void (*b1_fp)(char **) = b1;
    void (*b2_fp)(const char **) = b2;
    void (*b3_fp)(char * const*) = b3;
    void (*b4_fp)(char ** const) = b4;
    void (*b5_fp)(const char * const * const) = b5;
    void (*b5_typedef_fp)(const_arr) = b5_typedef;

    // call the fptrs so that we can test the fptr type detection. 
    // We don't care if the functions do anything useful though
    f1_fp("---");
    f2_fp("---");
    f3_fp("---");

    char *arr[1];
    b1_fp(arr);
    b2_fp(arr);
    b3_fp(arr);
    b4_fp(arr);
    b5_fp(arr);

    b5_typedef(arr);
}
