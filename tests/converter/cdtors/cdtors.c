#include <stdio.h>

int global = 0;

int add(int x, int y) {
    return x + y;
}

__attribute__((constructor(101))) void ctor1(void) {
    // should output "ctor1(): 1"
    printf("ctor1(): %d\n", ++global);
}

__attribute__((constructor(102))) void ctor2(void) {
    // should output "ctor2(): 3"
    global = add(global, 2);
    printf("ctor2(): %d\n", global);
}

__attribute__((constructor)) void ctor3(void) {
    // should output "ctor1(): 6"
    global = add(global, 3);
    printf("ctor3(): %d\n", global);
}

__attribute__((destructor(103))) void dtor1(void) {
    // should output "dtor1(): 10"
    global += 4;
    printf("dtor1(): %d\n", global);
}

__attribute__((destructor(104))) void dtor2(void) {
    // should output "dtor2(): 15"
    global = add(global, 5);
    printf("dtor2(): %d\n", global);
}
