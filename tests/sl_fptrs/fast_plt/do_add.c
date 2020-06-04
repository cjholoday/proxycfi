#include <stdio.h>

#include "do_add.h"
#include "add.h"

/* make sure we distinguish between data and functions referenced relative to
 * the GOT. Both will show up with GOTPCREL assembly instructions */
int global = 3;

int do_add(int x, int y) {
    printf("do_add()\n");
    add(x, y);

    int (*fptr)(int, int) = add;
    fptr(x, y);
    return fptr(x, y);
}

int do_add_char1(char x, int y) {
    global = 2;
    printf("do_add_char1()\n");

    int (*fptr)(char, int) = add_char1;
    return fptr(x, y);
}

int do_add_char2(int x, char y) {
    global = 1;
    printf("do_add_char2()\n");

    int (*fptr)(int, char) = add_char2;
    return fptr(x, y);
}

extern int main_add(int, int);
int do_main_add(int x, int y) {
    printf("do_main_add()\n");
    int (*fptr)(int, int) = main_add;

    return fptr(x, y);
}

