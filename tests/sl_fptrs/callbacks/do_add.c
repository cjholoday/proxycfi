#include <stdio.h>

#include "do_add.h"
#include "add.h"

typedef int (*i_ii)(int, int);
typedef int (*i_ci)(char, int);
typedef int (*i_ic)(int, char);

int global = 3;
int do_add(int x, int y, i_ii fptr) {
    add(x, y);
    return fptr(x, y);
}

int do_add_char1(char x, int y, i_ci fptr) {
    printf("do_add_char1()\n");
    return fptr(x, y);
}

int do_add_char2(int x, char y, i_ic fptr) {
    printf("do_add_char2()\n");
    return fptr(x, y);
}

int do_main_add(int x, int y,  i_ii fptr) {
    printf("do_main_add()\n");
    return fptr(x, y);
}

