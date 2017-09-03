#include <stdio.h>

#include "add.h"

int add(int x, int y) {
    printf("add()\n");
    return x + y;
}

int add_char1(char x, int y) {
    printf("add_char1()\n");
    return x + y;
}

int add_char2(int x, char y) {
    printf("add_char2()\n");
    return x + y;
}

/* these functions exist solely to add to function pointer sleds */
int sl_trap1(int x, int y) {
    printf("sl_trap1()\n");
    return x;
}
int sl_trap2(int x, int y) {
    printf("sl_trap2()\n");
    return x;
}
int sl_trap3(char x, int y) {
    printf("sl_trap3()\n");
    return x;
}
int sl_trap4(int x, char y) {
    printf("sl_trap4()\n");
    return x;
}

i_ii add_callback(void) {
    return &add;
}

i_ci add_char1_callback(void) {
    return &add_char1;
}

i_ic add_char2_callback(void) {
    return &add_char2;
}
