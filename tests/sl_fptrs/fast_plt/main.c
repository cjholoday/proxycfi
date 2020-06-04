#include <stdio.h>

#include "add.h"
#include "do_add.h"

int main_add(int x, int y) { 
    printf("main_add()\n");
    return x + y;
}

int main() {
    int (*fptr1)(int, int) = add;
    int (*fptr2)(char, int) = add_char1;
    int (*fptr3)(int, int) = do_add;

    printf("5 + 6 = %d\n\n", add(5, 6));
    printf("3 + 2 = %d\n\n", do_add(3, 2));
    printf("8 + 1 = %d\n\n", do_add_char1(8, 1));
    printf("1 + 2 = %d\n\n", fptr1(1, 2));
    printf("5 + 7 = %d\n\n", fptr2(5, 7));
    printf("0 + 1 = %d\n\n", fptr3(0, 1));
    printf("9 + 7 = %d\n\n", do_main_add(9, 7));
}

/* these functions exist solely to add to function pointer sleds */
int trap1(int x, int y) {
    printf("trap1()\n");
    return x;
}
int trap2(int x, int y) {
    printf("trap2()\n");
    return x;
}
int trap3(char x, int y) {
    printf("trap3()\n");
    return x;
}
int trap4(int x, char y) {
    printf("trap4()\n");
    return x;
}

