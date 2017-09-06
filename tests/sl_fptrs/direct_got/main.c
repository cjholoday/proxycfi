#include <stdio.h>

#include "add.h"
#include "do_add.h"

int main_add(int x, int y) { 
    printf("main_add()\n");
    return x + y;
}

int main() {
    printf("3 + 2 = %d\n\n", do_add(3, 2));
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

