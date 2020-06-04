#include <stdio.h>

extern int global;
void main() {
    printf("main(): %d\n", global);
}
