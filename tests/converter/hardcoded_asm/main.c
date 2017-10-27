#include <stdio.h>
#include <string.h>

extern int add(int, int);
extern int do_add(int, int);

int main() {
    printf("1 + 1 = %d\n", add(1, 1));
    printf("1 + 1 = %d\n", do_add(1, 1));
}
