#include <stdio.h>

void __attribute__ ((weak)) print(char *str) {
    printf("%s", str);
}

