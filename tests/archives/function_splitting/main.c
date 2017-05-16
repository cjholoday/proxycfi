#include <stdlib.h>

#include "inline.h"

int main() {
    int sum = 
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-2, -1, 1, 1, 1, 1)  +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-11, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-2, -1, 1, 1, 1, 1); +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-2, -1, 1, 1, 1, 1)  +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-2, -1, 1, 1, 1, 1)  +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-8, -1, 1, 1, 1, 1)  +
        inline_me(-23, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-3, -1, 1, 1, 1, 1)  +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(-34, -1, 1, 1, 1, 1) +
        inline_me(30, 2, 3, 4, 5, 6);

    printf("total=%d\n", sum);
}
