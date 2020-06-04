#include <stdio.h>

#include "do_add.h"
#include "add.h"

/* make sure we distinguish between data and functions referenced relative to
 * the GOT. Both will show up with GOTPCREL assembly instructions */
int global = 3;

int do_add(int x, int y) {
    printf("do_add()\n"); 
    add(x, y);

    global += 1;

    int (*fptr)(int, int) = add;


    fptr(x, y + global);
    return fptr(x, y);
}
