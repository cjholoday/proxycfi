#include <stdio.h>
#include "sl1.h"

void sl2_internal() {
    printf("sl2_internal()\n");
    sl1_foo();
    sl1_bar();
    sl1_baz();
}
