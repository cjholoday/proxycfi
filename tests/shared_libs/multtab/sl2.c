#include <stdio.h>
#include "sl1.h"

void sl2_internal() {
    printf("sl2_internal()\n");
    sl1_foo();
    sl1_bar();
    sl1_baz();
}


void sl2_call_sl1_foo() {
    printf("sl2_call_sl1_foo()\n");
    sl1_foo();
}
