#include <stdio.h>
#include "sl1.h"

void sl3_internal() {
    printf("sl3_internal()\n");
    sl1_foo();
    sl1_foo();
    sl1_foo();
    sl1_foo();
    sl1_foo();
    sl1_foo();
    sl1_foo();
    sl1_foo();
    sl1_foo(); // all of these should count for 1 multiplicity
}
