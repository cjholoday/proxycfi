#include <stdio.h>
#include "sl1.h"

// multiplicity 3
void sl1_foo() {
    printf("sl1_foo()\n");
    sl1_bar();
    sl1_baz();
}

// multiplicity 2
void sl1_bar() {
    printf("sl1_bar()\n");
    sl1_baz();
}

// multiplicity 1 called from another shared library
void sl1_baz() {
    printf("sl1_baz()\n");
}

// multiplicity 1 called from the executable
void sl1_qux() {
    printf("sl1_qux()\n");
    sl1_internal();
}

// multiplicity 0 (mult should not be affected by calls within a shared library)
void sl1_internal() {
    printf("sl1_internal()\n");
}
