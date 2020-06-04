#include "print.h"

void call_print(char *str) {
    void (*oper)(char *) = print;
    oper(str);
}
