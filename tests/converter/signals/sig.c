#include <stdio.h>
#include <signal.h>


void hello() {
    int ret_value = raise(SIGSEGV);
    printf("success\n");
}

void catch() {
    printf("%s", "Hello World!\n");
}

int main() {
    signal(SIGSEGV, catch);
    hello();
}
