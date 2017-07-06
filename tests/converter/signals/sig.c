#include <stdio.h>
#include <signal.h>


void hello() {
    raise(SIGSEGV);
}

void catch() {
    printf("%s", "Hello World!\n");
}

int main() {
    signal(SIGSEGV, catch);
    hello();
}
