#include <stdio.h>
#include <string.h>

int main() {
    char greeting1[] = "Hello World";
    char greeting2[] = "HELLO WORLD";
    char greeting3[] = "XXXXXXXXXXX\n";

    memcpy((void*)greeting2, (void*)greeting1, 11);
    printf("%s", greeting2);

    memset(greeting3, '!', 11);
    printf("%s", greeting3);
}



