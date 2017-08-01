#include <stdio.h>
#include <string.h>

typedef int (*strcmp_ptr_t)(const char*, const char*);

int main() {
    strcmp_ptr_t strcmp_ptr = strcmp;
    if (!strcmp_ptr("hello", "hello")) {
        printf("Hello World\n");
    }
}
