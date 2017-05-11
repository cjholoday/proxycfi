#include <stdio.h>

void print_helper() {
    print("Print Helper\n");
}

int main() {
    print("Hello World\n");
    print_helper();
}

