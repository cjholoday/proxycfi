
#include <stdlib.h>
#include <time.h>

int add(int x, int y) {
    return x + y;
}

int multiply(int x, int y) {
    return x * y;
}

int subtract(int x, int y) {
    return x - y;
}


int divide(int x, int y) {
    return x / y;
}

int main() {
    srand(time(NULL));
    for (int i = 0; i < 3000; i++) {
        int function_to_call = rand() % 4;
        if (function_to_call == 0) {
            add(3, 5);
        }
        else if (function_to_call == 0) {
            multiply(3, 5);
        }
        else if (function_to_call == 0) {
            subtract(3, 5);
        }
        else if (function_to_call == 0) {
            divide(3, 5);
        }
    }

}
