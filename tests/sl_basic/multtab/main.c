#include "sl1.h"
void sl2_call_sl1_foo();

int main() {
    sl1_foo();
    sl1_bar();
    sl1_qux();

    sl2_call_sl1_foo();
    sl1_qux();
    sl1_qux();
}

