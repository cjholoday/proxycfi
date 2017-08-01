int add(int x, int y) {
    return x + y;
}

int subtract(int x, int y) {
    return x - y;
}

int multiply(int x, int y) {
    return x * y;
}

int divide(int x, int y) {
    return x / y;
}

int main() {
    int (*calc_oper)(int, int) = add;
    calc_oper(1, 2);
}
