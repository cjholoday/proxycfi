
int add(int x, int y) {
    return x + y;
}

int multiply(int x, int y) {
    return x * y;
}

int subtract(int x, int y) {
    return add(x, multiply(-1, y));
}


static int divide(int x, int y) {
    return x / y;
}

int main() {
    add(1, 2);
    subtract(3, 5);
    divide(1, 2);
    multiply(2, 2);
}
