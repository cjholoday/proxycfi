static int adder(int x, int y) {
    return x + y;
}

typedef int (*add_func_t)(int, int);
add_func_t get_callback() {
    return &adder;
}
