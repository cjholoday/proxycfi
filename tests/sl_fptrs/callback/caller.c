int call_it(int (*oper)(int, int), int arg1, int arg2) {
    return oper(arg1, arg2);
}
