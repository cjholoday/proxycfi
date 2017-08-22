static int hidden_call_it(int (*oper)(int, int), int arg1, int arg2) {
    return oper(arg1, arg2);
}

int call_it(int (*oper)(int, int), int arg1, int arg2) {
    int (*hidden_funct)(int (*)(int, int), int, int) = &hidden_call_it;
    return hidden_funct(oper, arg1, arg2);
}
