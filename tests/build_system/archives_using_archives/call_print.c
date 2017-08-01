extern void print(char *str);

void call_print(char *str) {
    void (*oper)(char *) = print;
    oper(str);
}
