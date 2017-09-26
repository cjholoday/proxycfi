#include <stdio.h>

extern void target1(const char *, int);
extern void target2(const char *, int);
extern void target3(const char *, int);

extern void target666(const char *, int);
extern void target1234(const char *, int);

void foo() {
    void (*fp)(const char *, int) = target1234;
    fp("good job", 1234);

    fp = target2;
    fp("good job", 2);

    fp = target3;
    fp("good job", 3);
}

void bar() {
    void (*fp)(const char *, int) = target1234;
    fp("good job", 1234);

    fp = target2;
    fp("good job", 2);

    fp = target3;
    fp("good job", 3);
}
int main() {
    target1("hello world", 1);
    target2("hello world", 2);

    void (*fp)(const char *, int) = target666;
    fp("good luck", 6);

    foo();
    bar();
}

