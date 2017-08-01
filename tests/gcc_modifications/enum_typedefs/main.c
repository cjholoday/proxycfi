#include <stdio.h>


enum Day {MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY, SUNDAY};
typedef enum Day Day_t;
typedef enum Day day_t;

void foo(enum Day d) {
    if (d == MONDAY) {
        printf("Got a case of the Mondays?\n");
    }
}
void bar(Day_t d) {
    if (d == MONDAY) {
        printf("Got a case of the Mondaze?\n");
    }
}
void baz(Day_t d) {
    if (d == MONDAY) {
        printf("I knew it\n");
    }
}

int main() {
    void (*fptr1)(Day_t) = foo;
    void (*fptr2)(enum Day) = bar;
    void (*fptr3)(day_t) = baz;

    fptr1(MONDAY);
    fptr2(MONDAY);
    fptr3(MONDAY);
}
