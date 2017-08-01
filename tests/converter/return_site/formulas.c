#ifndef FORMULAS_H
#define FORMULAS_H

#include "calc.h"

int area_square(int s) {
    return multiply(s, s);
}

int area_rectangle(int l, int w) {
    return multiply(l, w);
}

int area_circle(int r) {
    return multiply(multiply(r, r), 3.14);
}

static int fibonacci_helper(int terms_left, int prev1, int prev2) {
    if (!terms_left) {
        return prev2;
    }
    return fibonacci_helper(subtract(terms_left, 1), prev2, add(prev1, prev2));
}

/*
 * The first term here is 1:
 *      1, 1, 2, 3, 5, ...
 */
int nth_fibonacci(int term_num) {
    if (term_num <= 2) {
        return 1;
    }
    else {
        return fibonacci_helper(subtract(term_num, 2), 1, 1);
    }
}
#endif
