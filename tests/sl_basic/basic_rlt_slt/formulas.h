#ifndef FORMULAS_H
#define FORMULAS_H

#include "calc.h"

int area_square(int s);
int area_rectangle(int l, int w);
int area_circle(int r);
static int fibonacci_helper(int terms_left, int prev1, int prev2);
int nth_fibonacci(int term_num);

#endif
