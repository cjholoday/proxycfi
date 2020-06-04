#ifndef DO_ADD_H
#define DO_ADD_H

typedef int (*i_ii)(int, int);
typedef int (*i_ci)(char, int);
typedef int (*i_ic)(int, char);

int do_add(int x, int y, i_ii);
int do_add_char1(char x, int y, i_ci);
int do_add_char2(int x, char y, i_ic);
int do_main_add(int x, int y, i_ii);

#endif 
