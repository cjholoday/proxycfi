#ifndef ADD_H
#define ADD_H

int add(int x, int y);
int add_char1(char x, int y);
int add_char2(int x, char y);

typedef int (*i_ii)(int, int);
typedef int (*i_ci)(char, int);
typedef int (*i_ic)(int, char);

i_ii add_callback(void);
i_ci add_char1_callback(void);
i_ic add_char2_callback(void);

#endif
