#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "list.h"

int int_equal(int x, int y) {
    return x == y;
}
int int_not_equal(int x, int y) {
    return x != y;
}

int int_ptr_equal(void *x, void *y) {
    return *(int*)x == *(int*)y;
}
int int_ptr_not_equal(void *x, void *y) {
    return *(int*)x != *(int*)y;
}

int main() {
    ListEntry *list = LIST_NULL;

    int val1 = 1;
    int val2 = 2;
    int val3 = 3;
    int val4 = 4;
    list_append(&list, &val2);
    list_append(&list, &val3);
    list_append(&list, &val4);
    list_prepend(&list, &val1);

    assert(list_nth_data(list, 2) == &val3);
    assert(list_length(list) == 4);

    int val5 = 4;
    assert((int*)list_data(list_find_data(list, int_ptr_equal, &val5)) == &val4);
    list_remove_data(&list, int_ptr_equal, &val4);
}

