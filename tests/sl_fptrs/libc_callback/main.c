#include <stdlib.h>
#include <stdio.h>

int int_comp(const void *val1, const void *val2) {
    int v1 = *((int*)val1);
    int v2 = *((int*)val2);

    return (v1 > v2) - (v1 < v2);
}
int main() {
    int arr[] = {6, 3, 1, 2, 5, 4, 2, 0};

    qsort(arr, sizeof(arr)/sizeof(*arr), sizeof(*arr), int_comp);

    printf("{ ");
    for (int i = 0; i < sizeof(arr)/sizeof(*arr); i++) {
        printf("%d ", arr[i]);
    }
    printf("}\n");
}

    

