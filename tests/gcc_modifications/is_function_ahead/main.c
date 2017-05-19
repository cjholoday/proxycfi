#include <stdio.h>

int main() {
    add(1, 2);
    (add)(1, 2);
    ((add))(1, 2);
    ((add)) (1, 2);

    ( 
     (
      add
     )  
    ) 
        (
         1, 2
        );


    printf("Hello World\n");
}

int add(int x, int y) {
    return x + y;
}

int multiply(int x, int y) {
    return x * y;
}
