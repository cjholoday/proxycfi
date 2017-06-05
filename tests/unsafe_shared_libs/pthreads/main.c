/* DESCRIPTION:
 *   A "hello world" Pthreads program.  Demonstrates thread creation and
 *   termination.
 * AUTHOR: Blaise Barney
 * LAST REVISED: 08/09/11
 * Taken from https://computing.llnl.gov/tutorials/pthreads/
 ******************************************************************************/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define NUM_THREADS	5

pthread_once_t  once_control = PTHREAD_ONCE_INIT;                               

void *PrintHello(void *threadid) {
    long tid;
    tid = (long)threadid;
    printf("Hello World! It's me, thread #%ld!\n", tid);
    pthread_exit(NULL);
}

void hello_init() {
    printf("Hello World!\n");
}

int main(int argc, char *argv[]) {
    pthread_once(&once_control, hello_init);
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;
    for(t=0;t<NUM_THREADS;t++){
        printf("In main: creating thread %ld\n", t);
        rc = pthread_create(&threads[t], NULL, PrintHello, (void *)t);
        if (rc){
            printf("ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
    }

    /* Last thing that main() should do */
    pthread_exit(NULL);
}

