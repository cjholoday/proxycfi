#include <stdio.h>
#include <signal.h>
#include <pthread.h>

void segfault() {
    raise(SIGSEGV);
}

void catch() {
    printf("%s", "Caught segfault\n");
}

void *hello(void *unused) {
    printf("Hello World!\n");
    sleep(1);
}

int main() {
    pthread_t hello_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    void *status;

    pthread_create(&hello_thread, &attr, hello, NULL);
    pthread_attr_destroy(&attr);
    pthread_join(hello_thread, &status);
    pthread_exit(NULL);

    signal(SIGSEGV, catch);
}


