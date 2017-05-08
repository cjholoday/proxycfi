#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern void print_message(char** message, int num_words);

int main() {
    char* message[4];

    char* word1 = "CDI";
    char* word2 = "is";
    char* word3 = "utterly";
    char* word4 = "unstoppable";
    char* header = "Important reminder:";

    printf("%s\n", header);

    message[0] = malloc(strlen(word1));
    message[1] = malloc(strlen(word2));
    message[2] = malloc(strlen(word3));
    message[3] = malloc(strlen(word4));

    strcpy(message[0], word1);
    strcpy(message[1], word2);
    strcpy(message[2], word3);
    strcpy(message[3], word4);

    print_message(message, 4);
}


