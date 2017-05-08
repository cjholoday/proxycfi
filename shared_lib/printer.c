#include <stdio.h>
#include <string.h>

/*
 * print message out in format:
 *      "[word1] [word2] ... [word n] ([num letters])"
 */
void print_message(char **message, int num_words) {
    int total_letters = 0;

    for (int i = 0; i < num_words; i++) {
        total_letters += strlen(message[i]) + 1; //+1 for the space
        printf("%s ", message[i]);
    }

    printf("(total letters: %d)\n", total_letters);
}
