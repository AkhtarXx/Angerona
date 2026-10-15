/* Reproducible static-analysis fixture. Do not execute with oversized input.
 * Build: gcc -O0 -g -fno-builtin -fno-stack-protector -no-pie crackme.c -o crackme
 */
#include <stdio.h>
#include <string.h>

int add(int a, int b) { return a + b; }

int main(int argc, char **argv) {
    char buffer[32];
    if (argc != 2) {
        puts("usage: crackme INPUT");
        return 2;
    }
    strcpy(buffer, argv[1]);
    puts(strcmp(buffer, "test-input") == 0 ? "accepted" : "rejected");
    return 0;
}
