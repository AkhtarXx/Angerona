#include <stddef.h>

typedef int (*operation)(int);
static int add_one(int value) { return value + 1; }
static int sub_one(int value) { return value - 1; }

int dispatch(unsigned selector, int value) {
    operation table[] = {add_one, sub_one};
    if (selector < 2) return table[selector](value);
    switch (selector) {
        case 7: return value * 4;
        case 9: return value ^ 0x55;
        default: return -1;
    }
}

int main(int argc, char **argv) {
    return dispatch((unsigned)argc, argv != NULL ? argc : 0);
}
