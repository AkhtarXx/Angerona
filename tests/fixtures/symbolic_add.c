__attribute__((noinline)) long symbolic_add(long left, long right) {
    if (left == 7) {
        return right + 11;
    }
    return left + right;
}

int main(void) {
    return (int)symbolic_add(1, 2);
}
