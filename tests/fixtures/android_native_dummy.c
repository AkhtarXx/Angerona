#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("default")))
int Java_com_example_dummy_Native_add(void *env, void *clazz, int left, int right) {
    (void)env;
    (void)clazz;
    return left + right;
}

__attribute__((visibility("default")))
uint32_t dummy_checksum(const uint8_t *data, size_t size) {
    uint32_t value = 2166136261u;
    for (size_t index = 0; index < size; ++index) {
        value = (value ^ data[index]) * 16777619u;
    }
    return value;
}
