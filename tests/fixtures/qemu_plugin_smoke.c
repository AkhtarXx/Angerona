#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define QEMU_PLUGIN_EXPORT __attribute__((visibility("default")))
#define QEMU_PLUGIN_VERSION 5

typedef uint64_t qemu_plugin_id_t;

typedef struct qemu_info_t {
    const char *target_name;
    struct {
        int min;
        int cur;
    } version;
    bool system_emulation;
    union {
        struct {
            int smp_vcpus;
            int max_vcpus;
        } system;
    };
} qemu_info_t;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(
    qemu_plugin_id_t id,
    const qemu_info_t *info,
    int argc,
    char **argv
) {
    (void)id;
    (void)argc;
    (void)argv;
    fprintf(
        stderr,
        "ANGERONA_QEMU_PLUGIN_LOADED target=%s system=%d api=%d\n",
        info->target_name,
        info->system_emulation,
        info->version.cur
    );
    fflush(stderr);
    return 0;
}
