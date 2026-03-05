/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xpida_cli - userspace client for xpida KPM
 *
 * Usage:
 *   xpida_cli <cmd> [args]                 # ioctl mode (SuKiSU)
 *   xpida_cli -s <superkey> <cmd> [args]   # supercall mode
 *   xpida_cli result                        # read text result file
 *   xpida_cli result.bin                    # read binary result file (hex dump)
 *
 * Commands: ping, find <name>, maps <pid>, read <pid> <hex_addr> <size>
 *
 * Environment:
 *   KSU_DEV=<path>   override KSU device path (default: auto-detect)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <errno.h>

#include "../../kernel/patch/include/uapi/scdefs.h"

#define OUTPUT_PATH     "/data/local/tmp/xpida_result"
#define OUTPUT_PATH_BIN "/data/local/tmp/xpida_result.bin"

/* SuKiSU ioctl: _IOWR('K', 200, ()) with size=0 => 0xC0004BC8 */
#define KSU_IOCTL_KPM  0xC0004BC8
#define KPM_CONTROL     6

struct ksu_kpm_cmd {
    uint64_t control_code;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t result_code;
};

/* ---- ioctl mode (SuKiSU) ---- */

static int open_ksu_dev(void)
{
    const char *env = getenv("KSU_DEV");
    if (env) {
        int fd = open(env, O_RDWR);
        if (fd >= 0) return fd;
        fprintf(stderr, "Cannot open KSU_DEV=%s: %s\n", env, strerror(errno));
        return -1;
    }
    static const char *paths[] = {
        "/dev/ksu", "/dev/kernelsu", "/dev/sukisu", NULL
    };
    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDWR);
        if (fd >= 0) return fd;
    }
    fprintf(stderr, "Cannot open KSU device (tried /dev/ksu /dev/kernelsu /dev/sukisu)\n"
                    "Set KSU_DEV=<path> to override\n");
    return -1;
}

static int ioctl_control(const char *name, const char *args)
{
    int fd = open_ksu_dev();
    if (fd < 0) return -1;

    int ret = -1;
    struct ksu_kpm_cmd cmd = {
        .control_code = KPM_CONTROL,
        .arg1 = (uint64_t)(uintptr_t)name,
        .arg2 = (uint64_t)(uintptr_t)args,
        .result_code = (uint64_t)(uintptr_t)&ret,
    };

    if (ioctl(fd, KSU_IOCTL_KPM, &cmd) < 0) {
        fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return ret;
}

/* ---- supercall mode ---- */

#ifndef MAJOR
#define MAJOR 0
#define MINOR 10
#define PATCH 7
#endif

static inline long ver_and_cmd(long cmd)
{
    uint32_t vc = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)vc << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

static long supercall_control(const char *key, const char *name,
                              const char *args, char *out, long outlen)
{
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_CONTROL),
                   name, args, out, outlen);
}

/* ---- result file reading ---- */

static int read_result_file(const char *path, int as_hex)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "No result file: %s (%s)\n", path, strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }

    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return -1; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    if (as_hex) {
        printf("Read %ld bytes:\n", sz);
        long show = sz > 512 ? 512 : sz;
        for (long i = 0; i < show; i++) {
            if (i > 0 && i % 16 == 0) printf("\n");
            printf("%02x ", (unsigned char)buf[i]);
        }
        if (sz > 512) printf("\n... (%ld more bytes)", sz - 512);
        printf("\n");
    } else {
        printf("%s", buf);
    }

    free(buf);
    return 0;
}

/* ---- build ctl_args string from argv ---- */

static int build_ctl_args(char *out, int outsz, int argc, char **argv, int cmd_idx)
{
    const char *cmd = argv[cmd_idx];

    if (strcmp(cmd, "ping") == 0) {
        snprintf(out, outsz, "ping");
    } else if (strcmp(cmd, "find") == 0 && cmd_idx + 1 < argc) {
        snprintf(out, outsz, "find %s", argv[cmd_idx + 1]);
    } else if (strcmp(cmd, "maps") == 0 && cmd_idx + 1 < argc) {
        snprintf(out, outsz, "maps %s", argv[cmd_idx + 1]);
    } else if (strcmp(cmd, "read") == 0 && cmd_idx + 3 < argc) {
        snprintf(out, outsz, "read %s %s %s",
                 argv[cmd_idx + 1], argv[cmd_idx + 2], argv[cmd_idx + 3]);
    } else {
        fprintf(stderr, "Unknown command or missing args: %s\n", cmd);
        return -1;
    }
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s <cmd> [args]                 ioctl mode (SuKiSU)\n"
        "  %s -s <superkey> <cmd> [args]   supercall mode\n"
        "  %s result                        read text result\n"
        "  %s result.bin                    read binary result\n"
        "\nCommands: ping, find <name>, maps <pid>, read <pid> <addr> <size>\n",
        prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    /* read result files */
    if (strcmp(argv[1], "result") == 0)
        return read_result_file(OUTPUT_PATH, 0);
    if (strcmp(argv[1], "result.bin") == 0)
        return read_result_file(OUTPUT_PATH_BIN, 1);

    /* supercall mode: -s <key> <cmd> ... */
    if (strcmp(argv[1], "-s") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        const char *key = argv[2];

        char ctl_args[512];
        if (build_ctl_args(ctl_args, sizeof(ctl_args), argc, argv, 3) != 0)
            return 1;

        int is_read = (strcmp(argv[3], "read") == 0);
        int buflen = is_read ? (64 * 4096 + 64) : (256 * 1024);
        char *buf = (char *)calloc(1, buflen);
        if (!buf) { perror("calloc"); return 1; }

        long rc = supercall_control(key, "xpida", ctl_args, buf, buflen);

        if (buf[0]) {
            if (is_read && rc > 0) {
                printf("Read %ld bytes:\n", rc);
                long show = rc > 512 ? 512 : rc;
                for (long i = 0; i < show; i++) {
                    if (i > 0 && i % 16 == 0) printf("\n");
                    printf("%02x ", (unsigned char)buf[i]);
                }
                printf("\n");
            } else {
                printf("%s", buf);
            }
        } else {
            read_result_file(is_read ? OUTPUT_PATH_BIN : OUTPUT_PATH, is_read);
        }

        if (rc < 0) fprintf(stderr, "(rc: %ld)\n", rc);
        free(buf);
        return rc < 0 ? 1 : 0;
    }

    /* ioctl mode: <cmd> [args] */
    char ctl_args[512];
    if (build_ctl_args(ctl_args, sizeof(ctl_args), argc, argv, 1) != 0)
        return 1;

    int is_read = (strcmp(argv[1], "read") == 0);
    int rc = ioctl_control("xpida", ctl_args);
    fprintf(stderr, "rc: %d\n", rc);

    read_result_file(is_read ? OUTPUT_PATH_BIN : OUTPUT_PATH, is_read);
    return rc < 0 ? 1 : 0;
}
