/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xpida_cli - userspace client for xpida KPM
 *
 * Usage:
 *   xpida_cli <superkey> ping
 *   xpida_cli <superkey> find <name>
 *   xpida_cli <superkey> maps <pid>
 *   xpida_cli <superkey> read <pid> <hex_addr> <size>
 *
 * Build (with Android NDK):
 *   aarch64-linux-android21-clang -o xpida_cli xpida_cli.c -I../../user -I../../kernel/patch/include
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <errno.h>

#include "../../kernel/patch/include/uapi/scdefs.h"

#ifndef MAJOR
#define MAJOR 0
#define MINOR 10
#define PATCH 7
#endif

static inline long ver_and_cmd(const char *key, long cmd)
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

static long kpm_control(const char *key, const char *name,
                        const char *ctl_args, char *out, long outlen)
{
    return syscall(__NR_supercall, key, ver_and_cmd(key, SUPERCALL_KPM_CONTROL),
                   name, ctl_args, out, outlen);
}

static void print_hex(const char *buf, int len)
{
    for (int i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n");
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <superkey> <command> [args...]\n"
                        "Commands:\n"
                        "  ping\n"
                        "  find <name>\n"
                        "  maps <pid>\n"
                        "  read <pid> <hex_addr> <size>\n", argv[0]);
        return 1;
    }

    const char *key = argv[1];
    const char *cmd = argv[2];

    char ctl_args[512];

    if (strcmp(cmd, "ping") == 0) {
        snprintf(ctl_args, sizeof(ctl_args), "ping");
    } else if (strcmp(cmd, "find") == 0 && argc >= 4) {
        snprintf(ctl_args, sizeof(ctl_args), "find %s", argv[3]);
    } else if (strcmp(cmd, "maps") == 0 && argc >= 4) {
        snprintf(ctl_args, sizeof(ctl_args), "maps %s", argv[3]);
    } else if (strcmp(cmd, "read") == 0 && argc >= 6) {
        snprintf(ctl_args, sizeof(ctl_args), "read %s %s %s", argv[3], argv[4], argv[5]);
    } else {
        fprintf(stderr, "Unknown command or missing arguments\n");
        return 1;
    }

    int is_read = (strcmp(cmd, "read") == 0);
    int buflen = is_read ? (64 * 4096 + 64) : (256 * 1024);

    char *buf = calloc(1, buflen);
    if (!buf) { perror("calloc"); return 1; }

    long rc = kpm_control(key, "xpida", ctl_args, buf, buflen);

    if (is_read && rc > 0) {
        printf("Read %ld bytes:\n", rc);
        print_hex(buf, rc > 512 ? 512 : (int)rc);
    } else {
        printf("%s", buf);
    }

    if (rc < 0)
        fprintf(stderr, "(return code: %ld)\n", rc);

    free(buf);
    return rc < 0 ? 1 : 0;
}
