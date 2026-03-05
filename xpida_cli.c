/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xpida_cli - userspace client for xpida KPM
 *
 * Communicates with the xpida KPM via hooked syscall (userfaultfd #282).
 * No superkey, no device file, no ioctl. Just needs root (uid 0).
 *
 * Usage: xpida_cli <cmd> [args]
 *
 * Commands:
 *   ping, ps, find <name>, maps <pid>,
 *   read <pid> <hex_addr> <size>,
 *   dump <pid> <hex_start> <hex_end>
 *
 * Binary commands (read/dump) output raw bytes to stdout.
 * Text commands output text to stdout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>

#define XPIDA_NR     282
#define XPIDA_MAGIC  0x7870696461ULL

#define MAX_TEXT_BUF  (512 * 1024)
#define MAX_BIN_BUF   (64 * 1024 * 1024 + 4096)

static int is_binary_cmd(const char *cmd)
{
    return strcmp(cmd, "read") == 0 || strcmp(cmd, "dump") == 0;
}

static int build_ctl_args(char *out, int outsz, int argc, char **argv, int ci)
{
    if (strcmp(argv[ci], "ping") == 0) {
        snprintf(out, outsz, "ping");
    } else if (strcmp(argv[ci], "ps") == 0) {
        snprintf(out, outsz, "ps");
    } else if (strcmp(argv[ci], "find") == 0 && ci + 1 < argc) {
        snprintf(out, outsz, "find %s", argv[ci + 1]);
    } else if (strcmp(argv[ci], "maps") == 0 && ci + 1 < argc) {
        snprintf(out, outsz, "maps %s", argv[ci + 1]);
    } else if (strcmp(argv[ci], "read") == 0 && ci + 3 < argc) {
        snprintf(out, outsz, "read %s %s %s",
                 argv[ci + 1], argv[ci + 2], argv[ci + 3]);
    } else if (strcmp(argv[ci], "dump") == 0 && ci + 3 < argc) {
        snprintf(out, outsz, "dump %s %s %s",
                 argv[ci + 1], argv[ci + 2], argv[ci + 3]);
    } else {
        fprintf(stderr, "Unknown command or missing args: %s\n", argv[ci]);
        return -1;
    }
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s <cmd> [args]\n"
        "\nCommands:\n"
        "  ping, ps, find <name>, maps <pid>\n"
        "  read <pid> <hex_addr> <size>\n"
        "  dump <pid> <hex_start> <hex_end>\n",
        prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];
    int binary = is_binary_cmd(cmd);
    int buflen = binary ? MAX_BIN_BUF : MAX_TEXT_BUF;

    char *buf = (char *)mmap(NULL, buflen, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    buf[0] = '\0';

    char ctl_args[512];
    if (build_ctl_args(ctl_args, sizeof(ctl_args), argc, argv, 1) != 0) {
        munmap(buf, buflen);
        return 1;
    }

    long rc = syscall(XPIDA_NR, XPIDA_MAGIC, ctl_args, buf, (long)buflen);

    if (binary) {
        long nbytes = rc > 0 ? rc : 0;
        if (nbytes > 0)
            fwrite(buf, 1, nbytes, stdout);
    } else {
        if (buf[0])
            fputs(buf, stdout);
    }

    if (rc < 0)
        fprintf(stderr, "error: rc=%ld\n", rc);

    munmap(buf, buflen);
    return rc < 0 ? 1 : 0;
}
