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
 *   ping, ps, psx, find <name>, maps <pid>,
 *   read <pid> <hex_addr> <size>,
 *   dump <pid> <hex_start> <hex_end>
 *
 * Binary commands (read/dump) output raw bytes to stdout.
 * Text commands output text to stdout.
 * dump auto-chunks ranges > 64MB internally.
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
#define DUMP_CHUNK    (64ULL * 1024 * 1024)

static int is_binary_cmd(const char *cmd)
{
    return strcmp(cmd, "read") == 0;
}

static int do_chunked_dump(int pid, uint64_t start, uint64_t end)
{
    int buflen = (int)DUMP_CHUNK + 4096;
    char *buf = (char *)mmap(NULL, buflen, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    uint64_t cur = start;
    long total = 0;
    int seq = 0;

    while (cur < end) {
        uint64_t nxt = cur + DUMP_CHUNK;
        if (nxt > end) nxt = end;

        char ctl[256];
        snprintf(ctl, sizeof(ctl), "dump %d %llx %llx",
                 pid, (unsigned long long)cur, (unsigned long long)nxt);

        long rc = syscall(XPIDA_NR, XPIDA_MAGIC, ctl, buf, (long)buflen);

        uint64_t expect = nxt - cur;
        fprintf(stderr, "[%d] %llx-%llx  %ld/%llu bytes\n",
                seq, (unsigned long long)cur, (unsigned long long)nxt,
                rc > 0 ? rc : 0, (unsigned long long)expect);

        if (rc > 0) {
            fwrite(buf, 1, rc, stdout);
            total += rc;
        }
        if (rc <= 0) break;

        cur = nxt;
        seq++;
    }

    fprintf(stderr, "done: %d chunks, %ld bytes\n", seq, total);
    munmap(buf, buflen);
    return total > 0 ? 0 : 1;
}

static int build_ctl_args(char *out, int outsz, int argc, char **argv, int ci)
{
    if (strcmp(argv[ci], "ping") == 0) {
        snprintf(out, outsz, "ping");
    } else if (strcmp(argv[ci], "ps") == 0) {
        snprintf(out, outsz, "ps");
    } else if (strcmp(argv[ci], "psx") == 0) {
        snprintf(out, outsz, "psx");
    } else if (strcmp(argv[ci], "find") == 0 && ci + 1 < argc) {
        snprintf(out, outsz, "find %s", argv[ci + 1]);
    } else if (strcmp(argv[ci], "maps") == 0 && ci + 1 < argc) {
        snprintf(out, outsz, "maps %s", argv[ci + 1]);
    } else if (strcmp(argv[ci], "read") == 0 && ci + 3 < argc) {
        snprintf(out, outsz, "read %s %s %s",
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
        "  ping, ps, psx, find <name>, maps <pid>\n"
        "  read <pid> <hex_addr> <size>\n"
        "  dump <pid> <hex_start> <hex_end>\n",
        prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "dump") == 0) {
        if (argc < 5) { usage(argv[0]); return 1; }
        int pid = atoi(argv[2]);
        uint64_t start = strtoull(argv[3], NULL, 16);
        uint64_t end   = strtoull(argv[4], NULL, 16);
        if (pid <= 0 || end <= start) {
            fprintf(stderr, "bad args: pid=%d start=%llx end=%llx\n",
                    pid, (unsigned long long)start, (unsigned long long)end);
            return 1;
        }
        return do_chunked_dump(pid, start, end);
    }

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
