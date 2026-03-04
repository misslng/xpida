/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 xpida. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm_types.h>
#include <linux/kernel.h>
#include <asm/current.h>
#include <log.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <pgtable.h>

KPM_NAME("xpida");
KPM_VERSION("0.4.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("xpida");
KPM_DESCRIPTION("xpida Process Memory Tool");

#define MAX_PROCESSES   4000
#define MAX_VMAS        65536
#define MAX_READ_SIZE   (4096 * 64)
#define MAPS_BUF_SIZE   (256 * 1024)
#define PAGE_SZ         4096

#define VM_READ         0x00000001UL
#define VM_WRITE        0x00000002UL
#define VM_EXEC         0x00000004UL
#define VM_SHARED       0x00000008UL
#define F_PATH_OFF      16
#define FOLL_FORCE      0x10

/* ---- Global state ---- */

static int g_ready;

static struct task_struct *g_init_task;
static int16_t g_tasks_off;
static int16_t g_comm_off;
static int16_t g_pid_off;
static int16_t g_mm_off;
static int16_t g_pgd_off;
static int16_t g_mmap_off     = -1;
static int16_t g_vm_flags_off = -1;
static int16_t g_vm_file_off  = -1;
static int16_t g_vm_pgoff_off = -1;

static uint64_t g_linear_voffset;

static void *(*fn_vmalloc)(unsigned long size);
static void (*fn_vfree)(const void *addr);
static void (*fn_rcu_lock)(void);
static void (*fn_rcu_unlock)(void);
static char *(*fn_d_path)(const void *path, char *buf, int buflen);
static int (*fn_access_process_vm)(void *tsk, unsigned long addr, void *buf, int len, unsigned int gup);

/* ---- Safe memory access ---- */

static long (*safe_copy)(void *dst, const void *src, size_t size);

static int safe_read_ptr(uintptr_t addr, uintptr_t *out)
{
    if (safe_copy)
        return safe_copy(out, (const void *)addr, sizeof(*out)) ? -1 : 0;
    *out = *(volatile uintptr_t *)addr;
    return 0;
}

static int safe_read_buf(uintptr_t addr, void *buf, size_t len)
{
    if (safe_copy)
        return safe_copy(buf, (const void *)addr, len) ? -1 : 0;
    __builtin_memcpy(buf, (const void *)addr, len);
    return 0;
}

/* ---- Offset helpers ---- */

static int16_t probe_tasks_offset(void)
{
    uintptr_t base = (uintptr_t)g_init_task;
    for (int off = 64; off < 1300; off += 8) {
        uintptr_t head = base + off;
        uintptr_t next = *(uintptr_t *)head;
        uintptr_t prev = *(uintptr_t *)(head + 8);
        if (next < 0xffff000000000000ULL || prev < 0xffff000000000000ULL) continue;
        if (next == head) continue;
        uintptr_t back = 0;
        if (safe_read_ptr(next + 8, &back) != 0 || back != head) continue;
        char buf[16] = { 0 };
        if (safe_read_buf(next - off + g_comm_off, buf, 16) != 0) continue;
        buf[15] = '\0';
        for (int i = 0; i < 15 && buf[i]; i++)
            if (buf[i] >= 0x20 && buf[i] <= 0x7e) return (int16_t)off;
    }
    return -1;
}

static int16_t probe_pid_offset(void)
{
    uintptr_t head = (uintptr_t)g_init_task + g_tasks_off;
    uintptr_t p1 = 0, p2 = 0;
    if (safe_read_ptr(head, &p1) != 0 || safe_read_ptr(p1, &p2) != 0) return -1;
    uintptr_t t1 = p1 - g_tasks_off, t2 = p2 - g_tasks_off;
    for (int off = 0; off < g_comm_off; off += 4) {
        int32_t v0 = -1, v1 = -1, v2 = -1;
        safe_read_buf((uintptr_t)g_init_task + off, &v0, 4);
        safe_read_buf(t1 + off, &v1, 4);
        safe_read_buf(t2 + off, &v2, 4);
        if (v0 == 0 && v1 == 1 && v2 == 2) return (int16_t)off;
    }
    return -1;
}

static void probe_vma_offsets(uintptr_t mm_addr)
{
    for (int off = 0; off < 64; off += 8) {
        uintptr_t vma = 0;
        if (safe_read_ptr(mm_addr + off, &vma) != 0) continue;
        if (vma < 0xffff000000000000ULL) continue;
        uintptr_t vs = 0, ve = 0;
        safe_read_ptr(vma, &vs);
        safe_read_ptr(vma + 8, &ve);
        if (vs > 0 && vs < 0x800000000000ULL && ve > vs) {
            g_mmap_off = off;
            break;
        }
    }
    if (g_mmap_off < 0) return;

    uintptr_t first = 0;
    safe_read_ptr(mm_addr + g_mmap_off, &first);
    if (!first) return;

    for (int off = 64; off < 160; off += 8) {
        uintptr_t v = 0;
        safe_read_ptr(first + off, &v);
        if (v > 0 && v < 0x100000000ULL && (v & VM_READ)) {
            g_vm_flags_off = off;
            break;
        }
    }

    for (int off = 128; off < 208; off += 8) {
        int has_null = 0, has_ptr = 0;
        uintptr_t vma = first;
        for (int i = 0; i < 20 && vma; i++) {
            uintptr_t v = 0;
            safe_read_ptr(vma + off, &v);
            if (v == 0) has_null = 1;
            else if (v >= 0xffff000000000000ULL) has_ptr = 1;
            uintptr_t nx = 0;
            safe_read_ptr(vma + 16, &nx);
            vma = (nx >= 0xffff000000000000ULL) ? nx : 0;
        }
        if (has_null && has_ptr) {
            g_vm_file_off = off;
            g_vm_pgoff_off = off - 8;
            break;
        }
    }
}

static void compute_linear_voffset(void)
{
    uintptr_t init_mm_sym = kallsyms_lookup_name("init_mm");
    if (!init_mm_sym) return;
    uintptr_t init_mm = *(uintptr_t *)init_mm_sym;
    if (!init_mm) return;

    uintptr_t kern_pgd = 0;
    safe_read_ptr(init_mm + g_pgd_off, &kern_pgd);
    if (kern_pgd < 0xffff000000000000ULL) return;

    /*
     * Use a stack variable address (guaranteed in linear mapping on arm64)
     * to compute linear_voffset = VA - PA.
     */
    volatile uint64_t anchor = 0xdeadbeef;
    uint64_t va = (uint64_t)&anchor;
    uint64_t pa = pgtable_phys(kern_pgd, va);
    if (pa) {
        g_linear_voffset = va - pa;
        pr_info("[xpida] linear_voffset: %llx\n", (unsigned long long)g_linear_voffset);
    }
}

static int resolve_offsets(void)
{
    g_init_task = (struct task_struct *)kallsyms_lookup_name("init_task");
    if (!g_init_task) { pr_err("[xpida] init_task not found\n"); return -1; }

    g_comm_off = task_struct_offset.comm_offset;
    if (g_comm_off <= 0) { pr_err("[xpida] comm_offset failed\n"); return -1; }

    g_tasks_off = task_struct_offset.tasks_offset;
    if (g_tasks_off <= 0) g_tasks_off = probe_tasks_offset();
    if (g_tasks_off <= 0) { pr_err("[xpida] tasks_offset failed\n"); return -1; }

    g_pid_off = task_struct_offset.pid_offset;
    if (g_pid_off <= 0) g_pid_off = probe_pid_offset();

    int16_t amm = task_struct_offset.active_mm_offset;
    g_mm_off = task_struct_offset.mm_offset;
    if (g_mm_off <= 0 && amm > 8) g_mm_off = amm - 8;
    if (g_mm_off <= 0) { pr_err("[xpida] mm_offset failed\n"); return -1; }

    g_pgd_off = mm_struct_offset.pgd_offset;
    if (g_pgd_off <= 0) { pr_err("[xpida] pgd_offset failed\n"); return -1; }

    pr_info("[xpida] offsets: comm=%d tasks=%d pid=%d mm=%d pgd=%d\n",
            g_comm_off, g_tasks_off, g_pid_off, g_mm_off, g_pgd_off);

    compute_linear_voffset();

    uintptr_t pos = 0;
    safe_read_ptr((uintptr_t)g_init_task + g_tasks_off, &pos);
    int n = 0;
    while (pos && pos != (uintptr_t)g_init_task + g_tasks_off && n++ < 100) {
        uintptr_t task = pos - g_tasks_off;
        uintptr_t mm = 0;
        safe_read_ptr(task + g_mm_off, &mm);
        if (mm >= 0xffff000000000000ULL) {
            probe_vma_offsets(mm);
            break;
        }
        uintptr_t nxt = 0;
        if (safe_read_ptr(pos, &nxt) != 0) break;
        pos = nxt;
    }

    pr_info("[xpida] vma: mmap=%d flags=%d file=%d pgoff=%d\n",
            g_mmap_off, g_vm_flags_off, g_vm_file_off, g_vm_pgoff_off);
    return 0;
}

/* ---- Helper: find task by PID ---- */

static uintptr_t find_task_by_pid(int32_t target)
{
    uintptr_t init_head = (uintptr_t)g_init_task + g_tasks_off;
    uintptr_t pos = 0;
    if (safe_read_ptr(init_head, &pos) != 0) return 0;
    int count = 0;
    while (pos != init_head && count++ < MAX_PROCESSES) {
        uintptr_t task = pos - g_tasks_off;
        if (g_pid_off > 0) {
            int32_t pid = 0;
            safe_read_buf(task + g_pid_off, &pid, 4);
            if (pid == target) return task;
        }
        if (safe_read_ptr(pos, &pos) != 0) break;
    }
    return 0;
}

/* ---- cmd_find: find process by name ---- */

static long cmd_find(const char *name, char *__user out_msg, int outlen)
{
    if (!name || !name[0]) return -1;

    char *kbuf = fn_vmalloc(outlen);
    if (!kbuf) return -1;
    int off = 0, found = 0;

    uintptr_t init_head = (uintptr_t)g_init_task + g_tasks_off;
    uintptr_t pos = 0;
    int count = 0;

    if (fn_rcu_lock) fn_rcu_lock();
    if (safe_read_ptr(init_head, &pos) != 0) goto out;

    int nlen = 0;
    for (const char *p = name; *p; p++) nlen++;
    int cmplen = nlen < 15 ? nlen : 15;

    while (pos != init_head && count++ < MAX_PROCESSES) {
        uintptr_t task = pos - g_tasks_off;
        char comm[16] = { 0 };
        safe_read_buf(task + g_comm_off, comm, 16);
        comm[15] = '\0';

        int match = 1;
        for (int i = 0; i < cmplen; i++)
            if (comm[i] != name[i]) { match = 0; break; }

        if (match && (nlen <= 15 || comm[15] == '\0')) {
            int32_t pid = 0;
            if (g_pid_off > 0) safe_read_buf(task + g_pid_off, &pid, 4);
            if (off < outlen - 48)
                off += snprintf(kbuf + off, outlen - off, "%d:%s\n", pid, comm);
            found++;
        }
        if (safe_read_ptr(pos, &pos) != 0) break;
    }

out:
    if (fn_rcu_unlock) fn_rcu_unlock();
    if (!found && off < outlen - 16)
        off += snprintf(kbuf + off, outlen - off, "not_found\n");
    kbuf[off] = '\0';
    compat_copy_to_user(out_msg, kbuf, off + 1);
    fn_vfree(kbuf);
    return found > 0 ? 0 : -1;
}

/* ---- cmd_maps: dump process memory map ---- */

static void format_perms(unsigned long f, char *b)
{
    b[0] = (f & VM_READ)   ? 'r' : '-';
    b[1] = (f & VM_WRITE)  ? 'w' : '-';
    b[2] = (f & VM_EXEC)   ? 'x' : '-';
    b[3] = (f & VM_SHARED) ? 's' : 'p';
    b[4] = '\0';
}

static long cmd_maps(const char *args, char *__user out_msg, int outlen)
{
    int32_t pid = 0;
    if (sscanf(args, "%d", &pid) != 1 || pid <= 0) return -1;
    if (g_mmap_off < 0) return -1;

    uintptr_t task_addr = find_task_by_pid(pid);
    if (!task_addr) return -1;

    uintptr_t mm = 0;
    safe_read_ptr(task_addr + g_mm_off, &mm);
    if (mm < 0xffff000000000000ULL) return -1;

    int bsz = outlen < MAPS_BUF_SIZE ? outlen : MAPS_BUF_SIZE;
    char *kbuf = fn_vmalloc(bsz);
    if (!kbuf) return -1;
    int off = 0;
    char pathbuf[256];

    uintptr_t vma = 0;
    safe_read_ptr(mm + g_mmap_off, &vma);
    int vc = 0;

    if (fn_rcu_lock) fn_rcu_lock();

    while (vma >= 0xffff000000000000ULL && vc++ < MAX_VMAS) {
        uintptr_t vs = 0, ve = 0;
        safe_read_ptr(vma, &vs);
        safe_read_ptr(vma + 8, &ve);
        if (ve <= vs) break;

        unsigned long flags = 0;
        if (g_vm_flags_off > 0)
            safe_read_buf(vma + g_vm_flags_off, &flags, sizeof(flags));

        char perms[5];
        format_perms(flags, perms);

        unsigned long pgoff = 0;
        if (g_vm_pgoff_off > 0)
            safe_read_buf(vma + g_vm_pgoff_off, &pgoff, sizeof(pgoff));

        const char *path = "";
        if (g_vm_file_off > 0 && fn_d_path) {
            uintptr_t fp = 0;
            safe_read_ptr(vma + g_vm_file_off, &fp);
            if (fp >= 0xffff000000000000ULL) {
                uintptr_t mnt = 0, den = 0;
                safe_read_ptr(fp + F_PATH_OFF, &mnt);
                safe_read_ptr(fp + F_PATH_OFF + 8, &den);
                if (mnt >= 0xffff000000000000ULL && den >= 0xffff000000000000ULL) {
                    char *p = fn_d_path((const void *)(fp + F_PATH_OFF),
                                        pathbuf, sizeof(pathbuf));
                    if (p && (uintptr_t)p >= (uintptr_t)pathbuf &&
                        (uintptr_t)p < (uintptr_t)pathbuf + sizeof(pathbuf) && p[0] == '/')
                        path = p;
                }
            }
        }

        if (off < bsz - 128)
            off += snprintf(kbuf + off, bsz - off, "%lx-%lx %s %08lx %s\n",
                            vs, ve, perms, pgoff << 12, path);

        uintptr_t next = 0;
        safe_read_ptr(vma + 16, &next);
        vma = next;
    }

    if (fn_rcu_unlock) fn_rcu_unlock();

    kbuf[off] = '\0';
    compat_copy_to_user(out_msg, kbuf, off + 1);
    fn_vfree(kbuf);
    return 0;
}

/* ---- cmd_read: read process memory ---- */

static long cmd_read_via_apm(uintptr_t task_addr, unsigned long addr, int size,
                              char *__user out_msg, int outlen)
{
    char *kbuf = fn_vmalloc(size);
    if (!kbuf) return -1;
    int n = fn_access_process_vm((void *)task_addr, addr, kbuf, size, FOLL_FORCE);
    if (n > 0)
        compat_copy_to_user(out_msg, kbuf, n);
    fn_vfree(kbuf);
    return n > 0 ? n : -1;
}

static long cmd_read_via_phys(uintptr_t task_addr, unsigned long addr, int size,
                               char *__user out_msg, int outlen)
{
    if (!g_linear_voffset) return -1;

    uintptr_t mm = 0;
    safe_read_ptr(task_addr + g_mm_off, &mm);
    if (mm < 0xffff000000000000ULL) return -1;

    uintptr_t pgd = 0;
    safe_read_ptr(mm + g_pgd_off, &pgd);
    if (pgd < 0xffff000000000000ULL) return -1;

    char *kbuf = fn_vmalloc(size);
    if (!kbuf) return -1;

    int total = 0;
    unsigned long cur = addr;
    int rem = size;

    while (rem > 0) {
        int poff = cur & (PAGE_SZ - 1);
        int chunk = rem < (PAGE_SZ - poff) ? rem : (PAGE_SZ - poff);

        uint64_t pa = pgtable_phys(pgd, cur);
        if (!pa) {
            __builtin_memset(kbuf + total, 0, chunk);
        } else {
            uintptr_t kva = pa + g_linear_voffset;
            if (safe_read_buf(kva, kbuf + total, chunk) != 0)
                __builtin_memset(kbuf + total, 0, chunk);
        }

        cur += chunk;
        total += chunk;
        rem -= chunk;
    }

    compat_copy_to_user(out_msg, kbuf, total);
    fn_vfree(kbuf);
    return total;
}

static long cmd_read(const char *args, char *__user out_msg, int outlen)
{
    unsigned long addr = 0;
    int32_t pid = 0;
    int size = 0;

    if (sscanf(args, "%d %lx %d", &pid, &addr, &size) != 3) return -1;
    if (pid <= 0 || size <= 0) return -1;
    if (size > MAX_READ_SIZE) size = MAX_READ_SIZE;
    if (size > outlen) size = outlen;

    if (fn_rcu_lock) fn_rcu_lock();
    uintptr_t task_addr = find_task_by_pid(pid);
    if (fn_rcu_unlock) fn_rcu_unlock();
    if (!task_addr) return -1;

    if (fn_access_process_vm)
        return cmd_read_via_apm(task_addr, addr, size, out_msg, outlen);
    return cmd_read_via_phys(task_addr, addr, size, out_msg, outlen);
}

/* ---- CTL0 dispatcher ---- */

static long xpida_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!g_ready) {
        const char *msg = "error: not ready\n";
        compat_copy_to_user(out_msg, msg, 18);
        return -1;
    }
    if (!args || !args[0]) return -1;

    pr_info("[xpida] ctl0: %s\n", args);

    if (args[0] == 'f' && args[1] == 'i' && args[2] == 'n' && args[3] == 'd' && args[4] == ' ')
        return cmd_find(args + 5, out_msg, outlen);
    if (args[0] == 'm' && args[1] == 'a' && args[2] == 'p' && args[3] == 's' && args[4] == ' ')
        return cmd_maps(args + 5, out_msg, outlen);
    if (args[0] == 'r' && args[1] == 'e' && args[2] == 'a' && args[3] == 'd' && args[4] == ' ')
        return cmd_read(args + 5, out_msg, outlen);
    if (args[0] == 'p' && args[1] == 'i' && args[2] == 'n' && args[3] == 'g') {
        compat_copy_to_user(out_msg, "pong\n", 6);
        return 0;
    }

    compat_copy_to_user(out_msg, "find|maps|read|ping\n", 21);
    return -1;
}

/* ---- Init / Exit ---- */

static long xpida_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[xpida] init, event: %s, args: %s\n", event, args ? args : "(null)");
    pr_info("[xpida] kpver: %x, kver: %x\n", kpver, kver);

    safe_copy = (typeof(safe_copy))kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!safe_copy)
        safe_copy = (typeof(safe_copy))kallsyms_lookup_name("probe_kernel_read");

    fn_vmalloc = (typeof(fn_vmalloc))kallsyms_lookup_name("vmalloc");
    if (!fn_vmalloc)
        fn_vmalloc = (typeof(fn_vmalloc))kallsyms_lookup_name("vmalloc_noprof");
    fn_vfree = (typeof(fn_vfree))kallsyms_lookup_name("vfree");
    if (!fn_vmalloc || !fn_vfree) {
        pr_err("[xpida] vmalloc/vfree not found\n");
        return -1;
    }

    fn_rcu_lock = (void (*)(void))kallsyms_lookup_name("__rcu_read_lock");
    fn_rcu_unlock = (void (*)(void))kallsyms_lookup_name("__rcu_read_unlock");
    fn_d_path = (typeof(fn_d_path))kallsyms_lookup_name("d_path");
    fn_access_process_vm = (typeof(fn_access_process_vm))
        kallsyms_lookup_name("access_process_vm");

    pr_info("[xpida] d_path: %s, access_process_vm: %s\n",
            fn_d_path ? "ok" : "no", fn_access_process_vm ? "ok" : "no");

    if (resolve_offsets() != 0) {
        pr_err("[xpida] offset resolution failed\n");
        return 0;
    }

    g_ready = 1;
    pr_info("[xpida] ready\n");
    return 0;
}

static long xpida_exit(void *__user reserved)
{
    g_ready = 0;
    pr_info("[xpida] exit\n");
    return 0;
}

KPM_INIT(xpida_init);
KPM_CTL0(xpida_control0);
KPM_EXIT(xpida_exit);
