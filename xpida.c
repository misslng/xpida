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
#include <syscall.h>

KPM_NAME("xpida");
KPM_VERSION("0.5.0");
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

#define DUMP_CHUNK       (4096 * 16)

#define XPIDA_MAGIC  0x7870696461ULL
#define XPIDA_NR     __NR_userfaultfd

/* ---- Config ---- */
static bool use_fn_access_process_vm = false;

/* ---- Global state ---- */

static int g_ready;
static int g_hooked;

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
static int g_user_page_level = 3;

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

/* ---- Output helpers ---- */

static void output_text(char *__user out_msg, int outlen, const char *data, int len)
{
    if (out_msg && outlen > 0)
        compat_copy_to_user(out_msg, data, len < outlen ? len : outlen);
}

static void output_bin(char *__user out_msg, int outlen, const void *data, int len)
{
    if (out_msg && outlen > 0)
        compat_copy_to_user(out_msg, data, len < outlen ? len : outlen);
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

    uintptr_t vmas[32];
    int nvma = 0;
    uintptr_t cur = 0;
    safe_read_ptr(mm_addr + g_mmap_off, &cur);
    while (cur >= 0xffff000000000000ULL && nvma < 32) {
        vmas[nvma++] = cur;
        uintptr_t nx = 0;
        safe_read_ptr(cur + 16, &nx);
        cur = nx;
    }
    if (!nvma) return;

    for (int off = 64; off < 160; off += 8) {
        uintptr_t v = 0;
        safe_read_ptr(vmas[0] + off, &v);
        if (v > 0 && v < 0x100000000ULL && (v & VM_READ)) {
            g_vm_flags_off = off;
            break;
        }
    }

    /* probe vm_file: field that is NULL for anon VMAs, kernel ptr for file-backed.
     * validate with d_path to confirm it's actually struct file*. */
    for (int off = 64; off < 256; off += 8) {
        int has_null = 0;
        uintptr_t good_fp = 0;
        for (int i = 0; i < nvma; i++) {
            uintptr_t v = 0;
            safe_read_ptr(vmas[i] + off, &v);
            if (v == 0) has_null = 1;
            else if (v >= 0xffff000000000000ULL && !good_fp) good_fp = v;
        }
        if (!has_null || !good_fp) continue;

        if (fn_d_path) {
            char tmpbuf[256];
            uintptr_t mnt = 0, den = 0;
            safe_read_ptr(good_fp + F_PATH_OFF, &mnt);
            safe_read_ptr(good_fp + F_PATH_OFF + 8, &den);
            if (mnt < 0xffff000000000000ULL || den < 0xffff000000000000ULL)
                continue;
            char *p = fn_d_path((const void *)(good_fp + F_PATH_OFF),
                                tmpbuf, sizeof(tmpbuf));
            if (!p || (uintptr_t)p < (uintptr_t)tmpbuf ||
                (uintptr_t)p >= (uintptr_t)tmpbuf + sizeof(tmpbuf) || p[0] != '/')
                continue;
            g_vm_file_off = off;
            pr_info("[xpida] vm_file at +%d validated: %s\n", off, p);
        } else {
            g_vm_file_off = off;
        }
        break;
    }

    /* probe vm_pgoff: search near vm_file for a field that is NOT a kernel ptr
     * and is a plausible page offset (small value) for most VMAs. */
    if (g_vm_file_off > 0) {
        int best = -1;
        for (int off = g_vm_file_off - 40; off < g_vm_file_off + 40; off += 8) {
            if (off < 0 || off == g_vm_file_off) continue;
            int ok = 1;
            for (int i = 0; i < nvma && i < 15; i++) {
                uintptr_t v = 0;
                safe_read_ptr(vmas[i] + off, &v);
                if (v >= 0xffff000000000000ULL) { ok = 0; break; }
            }
            if (ok) { best = off; break; }
        }
        if (best >= 0) g_vm_pgoff_off = best;
    }
}

/*
 * AT S1E1R：ARM64 硬件地址翻译指令，让 CPU 走当前 EL1 页表返回 PA。
 * 翻译失败只是在 PAR_EL1 里标记 F=1，不会 crash。
 * 比 pgtable_phys（内部做直接内存读取，给错 VA 会 panic）安全得多。
 */
static uint64_t at_translate_el1(uint64_t va)
{
    uint64_t par;
    asm volatile(
        "at s1e1r, %1\n"
        "isb\n"
        "mrs %0, par_el1\n"
        : "=r"(par) : "r"(va));
    if (par & 1)
        return 0;
    return (par & 0x0000FFFFFFFFF000ULL) | (va & 0xFFF);
}

static void compute_linear_voffset(void)
{
    uint64_t tcr;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));

    uint64_t t1sz = (tcr >> 16) & 0x3f;
    uint64_t kern_va_bits = 64 - t1sz;

    uint64_t t0sz = tcr & 0x3f;
    uint64_t user_va_bits = 64 - t0sz;
    g_user_page_level = (int)((user_va_bits - 4) / 9);

    pr_info("[xpida] tcr: t0sz=%llu user_va=%llu t1sz=%llu kern_va=%llu\n",
            (unsigned long long)t0sz, (unsigned long long)user_va_bits,
            (unsigned long long)t1sz, (unsigned long long)kern_va_bits);

    int found = 0;

    /*
     * 方法 1：直接读内核的 physvirt_offset（arm64 5.x 都有导出）。
     *         physvirt_offset = PAGE_OFFSET - PHYS_OFFSET，
     *         __phys_to_virt(pa) = pa + physvirt_offset，和我们的 linear_voffset 语义完全一致。
     */
    int64_t *p_pvo = (int64_t *)kallsyms_lookup_name("physvirt_offset");
    if (p_pvo) {
        int64_t pvo = 0;
        if (safe_read_buf((uintptr_t)p_pvo, &pvo, sizeof(pvo)) == 0 && pvo != 0) {
            g_linear_voffset = (uint64_t)pvo;
            found = 1;
            pr_info("[xpida] linear_voffset: %llx (physvirt_offset @ %lx)\n",
                    (unsigned long long)g_linear_voffset, (unsigned long)p_pvo);
        }
    }

    /*
     * 方法 2：AT 翻译一个 slab 分配的 task_struct 地址。
     *         init_task 在 kimage .data 区，但链表里下一个 task 是 slab 分配的，
     *         一定在线性映射区，用 AT 翻译它就能精确算出 linear_voffset。
     */
    if (!found && g_tasks_off > 0) {
        uintptr_t next = 0;
        safe_read_ptr((uintptr_t)g_init_task + g_tasks_off, &next);
        if (next && next != (uintptr_t)g_init_task + g_tasks_off) {
            uintptr_t task_va = next - g_tasks_off;
            uint64_t task_pa = at_translate_el1((uint64_t)task_va);
            if (task_pa) {
                g_linear_voffset = (uint64_t)task_va - task_pa;
                found = 1;
                pr_info("[xpida] linear_voffset: %llx (AT task: va=%lx pa=%llx)\n",
                        (unsigned long long)g_linear_voffset,
                        (unsigned long)task_va, (unsigned long long)task_pa);
            }
        }
    }

    /*
     * 方法 3：memstart_addr 回退。
     *         5.4+:  PAGE_OFFSET = -(1ULL << VA_BITS)
     *         旧版:  PAGE_OFFSET = ~0ULL << (VA_BITS - 1)
     *         linear_voffset = PAGE_OFFSET - memstart_addr
     */
    if (!found) {
        uint64_t memstart = 0;
        int64_t *p_ms = (int64_t *)kallsyms_lookup_name("memstart_addr");
        if (p_ms)
            safe_read_buf((uintptr_t)p_ms, &memstart, sizeof(memstart));
        uint64_t page_offset = 0ULL - (1ULL << kern_va_bits);
        g_linear_voffset = page_offset - memstart;
        pr_info("[xpida] linear_voffset: %llx (fallback: po=%llx ms=%llx)\n",
                (unsigned long long)g_linear_voffset,
                (unsigned long long)page_offset,
                (unsigned long long)memstart);
    }

    pr_info("[xpida] user_va_bits=%llu page_level=%d\n",
            (unsigned long long)user_va_bits, g_user_page_level);
}

static int g_walk_dbg = 0;

static uint64_t safe_pgtable_phys_user(uint64_t pgd_va, uint64_t va)
{
    int dbg = g_walk_dbg > 0;
    if (dbg) g_walk_dbg--;

    uint64_t pxd_va = pgd_va;
    uint64_t pxd_pa = 0;
    for (int lv = 4 - g_user_page_level; lv < 4; ++lv) {
        uint64_t shift = 9 * (4 - lv) + 3;
        uint64_t idx = (va >> shift) & 0x1ff;
        uint64_t desc = 0;
        int rc = safe_read_ptr(pxd_va + idx * 8, (uintptr_t *)&desc);
        if (dbg)
            pr_info("[xpida] walk lv=%d pxd_va=%llx idx=%llu addr=%llx rc=%d desc=%llx type=%d\n",
                    lv, (unsigned long long)pxd_va, (unsigned long long)idx,
                    (unsigned long long)(pxd_va + idx * 8), rc,
                    (unsigned long long)desc, (int)(desc & 3));
        if (rc != 0)
            return 0;
        uint8_t type = desc & 0x3;
        if (type == 0x3) {
            pxd_pa = desc & 0x0000FFFFFFFFF000ULL;
        } else if (type == 0x1) {
            int bits = (3 - lv) * 9;
            uint64_t bb = bits + 12;
            uint64_t bm = ((1ULL << (48 - bb)) - 1) << bb;
            uint64_t om = ((1ULL << bits) - 1) << 12;
            pxd_pa = (desc & bm) + (va & om);
            return pxd_pa + (va & 0xfff);
        } else {
            return 0;
        }
        pxd_va = pxd_pa + g_linear_voffset;
    }
    return pxd_pa ? pxd_pa + (va & 0xfff) : 0;
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

    int bufsz = outlen > 0 ? outlen : 4096;
    char *kbuf = fn_vmalloc(bufsz);
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
            if (off < bufsz - 48)
                off += snprintf(kbuf + off, bufsz - off, "%d:%s\n", pid, comm);
            found++;
        }
        if (safe_read_ptr(pos, &pos) != 0) break;
    }

out:
    if (fn_rcu_unlock) fn_rcu_unlock();
    if (!found && off < bufsz - 16)
        off += snprintf(kbuf + off, bufsz - off, "not_found\n");
    kbuf[off] = '\0';
    output_text(out_msg, outlen, kbuf, off + 1);
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

    int omax = outlen > 0 ? outlen : MAPS_BUF_SIZE;
    int bsz = omax < MAPS_BUF_SIZE ? omax : MAPS_BUF_SIZE;
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
    output_text(out_msg, outlen, kbuf, off + 1);
    fn_vfree(kbuf);
    return 0;
}

/* ---- cmd_read: read process memory ---- */

static long cmd_read(const char *args, char *__user out_msg, int outlen)
{
    int32_t pid = 0;
    unsigned long addr = 0;
    int size = 0;

    if (sscanf(args, "%d %lx %d", &pid, &addr, &size) != 3) return -1;
    if (pid <= 0 || size <= 0) return -1;
    if (size > MAX_READ_SIZE) size = MAX_READ_SIZE;

    if (fn_rcu_lock) fn_rcu_lock();
    uintptr_t task_addr = find_task_by_pid(pid);
    if (fn_rcu_unlock) fn_rcu_unlock();
    if (!task_addr) return -1;

    char *kbuf = fn_vmalloc(size);
    if (!kbuf) return -1;
    long ret = -1;

    if (fn_access_process_vm) {
        int n = fn_access_process_vm((void *)task_addr, addr, kbuf, size, FOLL_FORCE);
        if (n > 0) { output_bin(out_msg, outlen, kbuf, n); ret = n; }
    } else if (g_linear_voffset) {
        uintptr_t mm = 0;
        safe_read_ptr(task_addr + g_mm_off, &mm);
        if (mm >= 0xffff000000000000ULL) {
            uintptr_t pgd = 0;
            safe_read_ptr(mm + g_pgd_off, &pgd);
            if (pgd >= 0xffff000000000000ULL) {
                int total = 0, rem = size;
                unsigned long cur = addr;
                while (rem > 0) {
                    int poff = cur & (PAGE_SZ - 1);
                    int chunk = rem < (PAGE_SZ - poff) ? rem : (PAGE_SZ - poff);
                    uint64_t pa = safe_pgtable_phys_user(pgd, cur);
                    if (pa)
                        safe_read_buf(pa + g_linear_voffset, kbuf + total, chunk);
                    else
                        for (int z = 0; z < chunk; z++) kbuf[total + z] = 0;
                    cur += chunk; total += chunk; rem -= chunk;
                }
                output_bin(out_msg, outlen, kbuf, total);
                ret = total;
            }
        }
    }

    fn_vfree(kbuf);
    return ret;
}

/* ---- cmd_ps: list all processes ---- */

static long cmd_ps(char *__user out_msg, int outlen)
{
    int bufsz = outlen > 0 ? outlen : (128 * 1024);
    char *kbuf = fn_vmalloc(bufsz);
    if (!kbuf) return -1;
    int off = 0, count = 0;

    uintptr_t init_head = (uintptr_t)g_init_task + g_tasks_off;
    uintptr_t pos = 0;

    if (fn_rcu_lock) fn_rcu_lock();
    if (safe_read_ptr(init_head, &pos) != 0) goto out;

    while (pos != init_head && count++ < MAX_PROCESSES) {
        uintptr_t task = pos - g_tasks_off;
        int32_t pid = 0;
        char comm[16] = { 0 };
        if (g_pid_off > 0) safe_read_buf(task + g_pid_off, &pid, 4);
        safe_read_buf(task + g_comm_off, comm, 16);
        comm[15] = '\0';
        if (pid > 0 && off < bufsz - 48)
            off += snprintf(kbuf + off, bufsz - off, "%d:%s\n", pid, comm);
        if (safe_read_ptr(pos, &pos) != 0) break;
    }

out:
    if (fn_rcu_unlock) fn_rcu_unlock();
    kbuf[off] = '\0';
    output_text(out_msg, outlen, kbuf, off + 1);
    fn_vfree(kbuf);
    return count > 0 ? 0 : -1;
}

/* ---- cmd_dump: dump process memory to out_msg ---- */

static long cmd_dump(const char *args, char *__user out_msg, int outlen)
{
    int32_t pid = 0;
    unsigned long start = 0, end = 0;

    int nr = sscanf(args, "%d %lx %lx", &pid, &start, &end);
    pr_info("[xpida] dump: parse nr=%d pid=%d start=%lx end=%lx\n",
            nr, pid, start, end);
    if (nr != 3) return -1;
    if (pid <= 0 || end <= start) return -1;

    unsigned long total_size = end - start;
    if (total_size > 64 * 1024 * 1024) total_size = 64 * 1024 * 1024;
    if ((unsigned long)outlen < total_size) {
        pr_info("[xpida] dump: outlen %d < total %lu\n", outlen, total_size);
        return -1;
    }

    if (fn_rcu_lock) fn_rcu_lock();
    uintptr_t task_addr = find_task_by_pid(pid);
    if (fn_rcu_unlock) fn_rcu_unlock();
    if (!task_addr) { pr_info("[xpida] dump: task not found\n"); return -1; }

    char *chunk = fn_vmalloc(DUMP_CHUNK);
    if (!chunk) return -1;

    unsigned long cur = start;
    long written = 0;

    uintptr_t mm = 0, pgd = 0;
    if (!fn_access_process_vm && g_linear_voffset) {
        safe_read_ptr(task_addr + g_mm_off, &mm);
        if (mm >= 0xffff000000000000ULL)
            safe_read_ptr(mm + g_pgd_off, &pgd);
    }
    pr_info("[xpida] dump: apm=%s voff=%llx mm=%lx pgd=%lx plvl=%d\n",
            fn_access_process_vm ? "yes" : "no",
            (unsigned long long)g_linear_voffset,
            (unsigned long)mm, (unsigned long)pgd, g_user_page_level);

    int dbg_n = 0, dbg_pa_ok = 0, dbg_pa_zero = 0, dbg_rd_ok = 0, dbg_rd_fail = 0;

    while (cur < start + total_size) {
        int sz = DUMP_CHUNK;
        if (cur + sz > start + total_size) sz = (int)(start + total_size - cur);

        int got = 0;
        if (fn_access_process_vm) {
            got = fn_access_process_vm((void *)task_addr, cur, chunk, sz, FOLL_FORCE);
        } else if (g_linear_voffset && pgd >= 0xffff000000000000ULL) {
            int pos2 = 0, rem = sz;
            unsigned long c = cur;
            while (rem > 0) {
                int poff = c & (PAGE_SZ - 1);
                int blk = rem < (PAGE_SZ - poff) ? rem : (PAGE_SZ - poff);
                uint64_t pa = safe_pgtable_phys_user(pgd, c);
                if (pa) {
                    dbg_pa_ok++;
                    uintptr_t kva = pa + g_linear_voffset;
                    int rc = safe_read_buf(kva, chunk + pos2, blk);
                    if (rc == 0) dbg_rd_ok++; else dbg_rd_fail++;
                    if (dbg_n < 4)
                        pr_info("[xpida] pg[%d] va=%lx pa=%llx kva=%lx rc=%d\n",
                                dbg_n, (unsigned long)c,
                                (unsigned long long)pa, (unsigned long)kva, rc);
                } else {
                    dbg_pa_zero++;
                    for (int z = 0; z < blk; z++) chunk[pos2 + z] = 0;
                    if (dbg_n < 4)
                        pr_info("[xpida] pg[%d] va=%lx pa=0 (unmapped)\n",
                                dbg_n, (unsigned long)c);
                }
                dbg_n++;
                c += blk; pos2 += blk; rem -= blk;
            }
            got = sz;
        }

        if (got <= 0) break;
        if (out_msg)
            compat_copy_to_user(out_msg + written, chunk, got);
        written += got;
        cur += got;
    }

    pr_info("[xpida] dump: total_pg=%d pa_ok=%d pa_zero=%d rd_ok=%d rd_fail=%d written=%ld\n",
            dbg_n, dbg_pa_ok, dbg_pa_zero, dbg_rd_ok, dbg_rd_fail, written);

    fn_vfree(chunk);
    return written;
}

/* ---- CTL0 dispatcher ---- */

/*
 * 从 args 末尾解析嵌入的用户态 buffer：" @<hex_addr> <hex_len>"
 * SuKiSU ioctl 模式没有 out_msg，CLI 把自己的 buffer 地址编码在 args 里。
 * 返回纯命令部分的长度（截掉 @... 后缀）。
 */
static int extract_user_buf(const char *args, char *__user *out, int *olen)
{
    const char *at = args;
    const char *found = 0;
    while (*at) {
        if (at[0] == ' ' && at[1] == '@') { found = at; break; }
        at++;
    }
    if (!found) return -1;
    unsigned long addr = 0, len = 0;
    if (sscanf(found + 2, "%lx %lx", &addr, &len) == 2 && addr && len) {
        *out = (char *__user)addr;
        *olen = (int)len;
        return (int)(found - args);
    }
    return -1;
}

static long xpida_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!g_ready) {
        output_text(out_msg, outlen, "error: not ready\n", 18);
        return -1;
    }
    if (!args || !args[0]) return -1;

    /*
     * 如果 out_msg 为 NULL（ioctl 模式），尝试从 args 尾部取嵌入 buffer。
     * 格式: "实际命令 @<hex_buf_addr> <hex_buf_len>"
     */
    char clean[1024];
    int clen = (int)__builtin_strlen(args);
    if (clen >= (int)sizeof(clean)) clen = (int)sizeof(clean) - 1;
    __builtin_memcpy(clean, args, clen);
    clean[clen] = '\0';

    if (!out_msg) {
        int cmd_len = extract_user_buf(clean, &out_msg, &outlen);
        if (cmd_len > 0)
            clean[cmd_len] = '\0';
    }

    pr_info("[xpida] ctl0: %s (out=%d)\n", clean, outlen);

    if (clean[0] == 'f' && clean[1] == 'i' && clean[2] == 'n' && clean[3] == 'd' && clean[4] == ' ')
        return cmd_find(clean + 5, out_msg, outlen);
    if (clean[0] == 'm' && clean[1] == 'a' && clean[2] == 'p' && clean[3] == 's' && clean[4] == ' ')
        return cmd_maps(clean + 5, out_msg, outlen);
    if (clean[0] == 'r' && clean[1] == 'e' && clean[2] == 'a' && clean[3] == 'd' && clean[4] == ' ')
        return cmd_read(clean + 5, out_msg, outlen);
    if (clean[0] == 'd' && clean[1] == 'u' && clean[2] == 'm' && clean[3] == 'p' && clean[4] == ' ')
        return cmd_dump(clean + 5, out_msg, outlen);
    if (clean[0] == 'p' && clean[1] == 's' && (clean[2] == '\0' || clean[2] == ' '))
        return cmd_ps(out_msg, outlen);
    if (clean[0] == 'p' && clean[1] == 'i' && clean[2] == 'n' && clean[3] == 'g') {
        output_text(out_msg, outlen, "pong\n", 6);
        return 0;
    }

    output_text(out_msg, outlen, "dump|ps|find|maps|read|ping\n", 29);
    return -1;
}

/* ---- Syscall hook handler ---- */

static void before_userfaultfd(hook_fargs4_t *fargs, void *udata)
{
    uint64_t magic = syscall_argn(fargs, 0);
    if (magic != XPIDA_MAGIC)
        return;

    fargs->skip_origin = 1;

    // if (current_uid() != 0) {
    //     fargs->ret = (uint64_t)(long)-1;
    //     return;
    // }

    if (!g_ready) {
        fargs->ret = (uint64_t)(long)-1;
        return;
    }

    char __user *args_u = (char __user *)syscall_argn(fargs, 1);
    char __user *out_buf = (char __user *)syscall_argn(fargs, 2);
    int out_len = (int)syscall_argn(fargs, 3);

    char args[1024];
    long slen = compat_strncpy_from_user(args, args_u, sizeof(args));
    if (slen <= 0) {
        fargs->ret = (uint64_t)(long)-1;
        return;
    }

    long ret = xpida_control0(args, out_buf, out_len);
    fargs->ret = (uint64_t)ret;
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
    if (use_fn_access_process_vm) {
        fn_access_process_vm = (typeof(fn_access_process_vm))
            kallsyms_lookup_name("access_process_vm");
    } else {
        fn_access_process_vm = NULL;
    }

    pr_info("[xpida] d_path: %s, access_process_vm: %s\n",
            fn_d_path ? "ok" : "no", fn_access_process_vm ? "ok" : "no");

    if (resolve_offsets() != 0) {
        pr_err("[xpida] offset resolution failed\n");
        return 0;
    }

    g_ready = 1;

    hook_err_t herr = hook_syscalln(XPIDA_NR, 1, before_userfaultfd, NULL, NULL);
    if (herr != HOOK_NO_ERR) {
        pr_err("[xpida] hook syscall %d failed: %d\n", XPIDA_NR, herr);
    } else {
        g_hooked = 1;
        pr_info("[xpida] hooked syscall %d\n", XPIDA_NR);
    }

    pr_info("[xpida] ready\n");
    return 0;
}

static long xpida_exit(void *__user reserved)
{
    if (g_hooked) {
        unhook_syscalln(XPIDA_NR, before_userfaultfd, NULL);
        g_hooked = 0;
    }
    g_ready = 0;
    pr_info("[xpida] exit\n");
    return 0;
}

KPM_INIT(xpida_init);
KPM_CTL0(xpida_control0);
KPM_EXIT(xpida_exit);
