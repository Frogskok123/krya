
#include "memory.h"
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>

typedef int (*valid_phys_addr_range_t)(phys_addr_t addr, size_t size);
static valid_phys_addr_range_t g_valid_phys_addr_range = NULL;

static unsigned long lookup_symbol(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

bool resolve_kernel_symbols(void) {
    g_valid_phys_addr_range = (valid_phys_addr_range_t)lookup_symbol("valid_phys_addr_range");
    return true; 
}

static struct page* v2p(struct mm_struct *mm, uintptr_t va, phys_addr_t *pa) {
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    struct page *pg;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;
    pte = pte_offset_kernel(pmd, va);
    if (!pte || !pte_present(*pte)) return NULL;

    pg = pte_page(*pte);
    if (!pg || !page_ref_count(pg)) return NULL;
    if (pa) *pa = page_to_phys(pg) + (va & ~PAGE_MASK);
    return pg;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    size_t done = 0;
    bool result = true;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return false;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) { put_pid(pid_struct); return false; }
    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); put_pid(pid_struct); return false; }

    mmap_read_lock(mm);
    while (done < size) {
        phys_addr_t pa;
        struct page *pg;
        void *mapped;
        uintptr_t curr_va = addr + done;
        size_t off = curr_va & ~PAGE_MASK;
        size_t chunk = min_t(size_t, PAGE_SIZE - off, size - done);

        pg = v2p(mm, curr_va, &pa);
        if (!pg) { result = false; break; }
        
        if (g_valid_phys_addr_range && !g_valid_phys_addr_range(pa, chunk)) {
            result = false; break;
        }

        // В ядре 5.10 на arm64 используем page_address
        mapped = page_address(pg);
        if (!mapped) { result = false; break; }

        if (copy_to_user((char __user *)buffer + done, (char *)mapped + off, chunk)) {
            result = false; break;
        }
        done += chunk;
    }
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    return result;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct pid *pid_struct;
    size_t done = 0;
    bool result = true;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return false;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) { put_pid(pid_struct); return false; }
    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); put_pid(pid_struct); return false; }

    mmap_read_lock(mm);
    while (done < size) {
        phys_addr_t pa;
        struct page *pg;
        void *mapped;
        uintptr_t curr_va = addr + done;
        size_t off = curr_va & ~PAGE_MASK;
        size_t chunk = min_t(size_t, PAGE_SIZE - off, size - done);

        pg = v2p(mm, curr_va, &pa);
        if (!pg) { result = false; break; }

        mapped = page_address(pg);
        if (!mapped) { result = false; break; }

        if (copy_from_user((char *)mapped + off, (char __user *)buffer + done, chunk)) {
            result = false; break;
        }
        done += chunk;
    }
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    return result;
}
