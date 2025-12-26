#include "memory.h"
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>

// Глобальный указатель для поиска скрытых функций
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

// Безопасный перевод виртуального адреса процесса в физическую страницу
static struct page* get_process_page(struct mm_struct *mm, uintptr_t va, phys_addr_t *pa) {
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep, pte;
    struct page *page = NULL;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;

    // Безопасное получение PTE с использованием маппинга для пользовательских процессов
    ptep = pte_offset_map(pmd, va);
    if (!ptep) return NULL;
    pte = *ptep;

    if (pte_present(pte)) {
        unsigned long pfn = pte_pfn(pte);
        if (pfn_valid(pfn)) {
            page = pfn_to_page(pfn);
            if (pa) *pa = (phys_addr_t)(pfn << PAGE_SHIFT) + (va & ~PAGE_MASK);
        }
    }
    pte_unmap(ptep);
    return page;
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

    // Защищаем память процесса от изменений во время чтения
    if (!mmap_read_trylock(mm)) {
        mmput(mm); put_task_struct(task); put_pid(pid_struct);
        return false;
    }

    while (done < size) {
        struct page *pg;
        void *kernel_addr;
        phys_addr_t pa;
        uintptr_t curr_va = addr + done;
        size_t off = curr_va & ~PAGE_MASK;
        size_t chunk = min_t(size_t, PAGE_SIZE - off, size - done);

        pg = get_process_page(mm, curr_va, &pa);
        if (!pg) { result = false; break; }

        // Дополнительная проверка диапазона, если символ найден
        if (g_valid_phys_addr_range && !g_valid_phys_addr_range(pa, chunk)) {
            result = false; break;
        }

        // На arm64 page_address — самый быстрый и безопасный способ
        kernel_addr = page_address(pg);
        if (!kernel_addr) { result = false; break; }

        // Копируем данные в буфер пользователя
        if (copy_to_user((char __user *)buffer + done, (char *)kernel_addr + off, chunk)) {
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

    if (!mmap_read_trylock(mm)) {
        mmput(mm); put_task_struct(task); put_pid(pid_struct);
        return false;
    }

    while (done < size) {
        struct page *pg;
        void *kernel_addr;
        phys_addr_t pa;
        uintptr_t curr_va = addr + done;
        size_t off = curr_va & ~PAGE_MASK;
        size_t chunk = min_t(size_t, PAGE_SIZE - off, size - done);

        pg = get_process_page(mm, curr_va, &pa);
        if (!pg) { result = false; break; }

        kernel_addr = page_address(pg);
        if (!kernel_addr) { result = false; break; }

        // Запись данных из буфера пользователя в память процесса
        if (copy_from_user((char *)kernel_addr + off, (char __user *)buffer + done, chunk)) {
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
