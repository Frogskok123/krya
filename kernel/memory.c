#include "memory.h"
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

static struct perf_event *jiang_hbp = NULL;

// Обработчик срабатывания (выполняется в контексте прерывания)
static void jiang_hbp_handler(struct perf_event *bp, 
                             struct perf_sample_data *data, 
                             struct pt_regs *regs) 
{
    // Безопасный вывод в лог (dmesg)
    pr_info("JiangNight: HWBP Hit! Addr: 0x%lx, PC: 0x%llx\n", 
            (unsigned long)bp->attr.bp_addr, regs->pc);
}

bool set_hw_breakpoint(pid_t pid, uintptr_t addr, int type, int len) {
    struct perf_event_attr attr;
    struct task_struct *task;
    struct pid *pid_struct;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return false;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return false;

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len = (len == 8) ? HW_BREAKPOINT_LEN_8 : HW_BREAKPOINT_LEN_4;
    
    if (type == 1) attr.bp_type = HW_BREAKPOINT_X;
    else if (type == 2) attr.bp_type = HW_BREAKPOINT_W;
    else attr.bp_type = HW_BREAKPOINT_RW;

    // Создание события для конкретного процесса на всех ядрах Dimensity 8100
    jiang_hbp = perf_event_create_kernel_counter(&attr, -1, task, jiang_hbp_handler, NULL);
    put_task_struct(task);

    if (IS_ERR(jiang_hbp)) {
        pr_err("JiangNight: Failed to set BP: %ld\n", PTR_ERR(jiang_hbp));
        jiang_hbp = NULL;
        return false;
    }
    return true;
}

void remove_hw_breakpoint(void) {
    if (jiang_hbp) {
        perf_event_release_kernel(jiang_hbp);
        jiang_hbp = NULL;
    }
}

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
