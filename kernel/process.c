#include "process.h"
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/sched/mm.h>

#define ARC_PATH_MAX 256

uintptr_t get_module_base(pid_t pid, char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return 0;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        put_pid(pid_struct);
        return 0;
    }

    // КРИТИЧНО: Блокировка для безопасного обхода VMA
    if (!mmap_read_trylock(mm)) {
        mmput(mm);
        put_task_struct(task);
        put_pid(pid_struct);
        return 0;
    }

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            char buf[ARC_PATH_MAX];
            char *path_nm;

            // Используем d_path, так как он более стабилен внутри ядра
            path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX - 1);
            if (IS_ERR(path_nm))
                continue;
            
            // Используем strstr вместо strcmp, так как пути в Android длинные
            // Это позволит найти "libUE4.so" в "/data/app/.../libUE4.so" [web:107]
            if (strstr(path_nm, name)) {
                base_addr = vma->vm_start;
                break;
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    put_pid(pid_struct);
    
    return base_addr;
}
