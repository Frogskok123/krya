#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#define DEVICE_NAME "mtk_tersafe"

static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

static long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char key[0x100] = {0};
    static char name[0x100] = {0};
    static bool is_verified = false;

    if (cmd == OP_INIT_KEY && !is_verified) {
        if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) != 0)
            return -EFAULT;
        is_verified = true;
        return 0;
    }

    if (!is_verified)
        return -EACCES;

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
            return -EFAULT;
        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
            return -EIO;
        break;

    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
            return -EFAULT;
        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
            return -EIO;
        break;

    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || 
            copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
            return -EFAULT;
        
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
            return -EFAULT;
        break;

    default:
        return -EINVAL;
    }
    return 0;
}

static const struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

// Найти функцию driver_entry и заменить на:
static int __init driver_entry(void) {
    int ret;
    
    // Инициализация Kprobes для скрытых функций
    resolve_kernel_symbols();

    printk(KERN_INFO "[+] JiangNight: Fast Kmap Driver Loaded");
    ret = misc_register(&misc);
    return ret;
}
static void __exit driver_unload(void)
{
    printk(KERN_INFO "[+] JiangNight driver unloaded\n");
    misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Android GKI Memory Driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kryasan");
