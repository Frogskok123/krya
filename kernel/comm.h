#pragma once

#include <linux/types.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
};
// Добавь в конец файла
typedef struct _HW_BREAKPOINT {
    pid_t pid;
    uintptr_t addr;
    int type; // 1 - Execute, 2 - Write, 3 - Read/Write
    int len;  // 4 или 8
} HW_BREAKPOINT, *PHW_BREAKPOINT;

#define OP_SET_HW_BP 0x804
#define OP_DEL_HW_BP 0x805
