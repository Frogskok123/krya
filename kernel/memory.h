#ifndef MEMORY_H
#define MEMORY_H

#include <linux/types.h>
#include <linux/mm.h>

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool resolve_kernel_symbols(void);

#endif
