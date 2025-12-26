#pragma once

#include <linux/kernel.h>
#include <linux/types.h>

uintptr_t get_module_base(pid_t pid, char *name);
