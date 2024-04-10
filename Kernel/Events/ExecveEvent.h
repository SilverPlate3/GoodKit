#pragma once

#include "../Rules/Rules.h"

#include <linux/kernel.h>

#define MKVAR(Type, Name, From) Type Name = (Type)(From);

execve_event * create_execve_event(const struct pt_regs *regs);