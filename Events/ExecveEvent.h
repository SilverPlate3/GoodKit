#pragma once

#include "../Rules/Rules.h"

#include <linux/kernel.h> // for struct pt_regs

#define MKVAR(Type, Name, From) Type Name = (Type)(From);
#define MAX_ARG_LENGTH 1024 // TODO: is this really needed? as execve_rule.full_command is PATH_MAX

execve_event * create_execve_event(const struct pt_regs *regs);