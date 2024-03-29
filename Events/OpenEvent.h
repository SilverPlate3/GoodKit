#pragma once

#include "../Rules/Rules.h"

#include <linux/kernel.h> // for struct pt_regs

open_event * create_open_event(const struct pt_regs *regs);
//open_event * create_openat_event(const struct pt_regs *regs);