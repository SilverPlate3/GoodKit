#pragma once

#include <linux/fs.h>

long good_kit_rules_ioctl_main_callback(struct file *file, unsigned int ioctl_num, unsigned long parameter);

int register_rules_device(void);

void deregister_rules_device(void);