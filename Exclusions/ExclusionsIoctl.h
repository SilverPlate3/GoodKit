#pragma once

#include <linux/fs.h>

long good_kit_exclusions_ioctl_main_callback(struct file *file, unsigned int ioctl_num, unsigned long parameter);

int register_exclusions_device(void);

void deregister_exclusions_device(void);