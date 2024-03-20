#pragma once

#include "Rules.h"

#include <linux/ioctl.h>

#define ADD_RULE _IOW('a','a',struct rule*)
#define PRINT_ALL_RULLES _IO('a','b')

#define RULES_DEVICE_NAME "good_kit_rules"
#define RULES_DEVICE_PATH "/dev/" RULES_DEVICE_NAME