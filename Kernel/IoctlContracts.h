#pragma once

#include "Rules/Rules.h"

#include <linux/ioctl.h>

#define ADD_RULE _IOW('a','a',struct rule*)
#define PRINT_ALL_RULLES _IO('a','b')
#define DELETE_RULES _IO('a','c')

#define ADD_BINARY_EXCLUSION _IOW('a','d',char *)
#define PRINT_ALL_EXCLUSIONS _IO('a','e')
#define DELETE_EXCLUSIONS _IO('a','f')

#define RULES_DEVICE_NAME "good_kit_rules"
#define RULES_DEVICE_PATH "/dev/" RULES_DEVICE_NAME

#define EXCLUSIONS_DEVICE_NAME "good_kit_exclusions"
#define EXCLUSIONS_DEVICE_PATH "/dev/" EXCLUSIONS_DEVICE_NAME