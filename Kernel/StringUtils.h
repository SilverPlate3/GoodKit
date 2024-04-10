#pragma once

#include <linux/uaccess.h> 

int string_compare_with_wildcards(const char *wild, const char *string);

int join_strings_from_user(const char __user *const __user *ups, const char *delim, char *buff, size_t bufcap);