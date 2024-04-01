#pragma once

#include <linux/limits.h>

struct excluded_binary_list
{
    struct list_head list;
    char * binary_path;
};

int add_binary_to_excluded_list(char * binary_path);

int is_binary_excluded(char * binary_path);