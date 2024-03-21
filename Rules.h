#pragma once

#include <linux/limits.h>

enum rule_type
{
    execve
};

struct execve_rule
{
    char binary_path[PATH_MAX];
    char full_command[PATH_MAX];
    int uid;
    int gid;
    int argc;
    int prevention;
};

struct rule 
{
    enum rule_type type;
    union
    {
        struct execve_rule execve;
    } data;
};

#ifdef CONFIG_KPROBES

struct rules_list
{
    struct list_head list;
    struct rule rule;
};

int add_rule_raw(struct rule *rule);

void print_rules_raw(void);

void delete_rules_raw(void);

int add_rule(struct rule *rule);

void print_rules(void);

void delete_rules(void);

#endif