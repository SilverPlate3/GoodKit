#pragma once

#include <linux/limits.h>

// default rule values
#define DEFAULT_BINARY_PATH ""
#define DEFAULT_FULL_COMMAND ""
#define DEFAULT_UID -999
#define DEFAULT_GID -999
#define DEFAULT_ARGC -1

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

typedef struct execve_rule execve_event;

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

int add_rule(struct rule *rule);

void print_rules(void);

void delete_rules(void);

struct rule * does_event_match_rule(const execve_event *event);

#endif