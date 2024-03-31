#pragma once

#include <linux/limits.h>

// default rule values
#define DEFAULT_BINARY_PATH ""
#define DEFAULT_FULL_COMMAND ""
#define DEFAULT_TARGET_PATH ""
#define DEFAULT_UID -999
#define DEFAULT_GID -999
#define DEFAULT_ARGC -1
#define DEFAULT_FLAGS -1
#define DEFAULT_MODE -1

enum rule_type
{
    open_rule_type,
    execve_rule_type
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

struct open_rule
{
    char binary_path[PATH_MAX];
    char full_command[PATH_MAX];
    char target_path[PATH_MAX];
    int uid;
    int gid;
    int flags;
    int mode;
    int prevention;
};

typedef struct execve_rule execve_event;
typedef struct open_rule open_event;

struct rule 
{
    enum rule_type type;
    union
    {
        struct open_rule open;
        struct execve_rule execve;
    } data;
};

#ifdef __KERNEL__

struct rules_list
{
    struct list_head list;
    struct rule rule;
};

int add_rule(struct rule *rule);

void print_rules(void);

void delete_rules(void);

struct rule * does_execve_event_match_rule(const execve_event *event);

struct rule * does_open_event_match_rule(const open_event *event);

#endif