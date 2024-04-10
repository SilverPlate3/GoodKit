#include "Rules.h"
#include "../StringUtils.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rwlock.h> 

int are_there_execve_rules = 0;
int are_there_open_rules = 0;

LIST_HEAD(rules_list_head);
static DEFINE_RWLOCK(rules_list_rw_lock);

static void print_rule(struct rule* rule)
{
    if(rule->type == execve_rule_type)
    {
        const char * prefix = "execve_rule";
        pr_info("\n-------- %s -----------\nbinary_path: %s\nfull_command: %s\nuid: %d\ngid: %d\nargc: %d\nprevention: %d\n",
                prefix,
                rule->data.execve.binary_path,
                rule->data.execve.full_command,
                rule->data.execve.uid,
                rule->data.execve.gid,
                rule->data.execve.argc,
                rule->data.execve.prevention);
    }
    else if(rule->type == open_rule_type)
    {
        const char * prefix = "open_rule";
        pr_info("\n-------- %s -----------\nbinary_path: %s\nfull_command: %s\ntarget_path: %s\nuid: %d\ngid: %d\nflags: %d\nmode: %d\nprevention: %d\n",
                prefix,
                rule->data.open.binary_path,
                rule->data.open.full_command,
                rule->data.open.target_path,
                rule->data.open.uid,
                rule->data.open.gid,
                rule->data.open.flags,
                rule->data.open.mode,
                rule->data.open.prevention);
    }
    else
    {
        pr_alert("unsuported rule type\n");
    }
}

static void print_rules_raw(void)
{
    pr_info("\n-------- printing rules: --------\n");
    struct rules_list *temp;
    list_for_each_entry(temp, &rules_list_head, list) 
    {
        print_rule(&temp->rule);
    }
}

static void delete_rules_raw(void)
{
    pr_info("\n-------- deleting rules: --------\n");
    struct rules_list *temp, *next;
    list_for_each_entry_safe(temp, next, &rules_list_head, list) 
    {
        print_rule(&temp->rule);
        list_del(&temp->list);
        kfree(temp);
    }
}

static void print_matched_execve_rule(const execve_event *event, const struct execve_rule *execve_rule)
{
    pr_info("execve event match rule.\nRule.binary_path: '%s' Event.binary_path: '%s'\nRule.full_command: '%s' Event.full_command: '%s'\nRule.uid: %d Event.uid: %d\nRule.gid: %d Event.gid: %d\nRule.argc: %d Event.argc: %d\n",
            execve_rule->binary_path, event->binary_path, execve_rule->full_command, event->full_command, execve_rule->uid, event->uid, execve_rule->gid, event->gid, execve_rule->argc, event->argc);
}

static void print_matched_open_rule(const open_event *event, const struct open_rule *open_rule)
{
    pr_info("open event match rule.\nRule.binary_path: '%s' Event.binary_path: '%s'\nRule.full_command: '%s' Event.full_command: '%s'\nRule.target_path: '%s' Event.target_path: '%s'\nRule.uid: %d Event.uid: %d\nRule.gid: %d Event.gid: %d\nRule.flags: %d Event.flags: %d\nRule.mode: %d Event.mode: %d\n",
            open_rule->binary_path, event->binary_path, open_rule->full_command, event->full_command, open_rule->target_path, event->target_path, open_rule->uid, event->uid, open_rule->gid, event->gid, open_rule->flags, event->flags, open_rule->mode, event->mode);
}

static int is_execve_event_match_rule(const execve_event *event, const struct execve_rule *execve_rule)
{
    if(strcmp(execve_rule->binary_path, DEFAULT_BINARY_PATH) != 0)
    {
        if(string_compare_with_wildcards(execve_rule->binary_path, event->binary_path) == 0)
        {
            return 0;
        }
    }

    if(strcmp(execve_rule->full_command, DEFAULT_FULL_COMMAND) != 0)
    {
        if(string_compare_with_wildcards(execve_rule->full_command, event->full_command) == 0)
        {
            return 0;
        }
    }

    if(execve_rule->uid != DEFAULT_UID)
    {
        if(event->uid != execve_rule->uid)
        {
            return 0;
        }
    }

    if(execve_rule->gid != DEFAULT_GID)
    {
        if(event->gid != execve_rule->gid)
        {
            return 0;
        }
    }

    if(execve_rule->argc != DEFAULT_ARGC)
    {
        if(event->argc != execve_rule->argc)
        {
            return 0;
        }
    }

    print_matched_execve_rule(event, execve_rule);
    return 1;
}

static int is_open_event_match_rule(const open_event *event, const struct open_rule *open_rule)
{
    if(strcmp(open_rule->binary_path, DEFAULT_BINARY_PATH) != 0)
    {
        if(string_compare_with_wildcards(open_rule->binary_path, event->binary_path) == 0)
        {
            return 0;
        }
    }

    if(strcmp(open_rule->full_command, DEFAULT_FULL_COMMAND) != 0)
    {
        if(string_compare_with_wildcards(open_rule->full_command, event->full_command) == 0)
        {
            return 0;
        }
    }

    if(strcmp(open_rule->target_path, DEFAULT_TARGET_PATH) != 0)
    {
        if(string_compare_with_wildcards(open_rule->target_path, event->target_path) == 0)
        {
            return 0;
        }
    }

    if(open_rule->uid != DEFAULT_UID)
    {
        if(event->uid != open_rule->uid)
        {
            return 0;
        }
    }

    if(open_rule->gid != DEFAULT_GID)
    {
        if(event->gid != open_rule->gid)
        {
            return 0;
        }
    }

    if(open_rule->flags != DEFAULT_FLAGS)
    {
        if((event->flags & open_rule->flags) != open_rule->flags)
        {
            return 0;
        }
    }

    if(open_rule->mode != DEFAULT_MODE)
    {
        if((event->mode & open_rule->mode) != open_rule->mode)
        {
            return 0;
        }
    }

    print_matched_open_rule(event, open_rule);
    return 1;
}

static struct rule * does_execve_event_match_rule_raw(const execve_event *event)
{
    struct rules_list *temp;
    list_for_each_entry(temp, &rules_list_head, list) 
    {
        if(temp->rule.type == execve_rule_type)
        {
            if(is_execve_event_match_rule(event, &temp->rule.data.execve))
            {
                return &temp->rule;
            }
        }
    }

    return NULL;
}

static struct rule * does_open_event_match_rule_raw(const open_event *event)
{
    struct rules_list *temp;
    list_for_each_entry(temp, &rules_list_head, list) 
    {
        if(temp->rule.type == open_rule_type)
        {
            if(is_open_event_match_rule(event, &temp->rule.data.open))
            {
                return &temp->rule;
            }
        }
    }

    return NULL;
}

static void build_execve_rule(struct rule *rule, struct rules_list * new_node)
{
    new_node->rule.type = execve_rule_type;
    memset(new_node->rule.data.execve.binary_path, 0, PATH_MAX);
    memset(new_node->rule.data.execve.full_command, 0, PATH_MAX);
    strncpy(new_node->rule.data.execve.binary_path, rule->data.execve.binary_path, PATH_MAX);
    strncpy(new_node->rule.data.execve.full_command, rule->data.execve.full_command, PATH_MAX);
    new_node->rule.data.execve.uid = rule->data.execve.uid;
    new_node->rule.data.execve.gid = rule->data.execve.gid;
    new_node->rule.data.execve.argc = rule->data.execve.argc;
    new_node->rule.data.execve.prevention = rule->data.execve.prevention;
}

static void build_open_rule(struct rule *rule, struct rules_list * new_node)
{
    new_node->rule.type = open_rule_type;
    memset(new_node->rule.data.open.binary_path, 0, PATH_MAX);
    memset(new_node->rule.data.open.full_command, 0, PATH_MAX);
    memset(new_node->rule.data.open.target_path, 0, PATH_MAX);
    strncpy(new_node->rule.data.open.binary_path, rule->data.open.binary_path, PATH_MAX);
    strncpy(new_node->rule.data.open.full_command, rule->data.open.full_command, PATH_MAX);
    strncpy(new_node->rule.data.open.target_path, rule->data.open.target_path, PATH_MAX);
    new_node->rule.data.open.uid = rule->data.open.uid;
    new_node->rule.data.open.gid = rule->data.open.gid;
    new_node->rule.data.open.flags = rule->data.open.flags;
    new_node->rule.data.open.mode = rule->data.open.mode;
    new_node->rule.data.open.prevention = rule->data.open.prevention;
}

int add_rule(struct rule *rule)
{
    struct rules_list * new_node = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
    if(unlikely(new_node == NULL))
    {
        pr_alert("failled to allocate new rule\n");
        return ENOMEM;
    }

    if (rule->type == execve_rule_type)
    {
        build_execve_rule(rule, new_node);
        are_there_execve_rules = 1;
    }
    else if(rule->type == open_rule_type)
    {
        build_open_rule(rule, new_node);
        are_there_open_rules = 1;
    }
    else
    {
        pr_alert("unsported rule type\n");
        kfree(new_node);
        return EINVAL;
    }

    unsigned long flags; 
    write_lock_irqsave(&rules_list_rw_lock, flags); 
    list_add_tail(&new_node->list, &rules_list_head);
    write_unlock_irqrestore(&rules_list_rw_lock, flags); 
    return 0;
}

void print_rules(void)
{
    unsigned long flags; 
    read_lock_irqsave(&rules_list_rw_lock, flags);
    print_rules_raw();
    read_unlock_irqrestore(&rules_list_rw_lock, flags); 
}

void delete_rules(void)
{
    unsigned long flags; 
    write_lock_irqsave(&rules_list_rw_lock, flags); 
    delete_rules_raw();
    write_unlock_irqrestore(&rules_list_rw_lock, flags);
    are_there_execve_rules = 0;
    are_there_open_rules = 0;
}

struct rule * does_open_event_match_rule(const open_event *event)
{
    struct rule *rule;
    unsigned long flags;
    read_lock_irqsave(&rules_list_rw_lock, flags);
    rule = does_open_event_match_rule_raw(event);
    read_unlock_irqrestore(&rules_list_rw_lock, flags);
    return rule;
}

struct rule * does_execve_event_match_rule(const execve_event *event)
{
    struct rule *rule;
    unsigned long flags; 
    read_lock_irqsave(&rules_list_rw_lock, flags);
    rule = does_execve_event_match_rule_raw(event);
    read_unlock_irqrestore(&rules_list_rw_lock, flags); 
    return rule;
}