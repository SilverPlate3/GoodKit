#include "Rules.h"
#include "StringUtils.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/rwlock.h> 

LIST_HEAD(rules_list_head);

// TODO: Make the critical section smaller. Only list_add_tail should be in the critical section.
static int add_rule_raw(struct rule *rule)
{
    struct rules_list * new_node = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
    if(unlikely(new_node == NULL))
    {
        pr_alert("failled to allocate new rule\n");
        return ENOMEM;
    }

    if (rule->type == execve_rule_type)
    {
        memset(new_node->rule.data.execve.binary_path, 0, PATH_MAX);
        memset(new_node->rule.data.execve.full_command, 0, PATH_MAX);
        strncpy(new_node->rule.data.execve.binary_path, rule->data.execve.binary_path, PATH_MAX);
        strncpy(new_node->rule.data.execve.full_command, rule->data.execve.full_command, PATH_MAX);
        new_node->rule.data.execve.uid = rule->data.execve.uid;
        new_node->rule.data.execve.gid = rule->data.execve.gid;
        new_node->rule.data.execve.argc = rule->data.execve.argc;
        new_node->rule.data.execve.prevention = rule->data.execve.prevention;
    }
    else
    {
        pr_alert("unsported rule type\n");
        kfree(new_node);
        return EINVAL;
    }

    list_add_tail(&new_node->list, &rules_list_head);
    return 0;
}

static void print_rules_raw(void)
{
    struct rules_list *temp;
    list_for_each_entry(temp, &rules_list_head, list) 
    {
        if(temp->rule.type == execve_rule_type)
        {
            pr_info("\n-------- execve rule -----------\nbinary_path: %s\nfull_command: %s\nuid: %d\ngid: %d\nargc: %d\n prevention: %d\n",
                    temp->rule.data.execve.binary_path,
                    temp->rule.data.execve.full_command,
                    temp->rule.data.execve.uid,
                    temp->rule.data.execve.gid,
                    temp->rule.data.execve.argc,
                    temp->rule.data.execve.prevention);
        }
        else
        {
            pr_alert("unsuported rule type\n");
        }
    }
}

static void delete_rules_raw(void)
{
    struct rules_list *temp, *next;
    list_for_each_entry_safe(temp, next, &rules_list_head, list) 
    {
        if(temp->rule.type == execve_rule_type)
        {
            pr_info("\n------- deleting execve rule --------\nbinary_path: %s\nfull_command: %s\nuid: %d\ngid: %d\nargc: %d\nprevention: %d\n",
            temp->rule.data.execve.binary_path,
            temp->rule.data.execve.full_command,
            temp->rule.data.execve.uid,
            temp->rule.data.execve.gid,
            temp->rule.data.execve.argc,
            temp->rule.data.execve.prevention);
        }
        else
        {
            pr_alert("deleting unsuported rule type\n");
        }
        list_del(&temp->list);
        kfree(temp);
    }
}

static void print_matched_execve_rule(const execve_event *event, const struct execve_rule *execve_rule)
{
    pr_info("execve event match rule.\nRule.binary_path: '%s' Event.binary_path: '%s'\nRule.full_command: '%s' Event.full_command: '%s'\nRule.uid: %d Event.uid: %d\nRule.gid: %d Event.gid: %d\nRule.argc: %d Event.argc: %d\n",
            execve_rule->binary_path, event->binary_path, execve_rule->full_command, event->full_command, execve_rule->uid, event->uid, execve_rule->gid, event->gid, execve_rule->argc, event->argc);

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

static struct rule * does_event_match_rule_raw(const execve_event *event)
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
        else
        {
            pr_alert("unsuported rule type\n");
        }
    }

    return NULL;
}

static DEFINE_RWLOCK(rules_list_rw_lock); 

int add_rule(struct rule *rule)
{
    int ret;
    unsigned long flags; 
    write_lock_irqsave(&rules_list_rw_lock, flags); 
    ret = add_rule_raw(rule);
    write_unlock_irqrestore(&rules_list_rw_lock, flags); 
    return ret;
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
}

struct rule * does_event_match_rule(const execve_event *event)
{
    struct rule *rule;
    unsigned long flags; 
    read_lock_irqsave(&rules_list_rw_lock, flags);
    rule = does_event_match_rule_raw(event);
    read_unlock_irqrestore(&rules_list_rw_lock, flags); 
    return rule;
}