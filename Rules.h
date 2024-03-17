#pragma once

#include <linux/limits.h>
#include <linux/types.h>
#include <linux/slab.h>

enum rule_type
{
    execve
}

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
    rule_type type;
    union data
    {
        execve_rule execve;
    }
}

struct rules_list
{
    struct list_head list;
    struct rule rule;
};

LIST_HEAD(rules_list_head);

int add_rule(union rule *rule)
{
    struct rules_list * new_node = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
    if(unlikely(temp_node == NULL))
    {
        pr_alert("failled to allocate new rule\n");
        return ENOMEM;
    }

    if rule->type == execve
    {
        memset(rule->binary_path, 0, PATH_MAX);
        memset(rule->binary_path, 0, PATH_MAX);
        strncpy(new_node->rule.binary_path, rule->binary_path, PATH_MAX);
        strncpy(new_node->rule.full_command, rule->full_command, PATH_MAX);
        new_node->rule.uid = rule->uid;
        new_node->rule.gid = rule->gid;
        new_node->rule.argc = rule->argc;
        new_node->rule.prevention = rule->prevention;
    }
    else
    {
        pr_alert("unsported rule type\n");
        kfree(new_node);
        return EINVAL;
    }

    list_add(&new_node->list, &rules_list_head);
    return 0;
}

void print_rules()
{
    struct rules_list *temp;
    list_for_each_entry(temp, &rules_list_head, list) 
    {
        if(temp->rule.type == execve)
        {
            pr_info("binary_path: %s\n
                    full_command: %s\n
                    uid: %d\n
                    gid: %d\n
                    argc: %d\n
                    prevention: %d\n",
                    temp->rule.execve.binary_path,
                    temp->rule.execve.full_command,
                    temp->rule.execve.uid,
                    temp->rule.execve.gid,
                    temp->rule.execve.argc,
                    temp->rule.execve.prevention);
        }
        else
        {
            pr_alert("unsuported rule type\n");
        }
    }
}

void delete_rules()
{
    struct rules_list *temp, *next;
    list_for_each_entry_safe(temp, next, &rules_list_head, list) 
    {
        if(temp->rule.type == execve)
        {
            pr_info("deleting binary_path: %s\n
            full_command: %s\n
            uid: %d\n
            gid: %d\n
            argc: %d\n
            prevention: %d\n",
            temp->rule.execve.binary_path,
            temp->rule.execve.full_command,
            temp->rule.execve.uid,
            temp->rule.execve.gid,
            temp->rule.execve.argc,
            temp->rule.execve.prevention);
        }
        else
        {
            pr_alert("deleting unsuported rule type\n");
        }
        list_del(&temp->list);
        kfree(temp);
    }
}