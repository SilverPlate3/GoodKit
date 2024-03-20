#include "Rules.h"

#include <linux/types.h>
#include <linux/slab.h>

LIST_HEAD(rules_list_head);

int add_rule(struct rule *rule)
{
    struct rules_list * new_node = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
    if(unlikely(new_node == NULL))
    {
        pr_alert("failled to allocate new rule\n");
        return ENOMEM;
    }

    if (rule->type == execve)
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

void print_rules(void)
{
    struct rules_list *temp;
    list_for_each_entry(temp, &rules_list_head, list) 
    {
        if(temp->rule.type == execve)
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

void delete_rules(void)
{
    struct rules_list *temp, *next;
    list_for_each_entry_safe(temp, next, &rules_list_head, list) 
    {
        if(temp->rule.type == execve)
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