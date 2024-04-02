#include "Exclusions.h"
#include "../StringUtils.h"

#include <linux/slab.h>
#include <linux/rwlock.h> 

LIST_HEAD(excluded_binary_list_head);
static DEFINE_RWLOCK(excluded_binary_list_rw_lock);

int add_binary_to_excluded_list(char * binary_path)
{
    if(!binary_path)
    {
        return -EINVAL;
    }

    struct excluded_binary_list * new_node = kmalloc(sizeof(struct excluded_binary_list), GFP_KERNEL);
    if(unlikely(new_node == NULL))
    {
        pr_alert("failled to allocate new excluded_binary_list\n");
        return -ENOMEM;
    }

    int len = strlen(binary_path);
    new_node->binary_path = kmalloc(len + 1, GFP_KERNEL);
    if(unlikely(!new_node->binary_path))
    {
        pr_alert("failled to allocate new binary_path_copy\n");
        return -ENOMEM;
    }

    memset(new_node->binary_path, 0, len + 1);
    strcpy(new_node->binary_path, binary_path);
    new_node->binary_path[len] = '\0';

    unsigned long flags; 
    write_lock_irqsave(&excluded_binary_list_rw_lock, flags); 
    list_add_tail(&new_node->list, &excluded_binary_list_head);
    write_unlock_irqrestore(&excluded_binary_list_rw_lock, flags); 
    return 0;
}

static int is_binary_excluded_raw(char * binary_path)
{
    struct excluded_binary_list *temp;
    list_for_each_entry(temp, &excluded_binary_list_head, list)
    {
        if(string_compare_with_wildcards(temp->binary_path, binary_path))
        {
            return 1;
        }
    }
    return 0;
}

static void print_all_exclusions_raw(void)
{
    pr_info("\n-------- printing exclusions: --------\n");
    struct excluded_binary_list *temp;
    list_for_each_entry(temp, &excluded_binary_list_head, list)
    {
        pr_info("binary_path: %s\n", temp->binary_path);
    }
}

static void delete_exclusions_raw(void)
{
    struct excluded_binary_list *temp, *next;
    list_for_each_entry_safe(temp, next, &excluded_binary_list_head, list)
    {
        list_del(&temp->list);
        kfree(temp->binary_path);
        kfree(temp);
    }
}

int is_binary_excluded(char * binary_path)
{
    int rv;
    unsigned long flags;
    read_lock_irqsave(&excluded_binary_list_rw_lock, flags);
    rv = is_binary_excluded_raw(binary_path);
    read_unlock_irqrestore(&excluded_binary_list_rw_lock, flags);
    return rv;
}

void delete_exclusions(void)
{
    unsigned long flags; 
    write_lock_irqsave(&excluded_binary_list_rw_lock, flags); 
    delete_exclusions_raw();
    write_unlock_irqrestore(&excluded_binary_list_rw_lock, flags); 
}

void print_all_exclusions(void)
{
    unsigned long flags; 
    read_lock_irqsave(&excluded_binary_list_rw_lock, flags);
    print_all_exclusions_raw();
    read_unlock_irqrestore(&excluded_binary_list_rw_lock, flags); 
}