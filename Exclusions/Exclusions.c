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

int is_binary_excluded(char * binary_path)
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