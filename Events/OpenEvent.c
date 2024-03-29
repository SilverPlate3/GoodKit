#include "OpenEvent.h"
#include "EventCommon.h"

#include <linux/cred.h> /* For current_uid() */ 
#include <linux/uidgid.h> /* For __kuid_val() */ 
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string_helpers.h>

char * gut_current_task_binary_path(void)
{
    char exe_path [PATH_MAX];

    struct mm_struct * mm = get_task_mm(current);
    if(!mm)
    {
        pr_info("gut_current_task_binary_path - Failed to get mm_struct\n");
        return NULL;
    }

    mmap_read_lock(mm);
    struct file * exe_file = mm->exe_file;
    if (exe_file) 
    {
        get_file(exe_file);
    }
    mmap_read_unlock(mm);
    mmput(mm);

    char * binary_path = d_path( &(exe_file->f_path), exe_path, sizeof(exe_path) * sizeof(char) );
    if(IS_ERR(binary_path))
    {
        pr_info("gut_current_task_binary_path - Failed to get binary path\n");
        return NULL;
    }

    char *returned_binary_path = kmalloc(strlen(binary_path) + 1, GFP_KERNEL);
    if(unlikely(!returned_binary_path))
    {
        pr_info("gut_current_task_binary_path - Failed to allocate memory for returned_binary_path\n");
        return NULL;
    }
    memset(returned_binary_path, 0, strlen(binary_path) + 1);
    strncpy(returned_binary_path, binary_path, strlen(binary_path));
    returned_binary_path[strlen(binary_path)] = '\0';

    return returned_binary_path;
}

open_event * create_open_event(const struct pt_regs *regs)
{
    open_event *event = kmalloc(sizeof(open_event), GFP_KERNEL);
    if (unlikely(!event))
    {
        pr_info("Failed to allocate memory for execve_event\n");
        return NULL;
    }
    memset(event->binary_path, 0, PATH_MAX);
    memset(event->full_command, 0, PATH_MAX);
    memset(event->target_path, 0, PATH_MAX);

    event->uid = __kuid_val(current_uid());
    event->gid = __kgid_val(current_gid());
    
    const char __user *__filename = (const char __user *)regs->di;
    char * target_path = get_path_from_user_space(__filename);
    if(target_path)
    {
        strncpy(event->target_path, target_path, strlen(target_path));
        kfree(target_path);
    }

    event->flags = regs->si;
    event->mode = regs->dx;

    char * binary_path = gut_current_task_binary_path();
    if(binary_path)
    {
        strncpy(event->binary_path, binary_path, strlen(binary_path));
        kfree(binary_path);
    }

    char * full_command = kstrdup_quotable_cmdline(current, GFP_KERNEL);
    if(full_command)
    {
        strncpy(event->full_command, full_command, strlen(full_command));
        kfree(full_command);
    }

    return event;
}