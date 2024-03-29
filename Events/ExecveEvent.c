#include "ExecveEvent.h"
#include "../StringUtils.h"
#include "EventCommon.h"

#include <linux/cred.h> /* For current_uid() */ 
#include <linux/uidgid.h> /* For __kuid_val() */ 
#include <linux/slab.h>

struct full_command_data 
{
    char * full_command;
    int argc;
};

static struct full_command_data * get_full_command_data(const char __user *const __user *__argv)
{
    struct full_command_data * full_command_data = kmalloc(sizeof(struct full_command_data), GFP_KERNEL);
    if(unlikely(!full_command_data))
    {
        pr_info("Failed to allocate memory for full_command_data\n");
        return NULL;
    }

    full_command_data->full_command = kmalloc(MAX_ARG_LENGTH, GFP_KERNEL);
    if (unlikely(!full_command_data->full_command))
    {
        pr_info("Failed to allocate memory for full_command_data->full_command\n");
        kfree(full_command_data);
        return NULL;
    }

    MKVAR(const char __user *const __user *, argv, __argv);
    full_command_data->argc = join_strings_from_user(argv, " ", full_command_data->full_command, MAX_ARG_LENGTH);
    full_command_data->full_command[MAX_ARG_LENGTH - 1] = '\0';
    return full_command_data;
}

execve_event * create_execve_event(const struct pt_regs *regs)
{
    execve_event *event = kmalloc(sizeof(execve_event), GFP_KERNEL);
    if (unlikely(!event))
    {
        pr_info("Failed to allocate memory for execve_event\n");
        return NULL;
    }
    memset(event->binary_path, 0, PATH_MAX);
    memset(event->full_command, 0, PATH_MAX);

    event->uid = __kuid_val(current_uid());
    event->gid = __kgid_val(current_gid());
    
    const char __user *__filename = (const char __user *)regs->di;
    char * binary_path = get_path_from_user_space(__filename);
    if(binary_path)
    {
        strncpy(event->binary_path, binary_path, strlen(binary_path));
        kfree(binary_path);
    }

    const char __user *const __user *__argv = (const char __user *const __user *)regs->si;
    struct full_command_data * full_command_data = get_full_command_data(__argv);
    if(full_command_data)
    {
        event->argc = full_command_data->argc;
        strncpy(event->full_command, full_command_data->full_command, strlen(full_command_data->full_command));
        kfree(full_command_data->full_command);
        kfree(full_command_data);
    }

    return event;
}