#include "OpenEvent.h"
#include "EventCommon.h"
#include "../Exclusions/Exclusions.h"

#include <linux/cred.h> /* For current_uid() */ 
#include <linux/uidgid.h> /* For __kuid_val() */ 
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string_helpers.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_struct.h>

char * gut_current_task_binary_path(void)
{
    char exe_path [PATH_MAX]; // TODO: Dynamic allocation

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

static open_event * open_event_defaults(const struct pt_regs *regs)
{
    char * binary_path = gut_current_task_binary_path();
    if(binary_path && is_binary_excluded(binary_path))
    {
        kfree(binary_path);
        return NULL;
    }

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

open_event * create_open_event(const struct pt_regs *regs)
{
    open_event *event = open_event_defaults(regs);
    if(unlikely(!event))
    {
        return NULL;
    }
    
    event->flags = regs->si;
    event->mode = regs->dx;

    const char __user *__filename = (const char __user *)regs->di;
    char * target_path = get_path_from_user_space(__filename);
    if(target_path)
    {
        strncpy(event->target_path, target_path, strlen(target_path));
        kfree(target_path);
    }

    return event;
}

static struct file * get_file_object_from_fd(int fd)
{
    if(fd == AT_FDCWD)
    {
        return NULL;
    }

    struct fd fd_struct = __to_fd(__fdget(fd));
    struct file *file = fd_struct.file;
    if (!file) 
    {
        if(fd > 0 && fd < NR_OPEN_DEFAULT)
        {
            file = current->files->fd_array[fd];
        }
    }
    
    return file;
}

static void get_dir_path_from_fd(int fd, char * output)
{
    spin_lock(&current->files->file_lock);
    struct file * file = get_file_object_from_fd(fd);
    if(!file)
    {
        spin_unlock(&current->files->file_lock);
        return;
    }
    
    struct path * dir_path = &file->f_path;
    path_get(dir_path);
    spin_unlock(&current->files->file_lock);

    char *tmp = kmalloc(PATH_MAX, GFP_KERNEL);
    if(unlikely(!tmp))
    {
        path_put(dir_path);
        return;
    }

    char *dir_path_name = d_path(dir_path, tmp, PATH_MAX);
    path_put(dir_path);
    if (!IS_ERR(dir_path_name)) 
    {
        strncpy(output, dir_path_name, strlen(dir_path_name));
        strcat(output, "/");
    }
    kfree(tmp);
}

static void append_cwd_to_path(char * path)
{
    spin_lock(&current->fs->lock);
    struct path pwd = current->fs->pwd;
    path_get(&pwd);
    char *buf = (char *)kmalloc(GFP_KERNEL, PATH_MAX);
    char *cwd = d_path(&pwd, buf, PATH_MAX);
    path_put(&pwd);
    spin_unlock(&current->fs->lock);
    strcat(path, cwd);
    strcat(path, "/");
    kfree(buf);
}

open_event * create_openat_event(const struct pt_regs *regs)
{
    open_event *event = open_event_defaults(regs);
    if(unlikely(!event))
    {
        return NULL;
    }

    event->flags = regs->dx;
    event->mode = regs->r10;

    int fd = regs->di;
    get_dir_path_from_fd(fd, event->target_path);

    const char __user *__filename = (const char __user *)regs->si;
    const char * filename = get_path_from_user_space(__filename);
    if(filename)
    {
        if(fd == AT_FDCWD && filename[0] != '/')
        {
            append_cwd_to_path(event->target_path);
        }
        strcat(event->target_path, filename);
    }
    return event;
}