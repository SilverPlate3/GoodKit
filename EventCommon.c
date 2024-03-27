#include "EventCommon.h"

#include <linux/uaccess.h> 
#include <linux/slab.h>

char * get_binary_path(const char __user *__filename)
{
    int filename_len = strnlen_user(__filename, PATH_MAX);
    char *filename = kmalloc(filename_len, GFP_KERNEL);
    if (unlikely(!filename))
    {
        pr_info("Failed to allocate memory for filename\n");
        return NULL;
    }
    if(copy_from_user(filename, __filename, filename_len))
    {
        pr_info("Failed to copy filename from user space\n");
        kfree(filename);
        return NULL;
    }
    filename[filename_len - 1] = '\0'; 
    return filename;
}