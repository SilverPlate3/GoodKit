#include "../IoctlContracts.h"
#include "ExclusionsIoctl.h"
#include "Exclusions.h"

#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>

enum { 
    NOT_USED = 0, 
    USED = 1, 
}; 

static atomic_t good_kit_exclusions_file_open = ATOMIC_INIT(NOT_USED); 

static long good_kit_exclusions_ioctl_main_callback(struct file *file, unsigned int ioctl_num, unsigned long parameter)
{
    pr_info("good_kit_exclusions_ioctl_main_callback\n");
    if (atomic_cmpxchg(&good_kit_exclusions_file_open, NOT_USED, USED)) 
    {
        pr_alert("good_kit_exclusions_ioctl_main_callback - file is already open\n");
        return -EBUSY; 
    }

    int rv = 0;
    switch (ioctl_num)
    {
    case ADD_BINARY_EXCLUSION:
    {
        pr_info("good_kit_exclusions_file_open - ADD_BINARY_EXCLUSION\n");
        __user char * binary_path_user = (__user char *)parameter;
        int binary_path_user_len = strnlen_user(binary_path_user, PATH_MAX);
        char * binary_path = kmalloc(binary_path_user_len + 1, GFP_KERNEL);
        if (unlikely(!binary_path))
        {
            pr_alert("good_kit_exclusions_ioctl_main_callback ADD_BINARY_EXCLUSION - kmalloc failed\n");
            rv = -ENOMEM;
            goto good_kit_exclusions_ioctl_main_callback_exit;
        }
        memset(binary_path, 0, binary_path_user_len + 1);

        if(copy_from_user(binary_path, binary_path_user, binary_path_user_len))
        {
            pr_alert("good_kit_exclusions_ioctl_main_callback ADD_BINARY_EXCLUSION - copy_from_user failed\n");
            kfree(binary_path);
            rv = -EFAULT;
            goto good_kit_exclusions_ioctl_main_callback_exit;
        }

        add_binary_to_excluded_list(binary_path);
        kfree(binary_path);
        break;
    }
    case PRINT_ALL_EXCLUSIONS:
    {
        pr_info("good_kit_exclusions_file_open - PRINT_ALL_EXCLUSIONS\n");
        print_all_exclusions();
        break;
    }
    case DELETE_EXCLUSIONS:
    {
        pr_info("good_kit_exclusions_file_open - DELETE_EXCLUSIONS\n");
        delete_exclusions();
        break;
    }
    default:
    {
        pr_alert("good_kit_exclusions_ioctl_main_callback_exit - ioctl_num not found\n");
        rv = -EINVAL;
        goto good_kit_exclusions_ioctl_main_callback_exit;
    }
    }

good_kit_exclusions_ioctl_main_callback_exit:
    atomic_set(&good_kit_exclusions_file_open, NOT_USED); 
    return rv;
}

static int good_kit_exclusions_open(struct inode *inode, struct file *file)
{
        try_module_get(THIS_MODULE); 
        return 0;
}

static int good_kit_exclusions_release(struct inode *inode, struct file *file) 
{ 
    module_put(THIS_MODULE); 
    return 0; 
} 

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = good_kit_exclusions_open,
    .release        = good_kit_exclusions_release,
    .unlocked_ioctl = good_kit_exclusions_ioctl_main_callback
};

static struct miscdevice good_kit_exclusions_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = EXCLUSIONS_DEVICE_NAME,
    .fops = &fops,
};

int register_exclusions_device(void)
{
    int error = misc_register(&good_kit_exclusions_misc_device);
    if (error != 0) 
    {
        pr_info("misc_register failed. error: %d\n", error);
    }
    return error;
}

void deregister_exclusions_device(void)
{
    misc_deregister(&good_kit_exclusions_misc_device);
}