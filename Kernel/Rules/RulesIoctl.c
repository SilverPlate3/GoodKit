#include "../IoctlContracts.h"
#include "RulesIoctl.h"

#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>

enum { 
    NOT_USED = 0, 
    USED = 1, 
}; 

static atomic_t good_kit_rules_file_open = ATOMIC_INIT(NOT_USED); 

static long good_kit_rules_ioctl_main_callback(struct file *file, unsigned int ioctl_num, unsigned long parameter) 
{
    pr_info("good_kit_rules_ioctl_main_callback\n");
    if (atomic_cmpxchg(&good_kit_rules_file_open, NOT_USED, USED)) 
    {
        pr_alert("good_kit_rules_ioctl_main_callback - file is already open\n");
        return -EBUSY; 
    }
    
    int rv = 0;
    switch (ioctl_num) 
    {
        case ADD_RULE:
        {
            pr_info("good_kit_rules_ioctl_main_callback - ADD_RULE\n");
            struct rule *rule = kmalloc(sizeof(struct rule), GFP_KERNEL);
            if (unlikely(!rule)) 
            {
                pr_alert("good_kit_rules_ioctl_main_callback - failed to allocate memory for rule");
                rv = -ENOMEM;
                goto good_kit_rules_ioctl_main_callback_exit;
            }

            if(copy_from_user(rule, (struct rule *)parameter, sizeof(struct rule)))
            {
                pr_alert("good_kit_rules_ioctl_main_callback - failed to copy rule from user");
                kfree(rule);
                rv = -EFAULT;
                goto good_kit_rules_ioctl_main_callback_exit;
            }

            add_rule(rule);
            kfree(rule);
            break;
        }
        case PRINT_ALL_RULLES:
        {
            pr_info("good_kit_rules_ioctl_main_callback - PRINT_ALL_RULLES\n");
            print_rules();
            break;
        }
        case DELETE_RULES:
        {
            pr_info("good_kit_rules_ioctl_main_callback - DELETE_RULES\n");
            delete_rules();
            break;
        }
        default:
        {
            pr_alert("good_kit_rules_ioctl_main_callback - ioctl_num not found\n");
            rv = -EINVAL;
            goto good_kit_rules_ioctl_main_callback_exit;
        }
    }

good_kit_rules_ioctl_main_callback_exit:
    atomic_set(&good_kit_rules_file_open, NOT_USED); 
    return rv; 
}

static int good_kit_rules_open(struct inode *inode, struct file *file)
{
        try_module_get(THIS_MODULE); 
        return 0;
}

static int good_kit_rules_release(struct inode *inode, struct file *file) 
{ 
    module_put(THIS_MODULE); 
    return 0; 
} 

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = good_kit_rules_open,
    .release        = good_kit_rules_release,
    .unlocked_ioctl = good_kit_rules_ioctl_main_callback
};

//Misc device structure
static struct miscdevice good_kit_rules_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = RULES_DEVICE_NAME,
    .fops = &fops,
};

int register_rules_device(void)
{
    int error = misc_register(&good_kit_rules_misc_device);
    if (error != 0) 
    {
        pr_info("misc_register failed. error: %d\n", error);
    }
    return error;
}

void deregister_rules_device(void)
{
    misc_deregister(&good_kit_rules_misc_device);
}