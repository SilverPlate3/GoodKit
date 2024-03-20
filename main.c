#include <linux/module.h> 
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/sched.h> 
#include <linux/kprobes.h> 
#include <linux/miscdevice.h>

#include "ExecveEvent.h"
#include "IoctlContracts.h"

#ifndef CONFIG_KPROBES
#error "CONFIG_KPROBES is not defined but is required."
#endif

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#error "CONFIG_ARCH_HAS_SYSCALL_WRAPPER is not defined but is required."
#endif

#define MKVAR(Type, Name, From) Type Name = (Type)(From);
#define MAX_ARG_LENGTH 1024

static unsigned long **sys_call_table_stolen; 
static asmlinkage long (*original_execve)(const struct pt_regs *);

static asmlinkage long our_sys_execve(const struct pt_regs *regs) 
{
    execve_event * event = create_execve_event(regs);
    if(!event)
    {
        goto call_original_execve;
    }

    // pr_info("gid: %d uid: %d, argc: %d, binary: '%s', Full command: '%s'\n", gid, uid, argc, filename, full_command);
    // if(string_compare_with_wildcards("ping*", full_command))
    // {
    //     pr_info("Blocked ping\n");
    //     goto execve_prevention;
    // }

call_original_execve:
    return original_execve(regs);

execve_prevention:
        return -EPERM;
}

static unsigned long **acquire_sys_call_table(void) 
{  
    unsigned long (*kallsyms_lookup_name)(const char *name); 
    struct kprobe kp = { 
        .symbol_name = "kallsyms_lookup_name", 
    }; 
 
    if (register_kprobe(&kp) < 0) 
        return NULL; 
    kallsyms_lookup_name = (unsigned long (*)(const char *name))kp.addr; 
    unregister_kprobe(&kp); 
 
    return (unsigned long **)kallsyms_lookup_name("sys_call_table"); 
} 

static inline void __write_cr0(unsigned long cr0) 
{ 
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory"); 
} 

static void enable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    set_bit(16, &cr0); 
    __write_cr0(cr0); 
} 
 
static void disable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    clear_bit(16, &cr0); 
    __write_cr0(cr0); 
} 

enum { 
    NOT_USED = 0, 
    USED = 1, 
}; 

static atomic_t good_kit_rules_file_open = ATOMIC_INIT(NOT_USED); 

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
            if (!rule) 
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

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = good_kit_rules_open,
    .release        = good_kit_rules_release,
    .unlocked_ioctl = good_kit_rules_ioctl_main_callback
};

//Misc device structure
struct miscdevice good_kit_rules_misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = RULES_DEVICE_NAME,
    .fops = &fops,
};

static int __init good_kit_init(void) 
{
    pr_info("9------------------------------\n");
    sys_call_table_stolen = acquire_sys_call_table();
    if (!sys_call_table_stolen) 
    {
        pr_info("acquire_sys_call_table failed\n");
        return -1; 
    }

    if (misc_register(&good_kit_rules_misc_device)) 
    {
        pr_info("misc_register failed\n");
        return -1; 
    }
    
    disable_write_protection(); 
    original_execve = (void *)sys_call_table_stolen[__NR_execve];
    sys_call_table_stolen[__NR_execve] = (unsigned long *)our_sys_execve; 
    enable_write_protection(); 

    pr_info("Finished hooking syscall table\n");
    return 0;
}

static void __exit good_kit_exit(void) 
{
    if (!sys_call_table_stolen) 
        return; 

    disable_write_protection(); 
    sys_call_table_stolen[__NR_execve] = (unsigned long *)original_execve; 
    enable_write_protection(); 

    delete_rules();
    misc_deregister(&good_kit_rules_misc_device);
}

module_init(good_kit_init); 
module_exit(good_kit_exit); 
 
MODULE_LICENSE("GPL");

/*
struct rule * rule1 = kmalloc(sizeof(struct rule), GFP_KERNEL);
    rule1->type = execve;
    rule1->data.execve.argc = 2;
    memset(rule1->data.execve.binary_path, 0, sizeof(rule1->data.execve.binary_path));
    memset(rule1->data.execve.full_command, 0, sizeof(rule1->data.execve.full_command));
    strncpy(rule1->data.execve.binary_path, "rule 1 has everything", sizeof(rule1->data.execve.binary_path));
    strncpy(rule1->data.execve.full_command, "cccc.exe -n 123456789 abcde :/d!@#$%^&*()", sizeof(rule1->data.execve.full_command));
    rule1->data.execve.gid = 99;
    rule1->data.execve.uid = 88;
    rule1->data.execve.prevention = 1;

    struct rule * rule2 = kmalloc(sizeof(struct rule), GFP_KERNEL);
    rule2->type = execve;
    rule2->data.execve.argc = 2;
    memset(rule2->data.execve.binary_path, 0, sizeof(rule2->data.execve.binary_path));
    memset(rule2->data.execve.full_command, 0, sizeof(rule2->data.execve.full_command));
    strncpy(rule2->data.execve.binary_path, "rule 2 no execve, uid, prevention", sizeof(rule2->data.execve.binary_path));
    rule2->data.execve.gid = 99;

    struct rule * rule3 = kmalloc(sizeof(struct rule), GFP_KERNEL);
    rule3->type = execve;
    memset(rule3->data.execve.binary_path, 0, sizeof(rule3->data.execve.binary_path));
    memset(rule3->data.execve.full_command, 0, sizeof(rule3->data.execve.full_command));
    strncpy(rule3->data.execve.full_command, "rule 3 has only full_command", sizeof(rule3->data.execve.full_command));

    struct rule * rule4 = kmalloc(sizeof(struct rule), GFP_KERNEL);
    rule4->type = 3;

    add_rule(rule1);
    add_rule(rule2);
    print_rules();
    add_rule(rule3);
    add_rule(rule4);
    print_rules();
*/