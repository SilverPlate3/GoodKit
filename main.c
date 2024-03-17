#include <linux/delay.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/cred.h> /* For current_uid() */ 
#include <linux/uidgid.h> /* For __kuid_val() */ 
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/sched.h> 
#include <linux/kprobes.h> 

#include "StringUtils.h"
#include "Rules.h"

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
    const char __user *__filename = (const char __user *)regs->di;
    const char __user *const __user *__argv = (const char __user *const __user *)regs->si;

    uid_t uid = __kuid_val(current_uid());
    gid_t gid = __kgid_val(current_gid());

    int filename_len = strnlen_user(__filename, PATH_MAX);
    char *filename = kmalloc(filename_len+1, GFP_KERNEL);
    if (unlikely(!filename))
    {
        pr_info("Failed to allocate memory for filename\n");
        goto call_original_execve;
    }
    if(copy_from_user(filename, __filename, filename_len))
    {
        pr_info("Failed to copy filename from user space\n");
        goto free_file_name_and_call_original_execve;
    }
    filename[filename_len] = '\0'; 

    MKVAR(const char __user *const __user *, argv, __argv);
    char * full_command = kmalloc(MAX_ARG_LENGTH, GFP_KERNEL);
    if (unlikely(!full_command))
    {
        pr_info("Failed to allocate memory for full_command\n");
        goto free_file_name_and_call_original_execve;
    }

    int argc = join_strings_from_user(argv, " ", full_command, MAX_ARG_LENGTH);
    full_command[MAX_ARG_LENGTH - 1] = '\0';
    pr_info("gid: %d uid: %d, argc: %d, binary: '%s', Full command: '%s'\n", gid, uid, argc, filename, full_command);
    if(string_compare_with_wildcards("ping*", full_command))
    {
        pr_info("Blocked ping\n");
        goto execve_prevention;
    }

    kfree(full_command);
free_file_name_and_call_original_execve:
    kfree(filename);
call_original_execve:
    return original_execve(regs);

execve_prevention:
        kfree(full_command);
        kfree(filename);
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

static int __init good_kit_init(void) 
{
    if (!(sys_call_table_stolen = acquire_sys_call_table())) 
    {
        pr_info("acquire_sys_call_table failed\n");
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
}

module_init(good_kit_init); 
module_exit(good_kit_exit); 
 
MODULE_LICENSE("GPL");