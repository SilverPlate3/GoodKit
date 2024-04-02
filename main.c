#include "Events/ExecveEvent.h"
#include "IoctlContracts.h"
#include "Rules/RulesIoctl.h"
#include "Alert.h"
#include "Netlink/Netlink.h"
#include "ThreadManagment/ThreadManagment.h"
#include "Events/EventCommon.h"
#include "Events/OpenEvent.h"
#include "Exclusions/Exclusions.h"

#include <linux/module.h> 
#include <linux/limits.h>
#include <linux/sched.h> 
#include <linux/kprobes.h> 

#ifndef CONFIG_KPROBES
#error "CONFIG_KPROBES is not defined but is required."
#endif

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#error "CONFIG_ARCH_HAS_SYSCALL_WRAPPER is not defined but is required."
#endif

static unsigned long **sys_call_table_stolen; 
static asmlinkage long (*original_execve)(const struct pt_regs *);
static asmlinkage long (*original_open)(const struct pt_regs *);
static asmlinkage long (*original_openat)(const struct pt_regs *);

static asmlinkage long our_sys_execve(const struct pt_regs *regs) 
{
    if(!are_there_execve_rules)
    {
        goto call_original_execve;
    }

    execve_event * event = create_execve_event(regs);
    if(!event)
    {
        pr_info("create_execve_event failed\n");
        goto call_original_execve;
    }

    struct rule * rule = does_execve_event_match_rule(event);
    if(!rule)
    {
        kfree(event);
        goto call_original_execve;
    }
    
    execve_alert(rule, event);
    kfree(event);

    if(rule->data.execve.prevention == 1)
    {
        goto execve_prevention;
    }

call_original_execve:
    return original_execve(regs);

execve_prevention:
        return -EPERM;
}

static asmlinkage long our_sys_open(const struct pt_regs *regs) 
{
    if(!are_there_open_rules)
    {
        goto call_original_open;
    }

    open_event * event = create_open_event(regs);
    if(unlikely(!event))
    {
        pr_info("create_open_event failed\n");
        goto call_original_open;
    }

    struct rule * rule = does_open_event_match_rule(event);
    if(rule)
    {
        pr_info("matched open rule:  binary '%s' full_command %s target %s uid %d gid %d flags %d mode %d\n",
            rule->data.open.binary_path, rule->data.open.full_command, rule->data.open.target_path, rule->data.open.uid, rule->data.open.gid, rule->data.open.flags, rule->data.open.mode);        
    }

    kfree(event);

call_original_open:
    return original_open(regs);
}

static asmlinkage long our_sys_openat(const struct pt_regs *regs) 
{
    if(!are_there_open_rules)
    {
        goto call_original_openat;
    }

    open_event * event = create_openat_event(regs);
    if(unlikely(!event))
    {
        pr_info("create_openat_event failed\n");
        goto call_original_openat;
    }

    struct rule * rule = does_open_event_match_rule(event);
    if(rule)
    {
        pr_info("matched open rule:  binary '%s' full_command %s target %s uid %d gid %d flags %d mode %d\n",
            rule->data.open.binary_path, rule->data.open.full_command, rule->data.open.target_path, rule->data.open.uid, rule->data.open.gid, rule->data.open.flags, rule->data.open.mode);        
    }

    kfree(event);

call_original_openat:
    return original_openat(regs);
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
    sys_call_table_stolen = acquire_sys_call_table();
    if (!sys_call_table_stolen) 
    {
        pr_info("acquire_sys_call_table failed\n");
        return -1; 
    }

    if (register_rules_device()) 
    {
        return -1; 
    }

    if(!netlink_register())
    {
        return -1;
    }

    init_global_alert_threads_tracker();
    
    disable_write_protection(); 
    original_execve = (void *)sys_call_table_stolen[__NR_execve];
    original_open = (void *)sys_call_table_stolen[__NR_open];
    original_openat = (void *)sys_call_table_stolen[__NR_openat];
    sys_call_table_stolen[__NR_execve] = (unsigned long *)our_sys_execve; 
    sys_call_table_stolen[__NR_open] = (unsigned long *)our_sys_open; 
    sys_call_table_stolen[__NR_openat] = (unsigned long *)our_sys_openat;
    enable_write_protection(); 

    pr_info("Finished hooking syscall table\n");
    return 0;
}

static void __exit good_kit_exit(void) 
{
    pr_info("good_kit cleanup start\n");
    if (!sys_call_table_stolen) 
        return; 

    disable_write_protection(); 
    sys_call_table_stolen[__NR_execve] = (unsigned long *)original_execve; 
    sys_call_table_stolen[__NR_open] = (unsigned long *)original_open; 
    sys_call_table_stolen[__NR_openat] = (unsigned long *)original_openat;
    enable_write_protection(); 
    pr_info("Set original syscalls\n");

    ensure_no_alert_threads_are_running();
    pr_info("Set original syscalls\n");

    kfree(alert_threads_tracker);
    pr_info("Freed alert_threads_tracker\n");

    delete_rules();
    pr_info("Deleted rules\n");

    delete_exclusions();
    pr_info("Deleted exclusions\n");

    deregister_rules_device();
    pr_info("Deregistered rules device\n");

    netlink_unregister();
    pr_info("Unregistered netlink\n");
}

module_init(good_kit_init); 
module_exit(good_kit_exit); 
 
MODULE_LICENSE("GPL");