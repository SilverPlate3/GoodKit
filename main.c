#include "ExecveEvent.h"
#include "IoctlContracts.h"
#include "RulesIoctl.h"

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

#define MKVAR(Type, Name, From) Type Name = (Type)(From);
#define MAX_ARG_LENGTH 1024

static unsigned long **sys_call_table_stolen; 
static asmlinkage long (*original_execve)(const struct pt_regs *);

static asmlinkage long our_sys_execve(const struct pt_regs *regs) 
{
    execve_event * event = create_execve_event(regs);
    if(!event)
    {
        pr_info("create_execve_event failed\n");
        goto call_original_execve;
    }

    struct rule * rule = does_event_match_rule(event);
    if(!rule)
    {
        goto call_original_execve;
    }
    else
    {
        struct execve_rule * execve_rule = &rule->data.execve;
        pr_info("execve event match rule.\nRule.binary_path: '%s' Event.binary_path: '%s'\nRule.full_command: '%s' Event.full_command: '%s'\nRule.uid: %d Event.uid: %d\nRule.gid: %d Event.gid: %d\nRule.argc: %d Event.argc: %d\n",
            execve_rule->binary_path, event->binary_path, execve_rule->full_command, event->full_command, execve_rule->uid, event->uid, execve_rule->gid, event->gid, execve_rule->argc, event->argc);

        goto execve_prevention;
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

static int __init good_kit_init(void) 
{
    pr_info("9------------------------------\n");
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
    deregister_rules_device();
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