#include <linux/delay.h> 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/moduleparam.h> /* which will have params */ 
#include <linux/unistd.h> /* The list of system calls */ 
#include <linux/cred.h> /* For current_uid() */ 
#include <linux/uidgid.h> /* For __kuid_val() */ 
#include <linux/version.h> 
#include <linux/compat.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/limits.h>

/* For the current (process) structure, we need this to know who the 
 * current user is. 
 */ 
#include <linux/sched.h> 
#include <linux/uaccess.h> 
 
/* The way we access "sys_call_table" varies as kernel internal changes. 
 * - Prior to v5.4 : manual symbol lookup 
 * - v5.5 to v5.6  : use kallsyms_lookup_name() 
 * - v5.7+         : Kprobes or specific kernel module parameter 
 */ 
 
/* The in-kernel calls to the ksys_close() syscall were removed in Linux v5.11+. 
 */ 
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)) 
 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 0) 
#define HAVE_KSYS_CLOSE 1 
#include <linux/syscalls.h> /* For ksys_close() */ 
#else 
#include <linux/kallsyms.h> /* For kallsyms_lookup_name */ 
#endif 
 
#else 
 
#if defined(CONFIG_KPROBES) 
#define HAVE_KPROBES 1 
#include <linux/kprobes.h> 
#else 
#define HAVE_PARAM 1 
#include <linux/kallsyms.h> /* For sprint_symbol */ 
/* The address of the sys_call_table, which can be obtained with looking up 
 * "/boot/System.map" or "/proc/kallsyms". When the kernel version is v5.7+, 
 * without CONFIG_KPROBES, you can input the parameter or the module will look 
 * up all the memory. 
 */ 

#define __PT_PARM1_REG di
#define __PT_PARM2_REG si
#define __PT_PARM3_REG dx
#define __PT_SYSCALL_PARM4_REG r10
#define __PT_CCALL_PARM4_REG cx

#ifndef __PT_REGS_CAST
#define __PT_REGS_CAST(x) (x)
#endif

#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->__PT_PARM2_REG)
#define PT_REGS_PARM3(x) (__PT_REGS_CAST(x)->__PT_PARM3_REG)
#define PT_REGS_SYSCALL_PARM4(x) (__PT_REGS_CAST(x)->__PT_SYSCALL_PARM4_REG)
#define PT_REGS_CCALL_PARM4(x) (__PT_REGS_CAST(x)->__PT_CCALL_PARM4_REG)

static unsigned long sym = 0; 
module_param(sym, ulong, 0644); 
#endif /* CONFIG_KPROBES */ 
 
#endif /* Version < v5.7 */ 
 
static unsigned long **sys_call_table_stolen; 
 
/* UID we want to spy on - will be filled from the command line. */ 
static uid_t uid = -1; 
module_param(uid, int, 0644); 

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};
 
/* A pointer to the original system call. The reason we keep this, rather 
 * than call the original function (sys_openat), is because somebody else 
 * might have replaced the system call before us. Note that this is not 
 * 100% safe, because if another module replaced sys_openat before us, 
 * then when we are inserted, we will call the function in that module - 
 * and it might be removed before we are. 
 * 
 * Another reason for this is that we can not get sys_openat. 
 * It is a static variable, so it is not exported. 
 */ 
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER 
static asmlinkage long (*original_call)(const struct pt_regs *); 
static asmlinkage long (*original_execve)(const struct pt_regs *);
#else 
static asmlinkage long (*original_call)(int, const char __user *, int, umode_t); 
static asmlinkage long (*original_execve)(const char __user *, const char __user *const __user *, const char __user *const __user *); 
#endif 
 
/* The function we will replace sys_openat (the function called when you 
 * call the open system call) with. To find the exact prototype, with 
 * the number and type of arguments, we find the original function first 
 * (it is at fs/open.c). 
 * 
 * In theory, this means that we are tied to the current version of the 
 * kernel. In practice, the system calls almost never change (it would 
 * wreck havoc and require programs to be recompiled, since the system 
 * calls are the interface between the kernel and the processes). 
 */ 
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER 
static asmlinkage long our_sys_openat(const struct pt_regs *regs) 
#else 
static asmlinkage long our_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode) 
#endif 
{ 
    int i = 0; 
    char ch; 
 
    if (__kuid_val(current_uid()) != uid) 
        goto orig_call; 
 
    /* Report the file, if relevant */ 
    pr_info("Opened file by %d: ", uid); 
    do { 
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER 
        get_user(ch, (char __user *)regs->si + i); 
#else 
        get_user(ch, (char __user *)filename + i); 
#endif 
        i++; 
        pr_info("%c", ch); 
    } while (ch != 0); 
    pr_info("\n"); 
 
orig_call: 
    /* Call the original sys_openat - otherwise, we lose the ability to 
     * open files. 
     */ 
#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER 
    return original_call(regs); 
#else 
    return original_call(dfd, filename, flags, mode); 
#endif 
} 

// TODO: Make sure that the size of buff never execeeds bufcap. Maybe it does it automatically.
#define MKVAR(Type, Name, From) Type Name = (Type)(From);
int join_strings_from_user(const char __user *const __user *ups, const char *delim, char *buff, size_t bufcap)
{
    int index;
    const char __user* up;
    char tmp[1024];

    if (copy_from_user(&up, ups, sizeof up))
        return NULL;
    if (strncpy_from_user(buff, up, bufcap) <= 0)
        return NULL;

    index = 1;
    if (copy_from_user(&up, ups + index, sizeof up))
        return NULL;
    while (up) {
        strlcat(buff, delim, bufcap);
        if (strncpy_from_user(tmp, up, sizeof tmp) <= 0)
            return NULL;
        strlcat(buff, tmp, bufcap);
        index += 1;
        if (copy_from_user(&up, ups + index, sizeof up))
            return NULL;
    }

    return index;
}


#ifdef CONFIG_COMPAT
static asmlinkage long our_sys_execve(const struct pt_regs *regs) 
#else
static asmlinkage long our_sys_execve(const char __user *__filename, const char __user *const __user *__argv, const char __user *const __user *__envp) 
#endif
{
    uid_t uid = __kuid_val(current_uid());

    int filename_len = strnlen_user(regs->di, PATH_MAX);
    char *filename = kmalloc(filename_len+1, GFP_KERNEL);
    if (unlikely(!filename))
    {
        pr_info("Failed to allocate memory for filename\n");
        goto calling_original_execve;
    }
    if(copy_from_user(filename, regs->di, filename_len))
    {
        pr_info("Failed to copy filename from user space\n");
        kfree(filename);
        goto calling_original_execve;
    }
    filename[filename_len] = '\0'; 
    pr_info("filename: %s\n", filename);
    kfree(filename);

    MKVAR(const char __user *const __user *, argv, regs->si);
    char tmp[1024];
    int argc = join_strings_from_user(argv, " ", tmp, sizeof tmp);
    pr_info("execve: %s\n", tmp);

    pr_info("argc: %d\n", argc);
    
calling_original_execve:
    return original_execve(regs);
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
 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0) 
static inline void __write_cr0(unsigned long cr0) 
{ 
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory"); 
} 
#else 
#define __write_cr0 write_cr0 
#endif 
 
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
 
static int __init syscall_steal_start(void) 
{ 
    pr_info("syscall_steal_start - B");
    if (!(sys_call_table_stolen = acquire_sys_call_table())) 
        return -1; 
 
    disable_write_protection(); 
 
    /* keep track of the original open function */ 
    original_call = (void *)sys_call_table_stolen[__NR_openat]; 
    original_execve = (void *)sys_call_table_stolen[__NR_execve];
    
    /* use our openat function instead */ 
    sys_call_table_stolen[__NR_openat] = (unsigned long *)our_sys_openat; 
    sys_call_table_stolen[__NR_execve] = (unsigned long *)our_sys_execve; 

    enable_write_protection(); 
 
    pr_info("Spying on UID:%d\n", uid); 
 
    return 0; 
} 
 
static void __exit syscall_steal_end(void) 
{ 
    if (!sys_call_table_stolen) 
        return; 
 
    /* Return the system call back to normal */ 
    if (sys_call_table_stolen[__NR_openat] != (unsigned long *)our_sys_openat) { 
        pr_alert("Somebody else also played with the "); 
        pr_alert("open system call\n"); 
        pr_alert("The system may be left in "); 
        pr_alert("an unstable state.\n"); 
    } 
 
    disable_write_protection(); 
    sys_call_table_stolen[__NR_openat] = (unsigned long *)original_call; 
    sys_call_table_stolen[__NR_execve] = (unsigned long *)original_execve; 
    enable_write_protection(); 
 
    msleep(2000); 
} 
 
module_init(syscall_steal_start); 
module_exit(syscall_steal_end); 
 
MODULE_LICENSE("GPL");