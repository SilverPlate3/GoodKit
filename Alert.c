#include "Alert.h"
#include "Netlink/Netlink.h"
#include "Netlink/NetlinkSettings.h"
#include "ThreadManagment/ThreadManagment.h"

#include <linux/kthread.h> 

static void send_alert(struct alert *alert)
{
    int msg_size = sizeof(struct alert);

    struct sk_buff *skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) 
    {
        pr_info("Failed to allocate new skb. Can't send alert\n");
        return;
    }

    struct nlmsghdr *nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    memcpy(nlmsg_data(nlh), alert, msg_size);

    if(thread_safe_nlmsg_unicast(nl_sk, skb_out, NETLINK_PORT_ID) < 0)
    {
        pr_info("nlmsg_unicast failed. Alert wasn't sent\n");
    }
}

static int async_send_alert(void *arg)
{
    atomic_inc(&(alert_threads_tracker->thread_count));
    struct alert *alert = (struct alert *)arg;
    send_alert(alert);
    kfree(alert);
    int before_dec = atomic_read(&alert_threads_tracker->thread_count);
    atomic_dec(&alert_threads_tracker->thread_count);

    if(before_dec <= 1)
    {
        wake_up(&alert_threads_tracker->wq);
    }
    return 0;
}

static struct alert* create_alert_common(struct rule *rule)
{
    struct alert *alert = kmalloc(sizeof(struct alert), GFP_KERNEL);
    if(unlikley(!alert))
    {
        pr_info("kmalloc failed to allocate memory for alert\n");
        return NULL;
    }

    alert->rule = *rule;
    return alert;
}

static struct alert* create_alert_execve(struct rule *rule, execve_event * execve)
{
    struct alert *alert = create_alert_common(rule);
    if(likely(alert))
    {
        alert->event.execve = *execve;
    }
    return alert;
}

static struct alert* create_alert_open(struct rule *rule, open_event * open)
{
    struct alert *alert = kmalloc(sizeof(struct alert), GFP_KERNEL);
    if(likely(alert))
    {
        alert->event.open = *open;
    }
    return alert;
}

void execve_alert(struct rule *rule, execve_event * execve)
{
    struct alert* alert = create_alert_execve(rule, execve);
    if(!alert)
    {
        return;
    }

    struct task_struct *thread = kthread_create(async_send_alert, alert, "execve_alert_%s", execve->full_command); 
    if(IS_ERR(thread))
    {
        pr_alert("Error creating thread: 'execve_alert_%s'", execve->full_command);
        kfree(alert);
        return;
    }
    wake_up_process(thread);
}

void open_alert(struct rule *rule, open_event * open)
{
    struct alert* alert = create_alert_open(rule, open);
    if(!alert)
    {
        return;
    }

    struct task_struct *thread = kthread_create(async_send_alert, alert, "open_alert_%s", open->full_command); 
    if(IS_ERR(thread))
    {
        pr_alert("Error creating thread: 'open_alert_%s'", open->full_command);
        kfree(alert);
        return;
    }
    wake_up_process(thread);
}