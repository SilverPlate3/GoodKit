#include "Alert.h"

#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/netlink.h>

DEFINE_MUTEX(netlink_pipe_mutex);
struct sock *nl_sk = NULL;

static struct alert* create_alert_execve(struct rule *rule, execve_event * execve)
{
    struct alert *alert = kmalloc(sizeof(struct alert), GFP_KERNEL);
    if(!alert)
    {
        pr_info("kmalloc failed to allocate memory for alert\n");
        return NULL;
    }

    alert->rule = *rule;
    alert->event.execve = *execve;

    return alert;
}

static int thread_safe_nlmsg_unicast(struct sock *sk, struct sk_buff *skb, u32 portid)
{
    mutex_lock(&netlink_pipe_mutex);
    int rv = nlmsg_unicast(sk, skb, portid);
    mutex_unlock(&netlink_pipe_mutex);
    return rv;
}

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

void execve_alert(struct rule *rule, execve_event * execve)
{
    struct alert* alert = create_alert_execve(rule, execve);
    if(alert)
    {
        send_alert(alert);
        kfree(alert);
    }
}

int netlink_register(void)
{
    struct netlink_kernel_cfg cfg = {.input = NULL,};
    nl_sk = netlink_kernel_create(&init_net, NETLINK_GOOD_KIT, &cfg);
    if(!nl_sk)
    {
        pr_info("netlink_kernel_create failed to create netlink socket\n");
        return 0;
    }

    return 1;
}

void netlink_unregister(void)
{
    if(nl_sk)
    {
        netlink_kernel_release(nl_sk);
    }
}