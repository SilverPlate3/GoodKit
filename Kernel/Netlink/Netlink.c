#include "Netlink.h"
#include "NetlinkSettings.h"

#include <linux/netlink.h>

static DEFINE_MUTEX(netlink_pipe_mutex);
struct sock *nl_sk = NULL;

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

int thread_safe_nlmsg_unicast(struct sock *sk, struct sk_buff *skb, u32 portid)
{
    mutex_lock(&netlink_pipe_mutex);
    int rv = nlmsg_unicast(sk, skb, portid);
    mutex_unlock(&netlink_pipe_mutex);
    return rv;
}