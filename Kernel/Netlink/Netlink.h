#pragma once

#include <linux/skbuff.h>
#include <net/sock.h>

extern struct sock *nl_sk;

int netlink_register(void);

void netlink_unregister(void);

int thread_safe_nlmsg_unicast(struct sock *sk, struct sk_buff *skb, u32 portid);
