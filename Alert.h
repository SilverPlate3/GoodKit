#pragma once

#include "Rules.h"

#define NETLINK_GOOD_KIT 31
#define NETLINK_PORT_ID 1111

struct alert
{
    struct rule rule;
    union 
    {
        execve_event execve;
    } event;
};

#ifdef __KERNEL__

void execve_alert(struct rule *rule, execve_event * execve);

int netlink_register(void);

void netlink_unregister(void);

#endif