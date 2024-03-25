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

#ifdef __KERNEL__ // TODO: Change this macro to a more standard macro for this check. __KERNEL__ 

struct alert* create_alert_execve(struct rule *rule, execve_event * execve);

void send_alert(struct alert *alert);

int netlink_register(void);

void netlink_unregister(void);

#endif