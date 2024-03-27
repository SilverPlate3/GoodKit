#pragma once

#include "Rules/Rules.h"

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
#endif