#pragma once

#include "Rules/Rules.h"

struct alert
{
    struct rule rule;
    union 
    {
        open_event open;
        execve_event execve;
    } event;
};

#ifdef __KERNEL__
void execve_alert(struct rule *rule, execve_event * execve);

void open_alert(struct rule *rule, open_event * open);
#endif