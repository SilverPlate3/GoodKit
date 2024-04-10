#pragma once
#include <linux/wait.h>  
#include <linux/atomic.h> 

struct alert_threads_tracker {
    wait_queue_head_t wq;
    atomic_t thread_count;
};

extern struct alert_threads_tracker *alert_threads_tracker;

void ensure_no_alert_threads_are_running(void);

int init_global_alert_threads_tracker(void);
