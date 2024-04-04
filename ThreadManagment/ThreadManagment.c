#include "ThreadManagment.h"
#include <linux/sched.h>
#include <linux/slab.h>

struct alert_threads_tracker * alert_threads_tracker = NULL;

int init_global_alert_threads_tracker(void)
{
    alert_threads_tracker = kmalloc(sizeof(struct alert_threads_tracker), GFP_KERNEL);
    if(unlikely(!alert_threads_tracker))
    {
        pr_info("init_global_alert_threads_tracker - failed to allocate memory for alert_threads_tracker\n");
        return 0;
    }

    init_waitqueue_head(&(alert_threads_tracker->wq));
    atomic_set(&alert_threads_tracker->thread_count, 0);
    return 1;
}

void ensure_no_alert_threads_are_running(void)
{
    wait_event(alert_threads_tracker->wq, atomic_read(&alert_threads_tracker->thread_count) == 0);
}