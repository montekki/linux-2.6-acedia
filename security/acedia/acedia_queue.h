#ifndef ACEDIA_QUEUE_H
#define ACEDIA_QUEUE_H

#include <linux/mutex.h>
#include <linux/wait.h>

extern wait_queue_head_t read_queue_evt;

struct acedia_queued_event
{
    struct acedia_queued_event* next;
    struct acedia_queued_event* prev;

    struct event* evt;
    struct mutex m;
    int deny;
    int lock;
};

void __init acedia_queue_init(void);
struct acedia_queued_event* acedia_queue_event(struct event* ev);
struct event* acedia_read_event(void);
void acedia_delete_event(struct acedia_queued_event* old);

#endif

