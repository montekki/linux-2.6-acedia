#ifndef ACEDIA_ENGINE_H
#define ACEDIA_ENGINE_H

#include <linux/mutex.h>

#include "acedia_event.h"

extern int disabled;

void acedia_allow(void* pevt, int deny);

void acedia_setpid(pid_t pid);
int acedia_getpid(void);

int acedia_attempt(struct event* evt);
int acedia_attempt_lock(struct event* evt);

#endif

