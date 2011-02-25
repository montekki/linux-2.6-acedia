#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#include "acedia.h"
#include "acedia_queue.h"

static pid_t cpid = 0;

int disabled = 1;

void acedia_allow(void* pevt, int deny)
{
	struct acedia_queued_event* cevent = (struct acedia_queued_event*)pevt;

	if (cevent != NULL) {
		printk(KERN_INFO "acedia_allow with deny==%d\n", deny);
		cevent->deny = deny;
		if (cevent->lock)
			mutex_unlock(&cevent->m);
		else
			acedia_delete_event( cevent );
	}
}

void acedia_setpid(pid_t pid)
{
	printk(KERN_INFO "acedia_setpid with pid==%d\n", pid);
	cpid = pid;
}

int acedia_getpid(void)
{
	return cpid;
}

int acedia_attempt(struct event* evt)
{
	struct acedia_queued_event *qe = NULL;

	if (!cpid || evt->pid != cpid)
		return 0;

	printk(KERN_INFO "acedia_attempt starting\n");

	qe = acedia_queue_event(evt);

	if (qe == NULL) {
		printk(KERN_INFO "acedia_attempt failed to allocate memory\n");
		return 1;
	}
	return 0;
}

int acedia_attempt_lock(struct event* evt )
{
	struct acedia_queued_event *qe = 0;
	int res;

	if ( !cpid || evt->pid != cpid )
		return 0;

	printk(KERN_INFO "acedia_attempt_lock starting\n");

	qe = acedia_queue_event(evt);

	if (qe == 0){
		printk(KERN_INFO "acedia_attempt_lock failed "
				"to allocate memory\n" );
		return 1;
	}

	qe->lock = 1;

	printk(KERN_INFO "acedia_attempt_lock: locking once\n");
	mutex_lock(&qe->m);

	printk(KERN_INFO "acedia_attempt_lock: locking twice\n");
	mutex_lock(&qe->m);

	res = qe->deny;

	acedia_delete_event(qe);

	return res;
}
