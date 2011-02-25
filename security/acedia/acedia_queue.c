#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sched.h>

#include "acedia_queue.h"
#include "acedia.h"

static struct mutex qmutex;

static struct acedia_queued_event* read;
static struct acedia_queued_event* write;
static struct acedia_queued_event* first;

wait_queue_head_t read_queue_evt;

void acedia_queue_init(void)
{
	mutex_init(&qmutex);
	read = write = first = NULL;
	init_waitqueue_head(&read_queue_evt);
}

struct acedia_queued_event* acedia_queue_event(struct event* ev)
{
	struct acedia_queued_event* new;
       	new = kzalloc(sizeof(struct acedia_queued_event), GFP_KERNEL);

	if (new == NULL)
		return NULL;

	new->evt = ev;
	mutex_init(&new->m);
	new->deny = 0;

	printk(KERN_INFO "acedia_queue_event read==%p write==%p new==%p\n", read, write, new);
	mutex_lock(&qmutex);

	if (write == NULL)
	{
		write = new;
		new->next = NULL;
		new->prev = NULL;
	}
	else
	{
		write->next = new;
		new->prev = write;
	}
	if (first == NULL)
		first = new;
	if (read == NULL)
		read = new;

	ev->_pevt = new;

	mutex_unlock(&qmutex);

	printk(KERN_INFO "acedia_queue_event read==%p write==%p pevt==%p\n", read, write, ev->_pevt);

	wake_up_interruptible(&read_queue_evt);

	return new;
}

struct event* acedia_read_event()
{
	struct event* res;

	//    printk(KERN_INFO "acedia_read_event read==%p\n", read);

	if (read == NULL)
		return NULL;

	printk(KERN_INFO "acedia_read_event evt==%p next==%p\n", read->evt, read->next);

	mutex_lock(&qmutex);

	res = read->evt;
	read = read->next;

	mutex_unlock(&qmutex);

	printk(KERN_INFO "acedia_read_event (after) read==%p\n", read);

	return res;
}

void acedia_delete_event(struct acedia_queued_event* old)
{
	mutex_lock(&qmutex);

	if (first == old)
		first = old->next;

	if (read == old)
		read = old->next;

	if (write == old)
		write = old->prev;

	if (old->prev != NULL)
		old->prev->next = old->next;

	if (old->next != NULL)
		old->next->prev = old->prev;

	mutex_unlock(&qmutex);

	kfree(old);
}
