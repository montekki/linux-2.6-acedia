#include <linux/kernel.h>   
#include <linux/module.h>  
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/wait.h>

#include "acedia_dev.h"
#include "acedia_engine.h"
#include "acedia_queue.h"
#include "acedia_uprobes.h"

static struct event* cevent = NULL;
static int remaining = 0;

ssize_t acedia_dev_read(struct file *file, char *buffer,
		size_t length, loff_t *offset)
{
	int to_write = 0;

	printk(KERN_INFO "acedia_dev_read with length==%zu\n", length);

	while(cevent == NULL) {
		cevent = acedia_read_event();
		if (cevent == NULL) {

			wait_event_interruptible(read_queue_evt, 
				(cevent = acedia_read_event()) != NULL);

			if (signal_pending(current))
				return -ERESTARTSYS;
		}

		if (cevent != NULL)
			remaining = cevent->size;
	}


	printk(KERN_INFO "acedia_dev_read pevt==%p\n", cevent->_pevt);

	to_write = length;

	if (remaining < length)
		to_write = remaining;

	if (copy_to_user(buffer, ((char*)cevent) +
		(cevent->size - remaining), to_write))
			printk(KERN_INFO "acedia: unable to "
					"copy some bytes to user\n");

	*offset += to_write;
	remaining -= to_write;

	if (remaining <= 0)
		cevent = NULL;

	printk(KERN_INFO "acedia_dev_read to_write==%d remaining==%d\n",
				to_write, remaining);

	return to_write;
}

void *cpevt = NULL;

int acedia_dev_ioctl(struct inode *inode, struct file *file,
		unsigned int ioctl_num, unsigned long ioctl_param)
{
	printk(KERN_INFO "acedia_dev_ioctl with ioctl_num==%u"
			" ioctl_param==0x%lx\n", ioctl_num, ioctl_param);

	switch (ioctl_num) {
		case ACEDIA_SETPID:
			acedia_setpid((pid_t) ioctl_param);
			break;
		case ACEDIA_ALLOW:
			acedia_allow((void*) ioctl_param, 0);
			break;
		case ACEDIA_DENY:
			acedia_allow((void*) ioctl_param, 1);
			break;
#ifdef ACEDIA_SUPPORT_UPROBES
		case ACEDIA_BRK:
			acedia_set_brk(acedia_getpid(), ioctl_param);
			break;
		case ACEDIA_RMBRK:
			acedia_rm_brk(acedia_getpid(), ioctl_param);
			break;
#endif /* ACEDIA_SUPPORT_UPROBES */
	}

	return 0;
}

int acedia_dev_release(struct inode *inode, struct file *file)
{
	while((cevent = acedia_read_event()) != NULL) {
		acedia_allow(cevent->_pevt, 1);
	}

	disabled = 1;
	return 0;
}

int acedia_dev_open(struct inode *inode, struct file *file)
{
	// TODO: mutex
	if (!disabled)
		return -EBUSY;

	disabled = 0;
	return 0;
}
