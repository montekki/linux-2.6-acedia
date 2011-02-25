#include "acedia_engine.h"
#include "acedia_event.h"

#ifdef ACEDIA_SUPPORT_UPROBES
#include "acedia_uprobes.h"
#include "uprobes/uprobes.h"
#endif

#ifdef ACEDIA_SUPPORT_UPROBES

static struct uprobe* acedia_uprobes[ACEDIA_MAX_UPROBES];

int acedia_up_handler(struct uprobe* up, struct pt_regs* regs)
{
	struct brkevent *be;
	struct event *e;

	printk(KERN_INFO "acedia_up_handler with pid==%d vaddr==0x%x\n", up->pid, up->vaddr);

	be = create_brkevent(up->vaddr);

	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_BRK, up->pid, be, be->size);

	printk(KERN_INFO "brk %d %p\n", up->pid, up->vaddr);

	acedia_attempt_lock(e);
	kfree(be);
	kfree(e);

	return (0);
}

void *acedia_set_brk(pid_t pid, unsigned long vaddr)
{
	int i;
	struct uprobe *up;
	printk(KERN_INFO "acedia_set_brk with pid==%d vaddr==%p\n", pid, vaddr);

	for(i = 0; i < ACEDIA_MAX_UPROBES; i++)
		if(acedia_uprobes[i] == NULL) break;

	if (i >= ACEDIA_MAX_UPROBES)
	{
		printk(KERN_INFO "acedia_set_brk: max uprobes count reached\n");
		return NULL;
	}

	up = kzalloc(sizeof(struct uprobe), GFP_KERNEL);

	if (up == NULL)
		return NULL;

	acedia_uprobes[i] = up;

	up->pid = pid;
	up->vaddr = vaddr;
	up->handler = &acedia_up_handler;

	printk(KERN_INFO "acedia_set_brk: register_uprobe is %d\n",
						register_uprobe(up));
	return up;
}

int acedia_rm_brk(pid_t pid, unsigned long vaddr)
{
	int i;

	printk(KERN_INFO "acedia_rm_brk: pid==%d vaddr==%p\n", pid, vaddr);

	for(i = 0; i < ACEDIA_MAX_UPROBES; i++)
		if (acedia_uprobes[i] != NULL &&
			acedia_uprobes[i]->pid == pid &&
			acedia_uprobes[i]->vaddr == vaddr) {
				printk(KERN_INFO "acedia_rm_brk: found uprobe\n");
				unregister_uprobe(acedia_uprobes[i]);
				kfree(acedia_uprobes[i]);
				acedia_uprobes[i] = NULL;
		}
}

int __init acedia_uprobes_init(void)
{
	int i;

	for(i = 0; i < ACEDIA_MAX_UPROBES; i++)
		acedia_uprobes[i] = NULL;
}

#endif /* ACEDIA_SUPPORT_UPROBES */
