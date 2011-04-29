#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/security.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "acedia_dev.h"
#include "acedia_engine.h"
#include "acedia_event.h"
#include "acedia_queue.h"
#include "acedia_uprobes.h"
#include "acedia_hooks.h"

#define MAX_PATH 1024

static struct class *acedia_filter_class;
static struct device acedia_dev;
static struct cdev acedia_cdev;

static dev_t acedia_devt;

void acedia_get_filename(struct dentry *dentry, char* buf)
{
	char cnameReverse[MAX_PATH];
	struct dentry *dentrytmp = dentry;

	if (buf == NULL) return;
	if (dentry == NULL) return;

	memset(cnameReverse, 0, MAX_PATH);

	do {
		strcpy(buf, "/");
		strcpy(buf + 1, dentrytmp->d_name.name);

		if (strlen(buf) + strlen(cnameReverse) + 1 >= MAX_PATH)
			break;

		strcpy(buf + strlen(buf), cnameReverse);
		strcpy(cnameReverse, buf);
		if (dentrytmp == dentrytmp->d_parent) break;
		dentrytmp = dentrytmp->d_parent;
	} while (strlen(dentrytmp->d_name.name) != 0 &&
			strcmp(dentrytmp->d_name.name, "/") != 0);
}

int acedia_inode_create(struct inode *dir,
			struct dentry *dentry, int mode)
{
	char cname[MAX_PATH];
	struct fsevent *pe = 0;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	acedia_get_filename(dentry, cname);

	pe = create_fsevent(0, cname);
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_FS_CREATE,
					current->pid, pe, pe->size);

	printk(KERN_INFO "inode_create, %s\n", cname);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_inode_create);

int acedia_inode_mkdir(struct inode *dir,
			struct dentry *dentry, int mode)
{
	char cname[ MAX_PATH ];
	struct fsevent *pe = 0;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	acedia_get_filename(dentry, cname);

	pe = create_fsevent(1, cname);
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_FS_CREATE,
					current->pid, pe, pe->size);

	printk(KERN_INFO "inode_mkdir, %s\n", cname);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_inode_mkdir);

int acedia_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	char cname[MAX_PATH];
	struct fsevent *pe = 0;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	acedia_get_filename(dentry, cname);

	pe = create_fsevent(1, cname);
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_FS_DELETE,
					current->pid, pe, pe->size);

	printk(KERN_INFO "inode_rmdir %s\n", cname);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_inode_rmdir);

int acedia_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	char cname[ MAX_PATH ];
	struct fsevent *pe;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	acedia_get_filename(dentry, cname);

	pe = create_fsevent(0, cname);
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_FS_DELETE,
					current->pid, pe, pe->size);

	printk(KERN_INFO "inode_unlink, %s\n", cname);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_inode_unlink);

int acedia_task_create(unsigned long clone_flags)
{
	struct procevent *pe = 0;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	pe = create_procevent(current->pid, 0, 0, 0, "");
	e = NULL;
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_PROCESS_START,
					current->pid, pe, pe->size);

	printk(KERN_INFO "task_fork, %d\n", current->pid);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_task_create);

int acedia_cred_free(struct cred *c)
{
	struct procevent *pe = 0;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	pe = create_procevent(current->pid, 0, 0, 0, "");
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_PROCESS_STOP,
					current->pid, pe, pe->size);

	printk(KERN_INFO "task_stop, %d\n", current->pid);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_cred_free);

int acedia_task_kill(struct task_struct *p, struct siginfo *info,
		int sig, u32 secid)
{
	struct procevent *pe = 0;
	struct event* e = 0;

	if (disabled)
		return 0;

	if (info->si_pid < 1000)
		return 0;

	pe = create_procevent(task_pid_nr(p), p->cred->uid,
			p->cred->euid, info->si_signo, p->comm);

	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_PROCESS_KILL,
			info->si_pid, pe, pe->size);

	printk(KERN_INFO "task_kill, %d -> %d\n", info->si_pid, task_pid_nr(p));

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_task_kill);

int acedia_socket_bind(struct socket* sock,
		struct sockaddr *address, int addrlen)
{
	void* spe = NULL;
	struct event* e = NULL;
	struct sockaddr_in* ai;
	struct netevent* pe = 0;
	struct sockaddr_in6* ai6 = 0;
	struct net6event *pe6 = 0;
	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	if (address == NULL)
		return 0;

	if (address->sa_family == AF_INET) {
		ai = (struct sockaddr_in*) address;
		pe = NULL;
		spe = pe = create_netevent(0, ai->sin_addr.s_addr,
				ai->sin_port);

		e = create_event_pid(IDS_EVENT_LOCAL_LINUX_NET_BIND,
				current->pid, pe, pe->size);
	}
	else if (address->sa_family == AF_INET6)
	{
		ai6 = (struct sockaddr_in6*) address;
		spe = pe6 = create_net6event(0, ai6->sin6_addr.s6_addr,
				0 , ai6->sin6_port);

		e = create_event_pid(IDS_EVENT_LOCAL_LINUX_NET_BIND6,
				current->pid, pe6, pe6->size);
	}
	else
		return 0;

	printk(KERN_INFO "socket_bind, %d\n", current->pid);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_socket_bind);

int acedia_socket_connect(struct socket* sock,
		struct sockaddr *address, int addrlen)
{
	void* spe = NULL;
	struct event* e = NULL;
	struct sockaddr_in* ai = 0;
	struct netevent* pe = 0;
	struct sockaddr_in6* ai6 = 0;
	struct net6event* pe6 = NULL;

	if (disabled)
		return 0;
	if (current->pid < 1000)
		return 0;

	if (address == NULL)
		return 0;

	if (address->sa_family == AF_INET) {
		ai = (struct sockaddr_in*) address;
		pe = NULL;
		spe = pe = create_netevent(0, ai->sin_addr.s_addr,
				ai->sin_port);

		e = create_event_pid(IDS_EVENT_LOCAL_LINUX_NET_CONNECT,
				current->pid, pe, pe->size);
	}
	else if (address->sa_family == AF_INET6)
	{
		ai6 = (struct sockaddr_in6*) address;

		spe = pe6 = create_net6event(0, ai6->sin6_addr.s6_addr, 0,
				ai6->sin6_port);

		e = create_event_pid(IDS_EVENT_LOCAL_LINUX_NET_CONNECT6,
				current->pid, pe6, pe6->size);
	}
	else
		return 0;

	printk(KERN_INFO "socket_connect, %d\n", current->pid);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_socket_connect);

int acedia_socket_listen(struct socket* sock, int backlog)
{
	void* spe = NULL;
	struct event* e = NULL;
	struct netevent* pe = NULL;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	if (sock == NULL)
		return 0;

	spe = pe = create_netevent(0, 0, 0);
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_NET_LISTEN,
				current->pid, pe, pe->size);

	printk(KERN_INFO "socket_listen, %d\n", current->pid);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_socket_listen);

int acedia_socket_accept(struct socket* sock, struct socket *newsock)
{
	void* spe = NULL;
	struct event* e = NULL;
	struct netevent* pe = NULL;

	if (disabled)
		return 0;

	if (current->pid < 1000)
		return 0;

	if (sock == NULL)
	       	return 0;

	spe = pe = create_netevent(0, 0, 0);
	e = create_event_pid(IDS_EVENT_LOCAL_LINUX_NET_ACCEPT,
				current->pid, pe, pe->size);

	printk(KERN_INFO "socket_accept, %d\n", current->pid);

	acedia_attempt(e);

	return 0;
}
EXPORT_SYMBOL_GPL(acedia_socket_accept);

struct security_operations acedia_ops = {
	.name =             "acedia",

	//    .cred_free =            acedia_cred_free,

	.inode_create =         acedia_inode_create,
	.inode_mkdir =          acedia_inode_mkdir,
	.inode_rmdir =          acedia_inode_rmdir,
	.inode_unlink =         acedia_inode_unlink,

	.socket_bind =          acedia_socket_bind,
	.socket_listen =        acedia_socket_listen,
	.socket_connect =       acedia_socket_connect,
	.socket_accept =        acedia_socket_accept,

	.task_create =          acedia_task_create,
	.task_kill =            acedia_task_kill,
};

struct file_operations acedia_file_ops = {
	.read = acedia_dev_read,
	.open = acedia_dev_open,
	.release = acedia_dev_release,
	.unlocked_ioctl = acedia_dev_ioctl,
};

void acedia_external_init(void)
{
	/*
	if( register_chrdev(ACEDIA_MAJOR_NUMBER, ACEDIA_DEV_NAME, &acedia_file_ops) )
		panic("Acedia: unable to register char dev.\n");
	*/
	acedia_queue_init();
#ifdef ACEDIA_SUPPORT_UPROBES
	acedia_uprobes_init();
#endif
}
EXPORT_SYMBOL_GPL(acedia_external_init);

int __init acedia_init(void)
{
	int ret;

	printk(KERN_INFO "Acedia: Hi, this is Acedia!\n");
	printk(KERN_INFO "Acedia: perhaps you'd want to use 0x%lx and 0x%lx ioctl codes\n",
		       	ACEDIA_ALLOW, ACEDIA_SETPID);

	acedia_filter_class = class_create(THIS_MODULE, "acedia");

	if (!acedia_filter_class) {
		printk(KERN_ERR "Acedia: class_create() failed\n");
		return -EFAULT;
	}

	printk(KERN_INFO "Acedia: registering chrdev_region\n");

	ret = alloc_chrdev_region(&acedia_devt, 0,10,"acedia");

	if (ret < 0) {
		printk(KERN_ERR "Acedia: alloc_chrdev_region() failed\n");
		return -EFAULT;
	}

	dev_set_name(&acedia_dev, "acedia");

	cdev_init(&acedia_cdev,&acedia_file_ops);

	acedia_cdev.ops = &acedia_file_ops;
	acedia_dev.devt = MKDEV(MAJOR(acedia_devt),300);

	acedia_cdev.owner = THIS_MODULE;

	ret = cdev_add(&acedia_cdev, acedia_dev.devt, 1);

	if (ret < 0) {
		printk(KERN_ERR "acedia: failed to add char dev\n");
		return -EFAULT;
	}

	ret = device_register(&acedia_dev);

	if (ret) {
		printk(KERN_ERR "Acedia: failed to register device\n");
		return -EFAULT;
	}

	if (!security_module_enable(&acedia_ops))
		return 0;

	printk(KERN_INFO "Acedia:  Initializing.\n");

	if (register_security(&acedia_ops))
		panic("Acedia: Unable to register with kernel.\n");


	acedia_external_init();
	return 0;
}

module_init(acedia_init);
