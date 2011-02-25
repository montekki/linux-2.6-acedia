#include <linux/security.h>
#include <linux/slab.h>

#include "acedia_event.h"

struct fsevent* create_fsevent(int is_folder, const char* name)
{
	u32 size = sizeof(struct fsevent) + strlen(name);
	struct fsevent* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->is_folder = (u32)is_folder;
	strcpy(res->name, name);

	return res;
}

struct netevent* create_netevent(int fd, u32 ip, u16 port)
{
	u32 size = sizeof(struct netevent);
	struct netevent* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->fd = (u32)fd;
	res->ip = ip;
	res->port = port;

	return res;
}

struct net6event* create_net6event(int fd, const char* ip, u32 ip4, u16 port)
{
	u32 size = sizeof(struct net6event);
	struct net6event* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->fd = (u32)fd;
	memcpy(res->ip, ip, 16);
	res->ip4 = ip4;
	res->port = port;

	return res;
}

struct fileevent* create_fileevent(int fd, int mode, const char* name)
{
	u32 size = sizeof(struct fileevent) + strlen(name);
	struct fileevent* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->fd = fd;
	res->mode = mode;
	strcpy(res->name, name);

	return res;
}

struct procevent* create_procevent(pid_t pid, uid_t uid, uid_t euid, int sig,
		const char* name)
{
	u32 size = sizeof(struct procevent) + strlen(name);
	struct procevent* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->pid = (u32)pid;
	res->uid = (u32)uid;
	res->euid = (u32)euid;
	res->sig = (u32)sig;
	strcpy(res->name, name);

	return res;
}

struct brkevent* create_brkevent(u32 id)
{
	u32 size = sizeof(struct brkevent);
	struct brkevent* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->id = id;

	return res;
}

struct event* create_event(u32 type, pid_t pid, uid_t uid, uid_t euid,
		const char* procname, void* subevent, u32 subsize)
{
	u32 size = sizeof(struct event) + strlen(procname) + subsize;
	struct event* res = kzalloc(size, GFP_KERNEL);

	res->size = size;
	res->type = type;
	res->pid = (u32)pid;
	res->uid = (u32)uid;
	res->euid = (u32)euid;

	strcpy(res->procname, procname);
	res->_subevent = res->procname + strlen(procname) + 1;

	memcpy(res->_subevent, subevent, subsize);
	return res;
}

#ifndef ACEDIA_EVENT_TEST
struct event* create_event_pid(u32 type, pid_t pid, void* subevent, u32 subsize)
{
	struct task_struct *vtask = find_task_by_vpid(pid);

	if (vtask == NULL)
		return create_event(type, pid, 0, 0, "unknown", subevent, subsize);
	else
		return create_event(type, pid, vtask->cred->uid, vtask->cred->euid, 
				vtask->comm, subevent, subsize);
}
#endif /* ACEDIA_EVENT_TEST */
