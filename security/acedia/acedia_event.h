#ifndef ACEDIA_EVENT_H
#define ACEDIA_EVENT_H

#include "acedia.h"

struct fsevent* create_fsevent(int is_folder, const char* name);
struct netevent* create_netevent(int fd, u32 ip, u16 port);
struct net6event* create_net6event(int fd, const char* ip, u32 ip4, u16 port);
struct fileevent* create_fileevent(int fd, int mode, const char* name);
struct procevent* create_procevent(pid_t pid, uid_t uid, uid_t euid, int sig,
                                    const char* name);
struct brkevent* create_brkevent(u32 id);
struct event* create_event(u32 type, pid_t pid, uid_t uid, uid_t euid,
                            const char* procname, void* subevent, u32 subsize);
struct event* create_event_pid(u32 type, pid_t pid, void* subevent, u32 subsize);


#endif

