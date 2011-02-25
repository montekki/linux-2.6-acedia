#ifndef ACEDIA_H
#define ACEDIA_H

#define ACEDIA_MAJOR_NUMBER 124
#define ACEDIA_DEV_NAME     "acedia"

// #define ACEDIA_SUPPORT_UPROBES
#define ACEDIA_SETPID _IOR( ACEDIA_MAJOR_NUMBER, 1, pid_t )
#define ACEDIA_DENY   _IOR( ACEDIA_MAJOR_NUMBER, 4, void* )
#define ACEDIA_ALLOW  _IOR( ACEDIA_MAJOR_NUMBER, 5, void* )
#define ACEDIA_BRK    _IOR( ACEDIA_MAJOR_NUMBER, 8, unsigned long )
#define ACEDIA_RMBRK  _IOR( ACEDIA_MAJOR_NUMBER, 9, unsigned long )

#define IDS_EVENT_LOCAL_LINUX                           0x130       
#define IDS_EVENT_LOCAL_LINUX_FS                        0x131       
#define IDS_EVENT_LOCAL_LINUX_FS_CREATE                 0x132       
#define IDS_EVENT_LOCAL_LINUX_FS_DELETE                 0x133       
#define IDS_EVENT_LOCAL_LINUX_FS_LAST                   0x133       

#define IDS_EVENT_LOCAL_LINUX_PROCESS                   0x171       
#define IDS_EVENT_LOCAL_LINUX_PROCESS_START             0x172       
#define IDS_EVENT_LOCAL_LINUX_PROCESS_KILL              0x173       
#define IDS_EVENT_LOCAL_LINUX_PROCESS_STOP              0x174
#define IDS_EVENT_LOCAL_LINUX_PROCESS_FORK              0x175
#define IDS_EVENT_LOCAL_LINUX_PROCESS_LAST              0x175

#define IDS_EVENT_LOCAL_LINUX_NET                       0x151       
#define IDS_EVENT_LOCAL_LINUX_NET_BIND                  0x151       
#define IDS_EVENT_LOCAL_LINUX_NET_BIND6                 0x152       
#define IDS_EVENT_LOCAL_LINUX_NET_LISTEN                0x153       
#define IDS_EVENT_LOCAL_LINUX_NET_CONNECT               0x155       
#define IDS_EVENT_LOCAL_LINUX_NET_CONNECT6              0x157       
#define IDS_EVENT_LOCAL_LINUX_NET_ACCEPT                0x156       
#define IDS_EVENT_LOCAL_LINUX_NET_ACCEPT6               0x158       
#define IDS_EVENT_LOCAL_LINUX_NET_LAST                  0x158       

#define IDS_EVENT_LOCAL_LINUX_FILE                      0x13a
#define IDS_EVENT_LOCAL_LINUX_FILEOPEN                  0x13a       
#define IDS_EVENT_LOCAL_LINUX_FILECLOSE                 0x13b       
#define IDS_EVENT_LOCAL_LINUX_FILEREAD                  0x13c       
#define IDS_EVENT_LOCAL_LINUX_FILEWRITE                 0x13d       
#define IDS_EVENT_LOCAL_LINUX_FILEDUP                   0x13e       
#define IDS_EVENT_LOCAL_LINUX_FILE_LAST                 0x13e       

#define IDS_EVENT_LOCAL_LINUX_BRK                       0x200

/**
 * struct fsevent - file system event
 */
struct fsevent
{
    u32 size;
    u32 is_folder;
    char   name[1];  
};

/**
 * struct netevent - network event
 */
struct netevent
{
    u32 size;
    u32 fd;
    u32 ip;
    u32 port;
};

/**
 * struct net6event - network event
 */
struct net6event
{
    u32 size;
    u32 fd;
    char   ip[16];
    u32 ip4;
    u32 port;
};

/**
 * struct fileevent - file event
 */
struct fileevent
{
    u32 size;
    u32 fd;
    u32 mode;
    char   name[1];
};

/**
 * struct procevent - procfs event
 */
struct procevent
{
    u32 size;
    u32 pid;
    u32 uid;
    u32 euid;
    u32 sig;
    char   name[1];
};

/**
 * struct brkevent - breakpoint event
 */
struct brkevent
{
    u32 size;
    u32 id;
};

/**
 * struct event - base event struct
 */
struct event
{
    u32 size;
    u32 type;

    u32 pid;
    u32 uid;
    u32 euid;

    void *_pevt;

    union
    {
        struct fsevent* fs;
        struct netevent* net;
        struct net6event* net6;
        struct fileevent* file;
        struct procevent* proc;
        struct brkevent* brk;
        char *_subevent;
    };

    char procname[1];
};

#endif

