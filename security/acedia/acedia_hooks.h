#ifndef ACEDIA_HOOKS
#define ACEDIA_HOOKS

#define ACEDIA_SELINUX_HOOKS

struct inode;
struct dentry;
struct cred;
struct task_struct;
struct siginfo;
struct socket;
struct sockaddr;

int acedia_inode_create(struct inode *dir,struct dentry *dentry, int mode );
int acedia_inode_mkdir(struct inode *dir,struct dentry *dentry, int mode );
int acedia_inode_rmdir(struct inode *dir, struct dentry *dentry);
int acedia_inode_unlink(struct inode *dir, struct dentry *dentry);
int acedia_task_create(unsigned long clone_flags);
int acedia_cred_free(struct cred *c);
int acedia_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid);
int acedia_socket_bind(struct socket* sock, struct sockaddr *address, int addrlen);
int acedia_socket_connect(struct socket* sock, struct sockaddr *address, int addrlen);
int acedia_socket_listen(struct socket* sock, int backlog);
int acedia_socket_accept(struct socket* sock, struct socket *newsock);

void acedia_external_init(void);

#endif
