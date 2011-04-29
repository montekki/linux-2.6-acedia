/*
 * SELinux services exported to the rest of the kernel.
 *
 * Author: James Morris <jmorris@redhat.com>
 *
 * Copyright (C) 2005 Red Hat, Inc., James Morris <jmorris@redhat.com>
 * Copyright (C) 2006 Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 * Copyright (C) 2006 IBM Corporation, Timothy R. Chavez <tinytim@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */
#ifndef _LINUX_SELINUX_H
#define _LINUX_SELINUX_H

struct selinux_audit_rule;
struct audit_context;
struct kern_ipc_perm;

#ifdef CONFIG_SECURITY_SELINUX

int selinux_string_to_sid(char *str, size_t size, u32 *sid);
int selinux_secmark_relabel_packet_permission(u32 sid);
int selinux_kern_getprocattr(struct task_struct *p,
		char *name, char **value );

int selinux_kern_setprocattr(struct task_struct *p,
		char *name, void *value, size_t size);

int security_kern_setprocattr(struct task_struct *p,
		char *name, void *value, size_t size);

int security_kern_getprocattr(struct task_struct *p,
		char *name, char **value);

/**
 * selinux_is_enabled - is SELinux enabled?
 */
bool selinux_is_enabled(void);
#else

static inline bool selinux_is_enabled(void)
{
	return false;
}
#endif	/* CONFIG_SECURITY_SELINUX */

#endif /* _LINUX_SELINUX_H */
