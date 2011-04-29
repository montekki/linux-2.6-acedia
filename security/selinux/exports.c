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
#include <linux/module.h>

#include "security.h"

bool selinux_is_enabled(void)
{
	return selinux_enabled;
}
EXPORT_SYMBOL_GPL(selinux_is_enabled);

int selinux_kern_getprocattr(struct task_struct *p,
		char *name, char **value)
{
	if (selinux_enabled) {
		return security_kern_getprocattr(p, name, value );
	} else {
		*value = NULL;
		return 0;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(selinux_kern_getprocattr);

int selinux_kern_setprocattr(struct task_struct* p,
			char *name, void *value, size_t size)
{
	if (selinux_enabled) {
		return security_kern_setprocattr(p, name, value, size );
	} else {
		value = NULL;
		return 0;
	}
}
EXPORT_SYMBOL_GPL(selinux_kern_setprocattr);

int selinux_string_to_sid(char *str, size_t size, u32 *sid)
{
	if (selinux_enabled) {
		return security_context_to_sid( str, size, sid );
	} else {
		*sid = 0;
		return 0;
	}
}
EXPORT_SYMBOL_GPL(selinux_string_to_sid);
