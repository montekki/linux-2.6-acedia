#ifndef ACEDIA_UPROBES_H
#define ACEDIA_UPROBES_H

#include <linux/types.h>

#ifdef ACEDIA_SUPPORT_UPROBES

#define ACEDIA_MAX_UPROBES 1024

void *acedia_set_brk( pid_t pid, unsigned long vaddr );
void acedia_rm_brk( pid_t pid, unsigned long vaddr );
void __init acedia_uprobes_init( void );

#endif /* ACEDIA_SUPPORT_UPROBES */

#endif /* ACEDIA_UPROBES_H */
