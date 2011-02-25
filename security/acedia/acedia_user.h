#ifndef ACEDIA_USER_H
#define ACEDIA_USER_H

#include "acedia.h"

struct event* parse_event( void* buffer );
void print_event( struct event* evt );

int open_device( int make );
struct event* get_event( int fd );

int allow_event( int fd, struct event* pevt, int deny );
int target_pid( int fd, pid_t pid );

int set_brk( int fd, unsigned long vaddr );
int rm_brk( int fd, unsigned long vaddr );

#endif

