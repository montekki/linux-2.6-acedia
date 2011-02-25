#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>


#include "acedia_user_types.h"
#include "acedia.h"

struct event* parse_event( void* buffer )
{
	u32 size = *((u32*)buffer);
	struct event* res = malloc( size );

	res->_subevent = res->procname + strlen( res->procname ) + 1;
	return res;
}

void print_fsevent( struct fsevent *evt )
{
	printf( "fs is_folder %lu name %s", evt->is_folder, evt->name );
}

void print_netevent( struct netevent *evt )
{
	printf( "net fd %lu ip %08lx port %lu", evt->fd, evt->ip, evt->port );
}

void print_net6event( struct net6event *evt )
{
	printf( "net6 fd %lu ip %08x%08x%08x%08x ip4 %08lx port %lu", evt->fd, 
			*((unsigned int*)evt->ip), *((unsigned int*)evt->ip + 4), 
			*((unsigned int*)evt->ip + 8), *((unsigned int*)evt->ip + 12),
			evt->ip4, evt->port );
}

void print_fileevent( struct fileevent *evt )
{
	printf( "file fd %lu mode %lu name %s", evt->fd, evt->mode, evt->name );
}

void print_procevent( struct procevent *evt )
{
	printf( "proc pid %lu uid %lu euid %lu sig %lu name %s", 
			evt->pid, evt->uid, evt->euid, evt->sig, evt->name );
}

void print_brkevent( struct brkevent *evt )
{
	printf( "brk id %lu", evt->id );
}

void print_event( struct event* evt )
{
	printf( "type 0x%lx pid %lu uid %lu euid %lu procname %s ",
			evt->type, evt->pid, evt->uid, evt->euid, evt->procname );

	switch ( evt->type ) {
		case IDS_EVENT_LOCAL_LINUX_FS:
			print_fsevent( evt->fs );
			break;
		case IDS_EVENT_LOCAL_LINUX_PROCESS_KILL:
			print_procevent( evt->proc );
			break;
		case IDS_EVENT_LOCAL_LINUX_NET_BIND:
			print_netevent( evt->net );
			break;
		case IDS_EVENT_LOCAL_LINUX_NET_BIND6:
			print_net6event( evt->net6 );
			break;
		case IDS_EVENT_LOCAL_LINUX_FILE:
			print_fileevent( evt->file );
			break;
		case IDS_EVENT_LOCAL_LINUX_BRK:
			print_brkevent( evt->brk );
			break;
	}

	printf( "\n" );
}

int open_device( int make )
{
	int fd, res;

	fd = open( "/dev/" ACEDIA_DEV_NAME, 0 );
	if( fd < 0 && errno == ENOENT && make )
	{
		res = mknod( "/dev/" ACEDIA_DEV_NAME, S_IFCHR | 0600, makedev( SOOCH_MAJOR_NUMBER, 0 ) );
		if( res )
			fprintf( stderr, "Can't create Sooch device: %s\n", strerror( errno ) );
		else
			fd = open( "/dev/" ACEDIA_DEV_NAME, 0 );
	}
	if( fd < 0 )
		fprintf( stderr, "Can't open Sooch device: %s\n", strerror( errno ) );

	return fd;
}

char buffer[ 1024 ];

struct event* get_event( int fd )
{
	u32 size = 0;
	int res;
	struct event* evt = (struct event*) buffer;

	res = read( fd, &size, sizeof( u32 ) );
	printf( "read %d bytes size==%lu\n", res, size );
	if( res == 0 )
		return NULL;
	else if( res < (int)sizeof( u32 ) )
	{
		fprintf( stderr, "Reading device failed: %s\n", strerror( errno ) );
		return NULL;
	}

	evt = malloc( size );
	evt->size = size;

	size -= sizeof( u32 );
	res = read( fd, ((char*)evt) + sizeof( u32 ), size );

	if( res == 0 )
	{
		free( evt );
		return NULL;
	}
	else if( res < (int)sizeof( u32 ) )
	{
		free( evt );
		fprintf( stderr, "Reading device failed: %s\n", strerror( errno ) );
		return NULL;
	}

	evt->_subevent = evt->procname + strlen( evt->procname ) + 1;
	return evt;
}

int allow_event( int fd, struct event* pevt, int deny )
{
	return ioctl( fd, deny? (ACEDIA_DENY) : (SOOCH_ALLOW), pevt->_pevt );
}

int target_pid( int fd, pid_t pid )
{
	return ioctl( fd, ACEDIA_SETPID, pid );
}

int set_brk( int fd, unsigned long vaddr )
{
	return ioctl( fd, ACEDIA_BRK, vaddr );
}

int rm_brk( int fd, unsigned long vaddr )
{
	return ioctl( fd, ACEDIA_RMBRK, vaddr );
}

