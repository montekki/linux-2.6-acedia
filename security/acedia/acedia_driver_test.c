#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "acedia_user_types.h"
#include "acedia_user.h"
#include "acedia.h"

int main()
{
	int pid, allow, res;
	printf( "I am tester.\n" );
	scanf( "%d", &pid );
	printf( "Setting pid to %d: ", pid );
	int fd = open_device( 1 );
	printf( "fd==%d ", fd );
	res = ioctl( fd, ACEDIA_SETPID, pid );
	printf( "%s\n", res? strerror( errno ): "ok" );

    struct event* evt = NULL;
    if( (evt = get_event( fd )) != NULL )
    {
        print_event( evt );
        scanf( "%d", &allow );
        printf( "Sending allow with deny=%d: ", allow );
        res = allow_event( fd, evt, allow );
        printf( "%s\n", res? strerror( errno ): "ok" );
    }

	close( fd );
	return 0;
}

