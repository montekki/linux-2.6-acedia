#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "acedia_user_types.h"
#include "acedia_event.h"
#include "acedia_user.h"
#include "acedia.h"

int main()
{
    assert( sizeof( u32 ) == 4 );
    assert( sizeof( u16 ) == 2 );

    struct fsevent *fe = create_fsevent( 1, "/var/tmp/" );
    struct netevent* ne = create_netevent( 7, 0xc0112233, 1234 );
    struct net6event* n6e = create_net6event( 5, "1234567890123450", 0x36373637, 4321 );
    struct fileevent* Fe = create_fileevent( 15, 0666, "/boot/grub/menu.lst" );
    struct procevent* pe = create_procevent( 1221, 1001, 1002, 9, "bash -c" );
    struct brkevent* be = create_brkevent( 777 );

    print_event( create_event( IDS_EVENT_LOCAL_LINUX_FS,
                               9001, 1101, 1201, "kill -7", fe, fe->size ) );
    print_event( create_event( IDS_EVENT_LOCAL_LINUX_PROCESS,
                               9002, 1102, 1202, "kill -8", pe, pe->size ) );
    print_event( create_event( IDS_EVENT_LOCAL_LINUX_NET_BIND,
                               9003, 1103, 1203, "kill -9", ne, ne->size ) );
    print_event( create_event( IDS_EVENT_LOCAL_LINUX_NET_BIND6,
                               9004, 1104, 1204, "kill -1", n6e, n6e->size ) );
    print_event( create_event( IDS_EVENT_LOCAL_LINUX_FILE,
                               9005, 1105, 1205, "kill -2", Fe, Fe->size ) );
    print_event( create_event( IDS_EVENT_LOCAL_LINUX_BRK,
                               9006, 1106, 1206, "kill -3", be, be->size ) );

    return 0;
}

