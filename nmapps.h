#ifndef _NETMAP_APPS_H_
#define _NETMAP_APPS_H_
#include <stdio.h>              /* sprintf */
#include <string.h>             /* memset */
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>    /* D */

#ifdef DEBUG_NETMAP_USER
static void
pkt_dump(const u_char *p, uint32_t len)
{
    char data[56];
    int i, j;
    for (i = 0; i < len; ) {
        memset(data, sizeof(data), ' ');
        sprintf(data, "%3d: ", i);
        for (j=0; j < 16 && i < len; i++, j++)
            sprintf(data+5+j*3, "%02x ", (uint8_t)(p[i]));
        D("%s", data);
    }
}
#endif  /* DEBUG_NETMAP_USER */
#endif  /* _NETMAP_APPS_H_ */
