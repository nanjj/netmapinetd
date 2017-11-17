/*
 * This program opens a netmap port and starts receiving packets,
 * netmap cat
 * 
 */
#include <stdio.h>              /* printf */
#include <unistd.h>             /* getopt, read, write */
#include <stdlib.h>             /* exit */
#include <arpa/inet.h>          /* htonl */
#include <string.h>             /* strerror */
#include <poll.h>               /* pollfd, poll */
#include "nmapps.h"             /* pkt_dump */

#define NMCAT_BUF_SIZE 4096

static struct nm_desc*
open_port(const char *port)
{
    struct nm_desc *d = nm_open(port, NULL, 0, NULL);
    if (d == NULL) {
#ifdef DEBUG_NETMAP_USER
        if (errno) {
            D("%s\n", strerror(errno));
        }
        D("Failed to open %s.\n", port);
#endif  /* DEBUG_NETMAP_USER */
    }
    return d;
}

static int
dispatch(const char *port)
{
    struct nm_desc *nmd = open_port(port);
    if (nmd == NULL) {
        return -1;
    }

    struct pollfd pfd[1];
    int ret;
    pfd[0].fd = nmd->fd;
    pfd[0].events = POLLIN;

    u_char buf[NMCAT_BUF_SIZE];
    uint32_t idx = 4;
    
    for(;;) {
        /* We poll with a timeout to have a chance to break the main loop if
         * no packets are coming. */
        ret = poll(pfd, 1, 1000);
        if (ret < 0) {
            perror("poll()");
            return 1;
        } else if (ret == 0) {
#ifdef DEBUG_NETMAP_USER
            D("timeout, idx=%d", idx);
#endif  /* DEBUG_NETMAP_USER */
            /* Timeout */
            if (idx > 4) {
                uint32_t nidx = htonl(idx - 4);
                memcpy(buf, &nidx, 4);
                write(STDOUT_FILENO, buf, idx);
                idx = 4;
            }
            continue;
        }

        /* Scan all the receive rings. */
        unsigned int ri;
        for (ri = nmd->first_rx_ring; ri <= nmd->last_rx_ring; ri++) {
            struct netmap_ring *rxring;
            unsigned head, tail;
            rxring = NETMAP_RXRING(nmd->nifp, ri);
            if (nm_ring_empty(rxring)) {
                continue;
            }
            head = rxring->head;
            tail = rxring->tail;
            for (; head != tail; head = nm_ring_next(rxring, head)) {
                struct netmap_slot *slot = rxring->slot + head;
                u_char *data = (u_char *) NETMAP_BUF(rxring, slot->buf_idx);
                uint32_t size = slot->len;
#ifdef DEBUG_NETMAP_USER
                D("rx pkt size(%d), idx(%d)", size, idx);
                pkt_dump(data, size);                
#endif  /* DEBUG_NETMAP_USER */
                if ((idx + 4 + size) > NMCAT_BUF_SIZE ) {
                    uint32_t nidx = htonl(idx-4);
                    memcpy(buf, &nidx, 4);
                    write(STDOUT_FILENO, buf, idx);
                    idx = 4;
                }
                uint32_t nsize = htonl(size);
                memcpy(buf + idx, &nsize, 4);
                idx = idx + 4;
                memcpy(buf + idx, data, size);
                idx = idx + size;
            }
            rxring->cur = rxring->head = head;
        }
    }
    nm_close(nmd);
    return 0;
}

static inline ssize_t
readfully(void* p, size_t size)
{
    uint32_t n = 0, len = 0;
    for(;;) {
        n = read(STDIN_FILENO, p, size);
        if ( n <= 0) {
            return len;
        }else {
            len = len + n;
        }
        if ( len == size ) {
            return len;
        }
        p = p + n;
        size = size - n;
    }
}

static inline int
inject(const char *port)
{
    struct nm_desc *d = open_port(port);
    if (d == NULL) {
        return -1;
    }
    struct pollfd pfd;
    pfd.fd = d->fd;
    pfd.events = POLLOUT;
    for(;;){
        uint32_t size = 0;
        ssize_t n = readfully(&size, 4);
        if ( n != 4 ) {
#ifdef DEBUG_NETMAP_USER
            if (errno) {
                D("%s\n", strerror(errno));
            }
#endif  /* DEBUG_NETMAP_USER */
            return -1;
        }
        size = ntohl(size);
#ifdef DEBUG_NETMAP_USER
    D("tx pkt size: %d", size);
#endif
        u_char data[size];
        n = readfully(data, size);
        if ( n != size ) {
            if (errno) {
                D("%s\n", strerror(errno));
            }
            return -1;
        }
#ifdef DEBUG_NETMAP_USER
        pkt_dump(data, size);
#endif
        uint32_t idx;
        uint32_t *p;
        for(idx=0; idx != size;) {
            p = (uint32_t *) (data + idx);
            uint32_t len = ntohl(*p);
            idx = idx + 4;
            while (!nm_inject(d, data+idx, len)) {
                poll(&pfd, 1, -1);
            }
            idx = idx + len;
        }
    }
    nm_close(d);
}

static void
usage(char **argv)
{
    fprintf(stderr,
            "usage: %s [-h] <-i|-o PORT>\n"
            "\t -i PORT - read packets from PORT and write to stdout.\n"
            "\t -o PORT - read packets from stdin and write to PORT.\n",
            argv[0]);
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    const char *port = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "hi:o:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv);
            return 0;
        case 'i':
            if (port != NULL) {
                fprintf(stderr, "-i and -o can not be specified together.\n");
                usage(argv);
            }
            port = optarg;
            dispatch(port);
            break;
        case 'o':
            if (port != NULL) {
                fprintf(stderr, "-i and -o can not be specified together.\n");
                usage(argv);
            }
            port = optarg;
            inject(port);
            break;
        default:
            fprintf(stderr, "unrecognized option '-%c'\n", opt);
            usage(argv);
            return -1;
        }
    }
    return 0;
}
