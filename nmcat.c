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

static inline void
callback(u_char *arg, const struct nm_pkthdr *h, const u_char *data)
{
    uint32_t size = h->len;
#ifdef DEBUG_NETMAP_USER
    D("rx pkt size: %d", size);
    pkt_dump(data, size);
#endif
    uint32_t nsize = htonl(size);
    write(STDOUT_FILENO, &nsize, 4);
    write(STDOUT_FILENO, data, size);
}

static struct nm_desc*
port_open(const char *port)
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
    struct nm_desc *d = port_open(port);
    if (d == NULL){
        return -1;
    }
    struct pollfd pfd;
    pfd.fd = d->fd;
    pfd.events = POLLIN;
    for(;;){
        poll(&pfd, 1, -1);
        nm_dispatch(d, -1, callback, NULL);
    }
}

static int
inject(const char *port)
{
    struct nm_desc *d = port_open(port);
    if (d == NULL) {
        return -1;
    }
    struct pollfd pfd;
    pfd.fd = d->fd;
    pfd.events = POLLOUT;
    for(;;){
        uint32_t size = 0;
        ssize_t n = read(STDIN_FILENO, &size, 4);
        if ( n == -1 ) {
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
        n = read(STDIN_FILENO, data, size);
        if ( n == -1 ) {
#ifdef DEBUG_NETMAP_USER
            if (errno) {
                D("%s\n", strerror(errno));
            }
#endif  /* DEBUG_NETMAP_USER */
            return -1;
        }
#ifdef DEBUG_NETMAP_USER
        pkt_dump(data, size);
#endif
        poll(&pfd, 1, -1);
        nm_inject(d, data, size);
    }
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
