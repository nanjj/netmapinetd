/*
 * This program opens a netmap port and starts receiving packets,
 * reply arp request and icmp echo request.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <net/if.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#ifdef DEBUG_NETMAP_USER
static void
pkt_dump(const u_char *p, uint32_t l)
{
    char buf[56];
    int i, j;
    for (i = 0; i < l; ) {
        memset(buf, sizeof(buf), ' ');
        sprintf(buf, "%3d: ", i);
        for (j=0; j < 16 && i < l; i++, j++)
            sprintf(buf+5+j*3, "%02x ", (uint8_t)(p[i]));
        D("%s", buf);
    }
}
#endif

struct context
{
    u_int32_t if_addr;
    const u_int8_t * if_mac;
    struct pollfd *fdr;
    struct pollfd *fdw;
};

/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

static uint16_t
wrapsum(uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

static uint32_t
ipv4_aton(const char *name)
{
    uint32_t addr;
    uint8_t * a;
    a = (uint8_t *) &addr;
    sscanf(name, "%hhu.%hhu.%hhu.%hhu", a, a+1, a+2, a+3);
    return addr;
}

static inline int
icmp_echo_reply(struct context *ctx, struct nm_desc *d, u_char *buf, uint32_t l)
{
    struct ether_header *ethh;
    struct iphdr *iph;
    struct icmphdr *icmph;
    u_int32_t addr;
    ethh = (struct ether_header *)buf;
    iph = (struct iphdr *)(ethh + 1);
    if (iph->protocol != IPPROTO_ICMP || iph -> daddr != ctx->if_addr) {
        return 0;
    }
    icmph = (struct icmphdr *)(iph + 1);
    /* Match the icmp echo request. */
    if (icmph->type != ICMP_ECHO) {
        return 0;
    }
    addr = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = addr;
    iph->check = 0;
    iph->check = wrapsum(checksum(iph, 20, 0));
    bcopy(ethh->ether_shost, ethh->ether_dhost, 6);
    bcopy(ctx->if_mac,ethh->ether_shost, 6);
    icmph->type = ntohs(ICMP_ECHOREPLY);
    memset(&(icmph->checksum), 0, 2);
    icmph->checksum = wrapsum(checksum(icmph, 8, 0));
    poll(ctx->fdw, 1, -1);
    nm_inject(d, buf, l);
#ifdef DEBUG_NETMAP_USER
    D("icmp echo replied:");
    pkt_dump(buf, l);
#endif
    return 1;
}

static inline int
arp_reply(struct context *ctx, struct nm_desc *d, u_char *buf, uint32_t l)
{
    struct ether_header *ethh;
    struct ether_arp *etha;
    u_int8_t addr[4];
    u_int32_t arp_tpa;
    ethh = (struct ether_header *)buf;
    etha = (struct ether_arp*)(ethh + 1);
    memcpy(&arp_tpa, etha->arp_tpa, 4);
    if (arp_tpa != ctx->if_addr){
        return 0;
    }
    if (etha->ea_hdr.ar_op == htons(ARPOP_REQUEST)) {
        bcopy(ethh->ether_shost, ethh->ether_dhost, 6);
        bcopy(ctx->if_mac, ethh->ether_shost, 6);
        bcopy(ethh->ether_dhost, etha->arp_tha, 6);
        bcopy(ethh->ether_shost, etha->arp_sha, 6);
        /* switch source address and target address */
        bcopy(etha->arp_spa, addr, 4);
        bcopy(etha->arp_tpa, etha->arp_spa, 4);
        bcopy(addr, etha->arp_tpa, 4);
        /* set reply */
        etha->ea_hdr.ar_op = htons(ARPOP_REPLY);
        poll(ctx->fdw, 1, -1);
        nm_inject(d, buf, l);
#ifdef DEBUG_NETMAP_USER
        D("arp request replied:");
        pkt_dump(buf, l);
#endif
    }
    return 1;
}

static inline int
handle_packet(struct context *ctx, struct nm_desc *d, u_char *buf, uint32_t l)
{
    struct ether_header *ethh;
    u_int16_t etht;
    ethh = (struct ether_header *)buf;
    etht = ntohs(ethh->ether_type);
    switch (etht) {
    case ETHERTYPE_IP:
        icmp_echo_reply(ctx, d, buf, l);
        return 0;
    case ETHERTYPE_ARP:
        arp_reply(ctx, d, buf, l);
        return 0;
    }
    return 0;
}

static inline void
initd_cb(u_char *arg, const struct nm_pkthdr *h, const u_char *d)
{
    struct context *ctx = (struct context*) arg;
#ifdef DEBUG_NETMAP_USER
    D("pkt received:");
    pkt_dump(d, h->len);
#endif
    handle_packet(ctx, h->d, h->buf, h->len);
}

static int
main_loop(const char *iname, u_int32_t iaddr, u_int8_t *imac)
{
    struct nm_desc *d;
    d = nm_open(iname, NULL, 0, NULL);
    if (d == NULL) {
        if (!errno) {
            printf("Failed to nm_open(%s): not a netmap port\n", iname);
        } else {
            printf("Failed to nm_open(%s): %s\n", iname,
                   strerror(errno));
        }
        return -1;
    }
    struct context ctx;
    ctx.if_mac = imac;
    ctx.if_addr = iaddr;
    struct pollfd fds, fdw;
    ctx.fdr = &fds;
    ctx.fdw = &fdw;
    fdw.fd = d->fd;
    fdw.events = POLLOUT;
    fds.fd = d->fd;
    fds.events = POLLIN;

    for(;;) {
        poll(&fds, 1, -1);
        nm_dispatch(d, -1, initd_cb, (u_char *)&ctx);
    }
    nm_close(d);
    return 0;
}

static void
usage(char **argv)
{
    printf("usage: %s [-h] <-i INTERFACE> [-a IP ADDRESS] [-m MAC ADDRESS]\n", argv[0]);
    exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
    const char *iname = NULL;
    uint32_t iaddr;
    uint8_t *imac = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "hi:a:m:")) != -1) {
        switch (opt) {
        case 'h':
            usage(argv);
            return 0;
        case 'i':
            iname = optarg;
            break;
        case 'a':
            iaddr = ipv4_aton(optarg);
            break;
        case 'm':
            imac = (uint8_t *)ether_aton(optarg);
            break;
        default:
            printf("    unrecognized option '-%c'\n", opt);
            usage(argv);
            return -1;
        }
    }

    if (iname == NULL) {
        printf("    missing netmap port\n");
        usage(argv);
    }
    printf("Interface    : %s\n", iname);
    uint8_t * p = (uint8_t *) &iaddr;
    printf("IP Address   : %hhu.%hhu.%hhu.%hhu\n", p[0],p[1],p[2],p[3]);
    printf("MAC Address  : %s\n", ether_ntoa((const struct ether_addr*) imac));
    main_loop(iname, iaddr, imac);
    return 0;
}
