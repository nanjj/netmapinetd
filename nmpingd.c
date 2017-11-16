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
#include "nmapps.h"

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
icmp_echo_reply(struct context *ctx, struct nm_desc *d, const u_char *data, uint32_t len)
{
    u_char buf[len];
    memcpy(buf, data, len);
    struct ether_header *ethh = (struct ether_header *)buf;
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    struct icmphdr *icmph = (struct icmphdr *)(iph + 1);
    u_int32_t addr = iph->saddr;
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
    nm_inject(d, buf, len);
#ifdef DEBUG_NETMAP_USER
    D("icmp echo replied:");
    pkt_dump(buf, len);
#endif
    return 1;
}

static inline int
arp_reply(struct context *ctx, struct nm_desc *d, const u_char *data, uint32_t len)
{
    u_char buf[len];
    memcpy(buf, data, len);
    struct ether_header *ethh = (struct ether_header *)buf;
    struct ether_arp *arph =  (struct ether_arp*)(ethh + 1);
    bcopy(ethh->ether_shost, ethh->ether_dhost, 6);
    bcopy(ctx->if_mac, ethh->ether_shost, 6);
    bcopy(ethh->ether_dhost, arph->arp_tha, 6);
    bcopy(ethh->ether_shost, arph->arp_sha, 6);
    /* switch source address and target address */
    uint8_t addr[4];
    bcopy(arph->arp_spa, addr, 4);
    bcopy(arph->arp_tpa, arph->arp_spa, 4);
    bcopy(addr, arph->arp_tpa, 4);
    /* set reply */
    arph->ea_hdr.ar_op = htons(ARPOP_REPLY);
    poll(ctx->fdw, 1, -1);
    nm_inject(d, buf, len);
#ifdef DEBUG_NETMAP_USER
    D("arp request replied:");
    pkt_dump(buf, len);
#endif
    return 1;
}

static inline void
initd_cb(u_char *arg, const struct nm_pkthdr *h, const u_char *data)
{
#ifdef DEBUG_NETMAP_USER
    D("pkt received:");
    pkt_dump(data, h->len);
#endif
    struct context *ctx = (struct context*) arg;
    struct ether_header *ethh = (struct ether_header *)data;
    struct iphdr *iph;
    struct icmphdr * icmph;
    struct ether_arp *arph;
    uint32_t len = h->len;
    switch (ntohs(ethh->ether_type)) {
    case ETHERTYPE_IP:
        iph = (struct iphdr *)(ethh + 1);
        if (iph->protocol != IPPROTO_ICMP || iph->daddr != ctx->if_addr){
            break;
        }
        icmph = (struct icmphdr *)(iph + 1);
        /* Match the icmp echo request. */
        if (icmph->type != ICMP_ECHO) {
            break;
        }
        icmp_echo_reply(ctx, h->d, data, len);
        break;
    case ETHERTYPE_ARP:
        arph = (struct ether_arp*)(ethh + 1);
        u_int32_t arp_tpa;
        memcpy(&arp_tpa, arph->arp_tpa, 4);
        if (arp_tpa != ctx->if_addr || arph->ea_hdr.ar_op != htons(ARPOP_REQUEST)){
            break;
        }
        arp_reply(ctx, h->d, data, len);
        break;
    }
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
