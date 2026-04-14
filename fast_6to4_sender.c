#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_LINE 256
#define IPV6_HDR_LEN 40
#define ICMPV6_HDR_LEN 8
#define UDP_HDR_LEN 8

struct icmp6_ptb_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    uint32_t mtu;
} __attribute__((packed));

struct pseudo6 {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t plen;
    uint8_t zero[3];
    uint8_t nh;
} __attribute__((packed));

static uint16_t checksum16(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t icmpv6_checksum(
    const struct in6_addr *src,
    const struct in6_addr *dst,
    const uint8_t *icmp,
    size_t icmp_len
) {
    struct pseudo6 ph;
    memset(&ph, 0, sizeof(ph));
    ph.src = *src;
    ph.dst = *dst;
    ph.plen = htonl((uint32_t)icmp_len);
    ph.nh = IPPROTO_ICMPV6;

    size_t total = sizeof(ph) + icmp_len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        return 0;
    }
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), icmp, icmp_len);
    uint16_t csum = checksum16(buf, total);
    free(buf);
    return csum;
}

static void ipv4_to_6to4_prefix(uint32_t v4_be, char *out, size_t out_len) {
    uint32_t v4 = ntohl(v4_be);
    uint16_t hi = (uint16_t)((v4 >> 16) & 0xFFFF);
    uint16_t lo = (uint16_t)(v4 & 0xFFFF);
    snprintf(out, out_len, "2002:%04x:%04x", hi, lo);
}

static int build_6to4_ptb_packet(
    uint8_t *buf,
    size_t buf_len,
    const char *scanner_v4,
    const char *scanner_v6,
    const char *target_v4,
    uint16_t mtu
) {
    if (buf_len < 1500) {
        return -1;
    }

    struct iphdr *ip4 = (struct iphdr *)buf;
    struct ip6_hdr *inner6 = (struct ip6_hdr *)(buf + sizeof(struct iphdr));
    struct icmp6_ptb_hdr *ptb = (struct icmp6_ptb_hdr *)(buf + sizeof(struct iphdr) + IPV6_HDR_LEN);
    struct ip6_hdr *trigger6 = (struct ip6_hdr *)((uint8_t *)ptb + ICMPV6_HDR_LEN);
    struct udphdr *trigger_udp = (struct udphdr *)((uint8_t *)trigger6 + IPV6_HDR_LEN);

    char prefix[32];
    struct in_addr target4_addr;
    if (inet_pton(AF_INET, target_v4, &target4_addr) != 1) {
        return -1;
    }
    ipv4_to_6to4_prefix(target4_addr.s_addr, prefix, sizeof(prefix));

    char target_v6[80];
    char spoofed_v6[80];
    snprintf(target_v6, sizeof(target_v6), "%s::1", prefix);
    snprintf(spoofed_v6, sizeof(spoofed_v6), "%s::abcd", prefix);

    memset(buf, 0, 1500);

    ip4->ihl = 5;
    ip4->version = 4;
    ip4->tos = 0;
    ip4->id = htons((uint16_t)(rand() & 0xFFFF));
    ip4->frag_off = 0;
    ip4->ttl = 64;
    ip4->protocol = 41;
    if (inet_pton(AF_INET, scanner_v4, &ip4->saddr) != 1) {
        return -1;
    }
    if (inet_pton(AF_INET, target_v4, &ip4->daddr) != 1) {
        return -1;
    }

    inner6->ip6_flow = htonl((6u << 28));
    inner6->ip6_hops = 64;
    inner6->ip6_nxt = IPPROTO_ICMPV6;
    if (inet_pton(AF_INET6, spoofed_v6, &inner6->ip6_src) != 1) {
        return -1;
    }
    if (inet_pton(AF_INET6, target_v6, &inner6->ip6_dst) != 1) {
        return -1;
    }

    ptb->type = 2;
    ptb->code = 0;
    ptb->csum = 0;
    ptb->mtu = htonl((uint32_t)mtu);

    trigger6->ip6_flow = htonl((6u << 28));
    trigger6->ip6_hops = 64;
    trigger6->ip6_nxt = IPPROTO_UDP;
    if (inet_pton(AF_INET6, target_v6, &trigger6->ip6_src) != 1) {
        return -1;
    }
    if (inet_pton(AF_INET6, scanner_v6, &trigger6->ip6_dst) != 1) {
        return -1;
    }
    trigger6->ip6_plen = htons(UDP_HDR_LEN);

    trigger_udp->source = htons(53);
    trigger_udp->dest = htons(12345);
    trigger_udp->len = htons(UDP_HDR_LEN);
    trigger_udp->check = 0;

    size_t icmp_len = ICMPV6_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN;
    inner6->ip6_plen = htons((uint16_t)icmp_len);

    ptb->csum = icmpv6_checksum(
        &inner6->ip6_src,
        &inner6->ip6_dst,
        (const uint8_t *)ptb,
        icmp_len
    );

    size_t total_len = sizeof(struct iphdr) + IPV6_HDR_LEN + icmp_len;
    ip4->tot_len = htons((uint16_t)total_len);
    ip4->check = 0;
    ip4->check = checksum16(ip4, sizeof(struct iphdr));

    return (int)total_len;
}

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <scanner_v4> <scanner_v6> <targets_v4.txt|--full-v4> [pps]\n", argv[0]);
        return 1;
    }

    const char *scanner_v4 = argv[1];
    const char *scanner_v6 = argv[2];
    const char *targets_arg = argv[3];
    int pps = (argc >= 5) ? atoi(argv[4]) : 10000;
    if (pps <= 0) {
        pps = 10000;
    }

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(fd);
        return 1;
    }

    srand((unsigned int)time(NULL));

    uint8_t packet[1500];
    int64_t interval = 1000000000LL / pps;
    int64_t next_ts = now_ns();

    uint64_t sent = 0;
    if (strcmp(targets_arg, "--full-v4") == 0) {
        for (uint64_t i = 0; i <= 0xFFFFFFFFULL; i++) {
            struct in_addr dst_v4;
            dst_v4.s_addr = htonl((uint32_t)i);
            char target_ip[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &dst_v4, target_ip, sizeof(target_ip))) {
                continue;
            }

            int pkt_len = build_6to4_ptb_packet(packet, sizeof(packet), scanner_v4, scanner_v6, target_ip, 1280);
            if (pkt_len <= 0) {
                continue;
            }

            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_addr = dst_v4;

            int64_t now = now_ns();
            if (now < next_ts) {
                int64_t wait_ns = next_ts - now;
                struct timespec slp;
                slp.tv_sec = wait_ns / 1000000000LL;
                slp.tv_nsec = wait_ns % 1000000000LL;
                nanosleep(&slp, NULL);
            }
            next_ts += interval;

            ssize_t n = sendto(fd, packet, (size_t)pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
            if (n < 0) {
                continue;
            }
            sent++;
            if (sent % 10000 == 0) {
                fprintf(stdout, "sent=%" PRIu64 " pps=%d last=%s\n", sent, pps, target_ip);
                fflush(stdout);
            }
        }
    } else {
        FILE *fp = fopen(targets_arg, "r");
        if (!fp) {
            perror("fopen");
            close(fd);
            return 1;
        }

        char line[MAX_LINE];
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strchr(line, '\n');
            if (nl) {
                *nl = '\0';
            }
            if (line[0] == '\0') {
                continue;
            }

            int pkt_len = build_6to4_ptb_packet(packet, sizeof(packet), scanner_v4, scanner_v6, line, 1280);
            if (pkt_len <= 0) {
                fprintf(stderr, "skip invalid target: %s\n", line);
                continue;
            }

            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            if (inet_pton(AF_INET, line, &dst.sin_addr) != 1) {
                fprintf(stderr, "skip non-ipv4 target: %s\n", line);
                continue;
            }

            int64_t now = now_ns();
            if (now < next_ts) {
                int64_t wait_ns = next_ts - now;
                struct timespec slp;
                slp.tv_sec = wait_ns / 1000000000LL;
                slp.tv_nsec = wait_ns % 1000000000LL;
                nanosleep(&slp, NULL);
            }
            next_ts += interval;

            ssize_t n = sendto(fd, packet, (size_t)pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
            if (n < 0) {
                fprintf(stderr, "sendto %s failed: %s\n", line, strerror(errno));
                continue;
            }
            sent++;
            if (sent % 10000 == 0) {
                fprintf(stdout, "sent=%" PRIu64 " pps=%d\n", sent, pps);
                fflush(stdout);
            }
        }
        fclose(fp);
    }

    fprintf(stdout, "done, sent=%" PRIu64 "\n", sent);
    close(fd);
    return 0;
}
