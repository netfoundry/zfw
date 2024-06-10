/*    Copyright (C) 2022  Robert Caamano   */
/*
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.

 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *   see <https://www.gnu.org/licenses/>.
*/

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bcc/bcc_common.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <stdbool.h>
#include <linux/if.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#ifndef memcpy
 #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#define MAX_IF_ENTRIES          30
#define BPF_MAX_SESSIONS        10000
#define INGRESS                 0
#define NO_REDIRECT_STATE_FOUND 10
#define DNS_PORT                53
#define MAX_QDCOUNT             1
#define MAX_DNS_CHARS           255
#define MAX_ALLOWED_CHARS       64
#define MAX_INDEX_ENTRIES       5
#define DNS_MATCH 1
#define DNS_NOT_MATCH 0
#define DNS_CHECK 2

struct bpf_event{
    unsigned long long tstamp;
    __u32 ifindex;
    __u32 tun_ifindex;
    __u32 daddr;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
    __u16 tport;
    __u8 proto;
    __u8 direction;
    __u8 error_code;
    __u8 tracking_code;
    unsigned char source[6];
    unsigned char dest[6];
};

/*Key to tun_map, tcp_map and udp_map*/
struct tuple_key {
    __u32 daddr;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

/*Key to tun_map*/
struct tun_key {
    __u32 daddr;
    __u32 saddr;
};

/*Value to tun_map*/
struct tun_state {
    unsigned long long tstamp;
    unsigned int ifindex;
    unsigned char source[6];
    unsigned char dest[6];
};

/*value to ifindex_tun_map*/
struct ifindex_tun {
    uint32_t index;
    char ifname[IFNAMSIZ];
    char cidr[16];
    uint32_t resolver;
    char mask[3];
    bool verbose;
};

/*tun ifindex map*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct ifindex_tun));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_tun_map SEC(".maps");

/*Ringbuf map*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb_map SEC(".maps");

/*Hashmap to track tun interface inbound passthrough connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tun_key));
     __uint(value_size,sizeof(struct tun_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_map SEC(".maps");

static inline struct tun_state *get_tun(struct tun_key key){
    struct tun_state *ts;
    ts = bpf_map_lookup_elem(&tun_map, &key);
	return ts;
}

/*get entry from tun ifindex map*/
static inline struct ifindex_tun *get_tun_index(uint32_t key){
    struct ifindex_tun *iftun; 
    iftun = bpf_map_lookup_elem(&ifindex_tun_map, &key);
	return iftun;
}

static inline void send_event(struct bpf_event *new_event){
    struct bpf_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&rb_map, sizeof(*rb_event), 0);
    if(rb_event){
        rb_event->ifindex = new_event->ifindex;
        rb_event->tun_ifindex = new_event->tun_ifindex;
        rb_event->tstamp = new_event->tstamp;   
        rb_event->daddr = new_event->daddr;
        rb_event->saddr = new_event->saddr;
        rb_event->dport = new_event->dport;
        rb_event->sport = new_event->sport;
        rb_event->tport = new_event->tport;
        rb_event->proto = new_event->proto;
        rb_event->direction = new_event->direction;
        rb_event->tracking_code = new_event->tracking_code;
        rb_event->error_code = new_event->error_code;
        for(int x =0; x < 6; x++){
            rb_event->source[x] = new_event->source[x];
            rb_event->dest[x] = new_event->dest[x];
        }
        bpf_ringbuf_submit(rb_event, 0);
    }
}

struct dns_name_struct {
    char dns_name[MAX_DNS_CHARS];
    uint8_t dns_length;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct dns_name_struct));
    __uint(max_entries, MAX_INDEX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct dns_name_struct));
    __uint(max_entries, MAX_INDEX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_map SEC(".maps");

/* The DNS message header. */
struct dnshdr {
    uint16_t id;
    uint8_t flags1, flags2;
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
/* The question section structure. */
struct dns_question_section {
    char qname[MAX_DNS_CHARS];
    uint16_t qtype;
    uint16_t qclass;
};
/* The resource record (i.e. answer, authority, additional sections) structure. */
struct dns_resource_record {
    /* DNS answer record starts with either a domain name or a pointer
       to a name already present somewhere in the packet. */
    char name[MAX_DNS_CHARS];
    uint16_t type;
    uint16_t class;
    uint16_t ttl[2];
    uint16_t rdlength;
    uint8_t ipaddr[4];
};

/* get entry from domain_map map */
static inline struct dns_name_struct *get_domain_name(const uint32_t key){
    struct dns_name_struct* domain_name = bpf_map_lookup_elem(&domain_map, &key);
    return domain_name;
}

/* get the length of dns question name */
static inline struct dns_name_struct *get_dns(const int index, const void *dns_question) {
    struct dns_name_struct *dns_name = NULL;
    dns_name = bpf_map_lookup_elem(&dns_map, &index);
    if(dns_name){
        const long length = bpf_probe_read_kernel_str((void *)&dns_name->dns_name, sizeof(dns_name->dns_name), dns_question);
        // bpf_printk("answer=%d",length);
        // if (length > 0) {
        //     for (int i = 0; i < length; i++) {
        //         bpf_printk(":%c", dns_name->dns_name[i]);
        //     }
        // }
        dns_name->dns_length = length;
    }else{
        bpf_printk("no map entry found");
    }
    return dns_name;
}

static inline int compare_domain_names(const struct dns_name_struct *dnc, const struct dns_name_struct *dni) {
    //const uint8_t dni_reverse_start = dni->dns_length - dnc->dns_length - 1;
    /* check if the configured domain length is not more than MAX_ALLOWED_CHARS chars long */
    int y =0; /* character counter */
    for (int z = 0; z < MAX_ALLOWED_CHARS; z++) {
        /* Point to the last char of each string to start counting */
        const uint8_t dni_reverse_start = dni->dns_length - 2 - z;
        const uint8_t dnc_reverse_start = dnc->dns_length - 2 - z;
        // bpf_printk("char count is %d", y);
        // bpf_printk("z is %d", z);
        // bpf_printk("dnc->dns_length is %d", dnc->dns_length);
        /* if custom domain char is a dot and intercepted domain name char is dot in form of char count */
        if (dnc->dns_name[dnc_reverse_start] == '.' && dni->dns_name[dni_reverse_start] == y) {
            // bpf_printk("dni start char is %x", dni->dns_name[dni_reverse_start]);
            // bpf_printk("dnc start char is %x", dnc->dns_name[dnc_reverse_start]);
            /* reset character counter for domain/subdomain */
            y=0;
        /* if custom domain reached its length and intercepted domain char is dot in form of char count */
        } else if (dnc->dns_length == z+1 && dni->dns_name[dni_reverse_start] == y) {
            // bpf_printk("dni start char is %x", dni->dns_name[dni_reverse_start]);
            // bpf_printk("dnc start char is %x", dnc->dns_name[dnc_reverse_start]);
             break;
        /* if custom domain and intercepted domain chars are not the same */
        } else if (dni->dns_name[dni_reverse_start] != dnc->dns_name[dnc_reverse_start]) {
            return 1;
        /* if neither of the previous asks are true, then increase the char counter and continue to compare chars  */
        } else {
            y++;
        }
    }
    return 0;
}

static inline uint16_t ip_checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }
    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

SEC("xdp_redirect")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    /*look up attached interface inbound diag status*/
    struct ifindex_tun *tun_diag = get_tun_index(0);
    if (!tun_diag)
    {
        return XDP_PASS;
    }  
    struct iphdr *iph = (struct iphdr *)(unsigned long)(ctx->data);
    /* ensure ip header is in packet bounds */
    if ((unsigned long)(iph + 1) > (unsigned long)ctx->data_end){
            return XDP_PASS;
    }
    /* ip options not allowed */
    if (iph->ihl != 5){
        
        return XDP_PASS;
    }
    unsigned long long tstamp = bpf_ktime_get_ns();
    struct bpf_event event = {
        tstamp,
        ctx->ingress_ifindex,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        INGRESS,
        0,
        0,
        {0},
        {0}
     };
   
    struct tun_key tun_state_key;
    tun_state_key.daddr = iph->saddr;
    tun_state_key.saddr = iph->daddr;

    // check for dns responses
    __u8 protocol = iph->protocol;
    if(protocol == IPPROTO_UDP){  
        struct udphdr *udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
        if ((unsigned long)(udph + 1) > (unsigned long)ctx->data_end){
            return XDP_PASS;
        }
        if (udph->dest == bpf_htons(DNS_PORT)) {
            struct dnshdr *dnsh = (struct dnshdr *)((unsigned long)udph + sizeof(*udph));
            if ((unsigned long)(dnsh + 1) > (unsigned long)ctx->data_end){
                return XDP_PASS;
            }
            event.proto = protocol;
            event.dport = udph->dest;
            event.sport = udph->source;
            event.saddr = iph->saddr;
            event.daddr = iph->daddr;
            event.tracking_code = DNS_CHECK;
            send_event(&event);
            /* Initial dns payload pointer */
            __u8 *dns_payload = (__u8 *)((unsigned long)dnsh + sizeof(*dnsh));
            if ((unsigned long)(dns_payload + 1) > (unsigned long)ctx->data_end) {
                return XDP_PASS;
            }
            
            /* logic to find dns name string */
            if (bpf_htons(dnsh->qdcount) != 0 && bpf_htons(dnsh->ancount) == 0) {
                // bpf_printk("in max_qdcount before loop");
                for (int x = 0; x < MAX_QDCOUNT; x++) {
                    /* get interceptes domain name from interface */
                    const struct dns_name_struct *domain_name_intercepted = get_dns(x, dns_payload);
                    if (domain_name_intercepted && domain_name_intercepted->dns_length > 0) {
                        for (int y = 0; y < MAX_INDEX_ENTRIES; y++) {
                            /* get private domain name from map */
                            const struct dns_name_struct *domain_name_configured = get_domain_name(y);
                            if (domain_name_configured && domain_name_configured->dns_name[0] != '\0') {
                                const int result = compare_domain_names(domain_name_configured, domain_name_intercepted);
                                if (result == 0) {
                                    event.tracking_code = DNS_MATCH;
                                    send_event(&event);
                                } else {
                                    event.tracking_code = DNS_NOT_MATCH;
                                    send_event(&event);
                                }
                            } else {
                                // bpf_printk("no entry found");sudo
                            }
                        }
                        /* Move dns payload pointer to next question or section */
                        dns_payload = (dns_payload + domain_name_intercepted->dns_length + 4);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    struct tun_state *tus = get_tun(tun_state_key);
    if(tus){
        bpf_xdp_adjust_head(ctx, -14);
        struct ethhdr *eth = (struct ethhdr *)(unsigned long)(ctx->data);
        /* verify its a valid eth header within the packet bounds */
        if ((unsigned long)(eth + 1) > (unsigned long)ctx->data_end){
                return XDP_PASS;
        }
        if(tun_diag->verbose){
            struct iphdr *iph = (struct iphdr *)(ctx->data + sizeof(*eth));
            /* ensure ip header is in packet bounds */
            if ((unsigned long)(iph + 1) > (unsigned long)ctx->data_end){
                    return XDP_PASS;
            }
            __u8 protocol = iph->protocol;
            if(protocol == IPPROTO_TCP){
                struct tcphdr *tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
                if ((unsigned long)(tcph + 1) > (unsigned long)ctx->data_end){
                    return XDP_PASS;
                }
                event.dport = tcph->dest;
                event.sport = tcph->source;
            }else if (protocol == IPPROTO_UDP){
                struct udphdr *udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
                if ((unsigned long)(udph + 1) > (unsigned long)ctx->data_end){
                    return XDP_PASS;
                }
                event.dport = udph->dest;
                event.sport = udph->source;
            }
            event.tun_ifindex = tus->ifindex;
            event.proto = protocol;
            event.saddr = iph->saddr;
            event.daddr = iph->daddr;
            memcpy(&event.source, &tus->dest, 6);
            memcpy(&event.dest, &tus->source, 6);
            send_event(&event);
        }
        memcpy(&eth->h_dest, &tus->source,6);
        memcpy(&eth->h_source, &tus->dest,6);
        unsigned short proto = bpf_htons(ETH_P_IP);
        memcpy(&eth->h_proto, &proto, sizeof(proto));
        return bpf_redirect(tus->ifindex,0);
    }
    if(tun_diag->verbose){
        event.error_code = NO_REDIRECT_STATE_FOUND;
        send_event(&event);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
