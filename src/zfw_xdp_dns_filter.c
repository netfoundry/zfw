#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#define DNS_PORT 53

struct dns_name_struct {
    char dns_name[255];
    __u8 dns_name_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint8_t));
    __uint(value_size, sizeof(struct dns_name_struct));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_map SEC(".maps");

struct dns_question {
    unsigned char qname[64];
    __u16 qtype;
    __u16 qclass;
};
/** \internal The DNS message header. */
struct dnshdr {
    __uint16_t id;
    __uint8_t flags1, flags2;
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
    __uint16_t qdcount;
    __uint16_t ancount;
    __uint16_t nscount;
    __uint16_t arcount;
};
struct dns_question_section {
    char qname[64];
    __uint16_t qtype;
    __uint16_t qclass;
};
/** \internal The resource record (i.e. answer, authority, additional sections) structure. */
struct dns_resource_record {
    /* DNS answer record starts with either a domain name or a pointer
       to a name already present somewhere in the packet. */
    char name[64];
    __uint16_t type;
    __uint16_t class;
    __uint16_t ttl[2];
    __uint16_t rdlength;
    __uint8_t ipaddr[4];
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {

    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(ctx->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(ctx->data + sizeof(*eth));
    /* ensure ip header is in packet bounds */
    if ((unsigned long)(iph + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr *udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
    if ((unsigned long)(udph + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    if (udph->dest != bpf_htons(DNS_PORT)) {
        return XDP_PASS;
    }

    struct dnshdr *dnsh = (struct dnshdr *)((unsigned long)udph + sizeof(*udph));
    if ((unsigned long)(dnsh + 1) > (unsigned long)ctx->data_end){
        return XDP_PASS;
    }

    /* Calculate dns payload size */
    __u8 *dns_payload = (__u8 *)((unsigned long)dnsh + sizeof(*dnsh));
    if ((unsigned long)(dns_payload + 1) > (unsigned long)ctx->data_end) {
        return XDP_PASS;
    }

    int max_question_count = 1;
    __u8 dns_name_len;
    struct dns_name_struct *dns_name = NULL;
    if ((dnsh->qdcount != 0) && (dnsh->ancount == 0) && (dnsh->nscount == 0) && (dnsh->arcount == 0)) {
        for (int i = 0; i < max_question_count; i++) {
            for (int j = 0; j < 255; j++) {
                if ((unsigned long)(dns_payload + j + 1) > (unsigned long)ctx->data_end){
                    return XDP_PASS;
                }
                if (*(dns_payload + j) == 0) {
                    dns_name_len = j+1;
                    break;
                }
            }
            bpf_printk("completed %d ", dns_name_len);
//            for (int j = 0; j < dns_name_len; j++) {
//                bpf_printk("dns name is %c ", *(dns_payload + j));
//            }
//            bpf_map_update_elem(&dns_map, &i, &dns_payload,0);
//            memcpy(&dns_map,&dns_payload,dns_name_len);
//            bpf_printk("completed2 %d ", dns_name_len);
            dns_name = bpf_map_lookup_elem(&dns_map, &i);
            long anwser = bpf_probe_read_str(&dns_name->dns_name, sizeof(dns_name->dns_name), dns_payload);
            if (!anwser) {
                return XDP_PASS;
            }
            
            bpf_printk("completed2 %d ", dns_name_len);
        }
    }
    return XDP_PASS;
}

SEC("license") const char __license[] = "Dual BSD/GPL";