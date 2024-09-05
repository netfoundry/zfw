/*   Copyright (C) 2022  Robert Caamano   */
/*   SPDIX-License-Identifier: SPDX-License-Identifier: LGPL-2.1+
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
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bcc/bcc_common.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <iproute2/bpf_elf.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <stdio.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES   100 //MAX # PREFIXES
#endif
#define MAX_INDEX_ENTRIES 100
#define MAX_ADDRESSES 10
#define BPF_MAX_RANGES 250000
#define MAX_IF_LIST_ENTRIES 3
#define MATCHED_KEY_DEPTH 3
#define MAX_IF_ENTRIES 256
#define BPF_MAX_SESSIONS 65535
#define IP_HEADER_TOO_BIG 1
#define NO_IP_OPTIONS_ALLOWED 2
#define IP_TUPLE_TOO_BIG 8
#define IF_LIST_MATCH_ERROR 9
#define EGRESS 1
#define ICMP_HEADER_TOO_BIG 7
#define CLIENT_SYN_RCVD 7
#define CLIENT_FIN_RCVD 8
#define CLIENT_RST_RCVD 9
#define TCP_CONNECTION_ESTABLISHED 10
#define CLIENT_FINAL_ACK_RCVD 11
#define CLIENT_INITIATED_UDP_SESSION 12
#define INGRESS_UDP_MATCHED_EXPIRED_STATE 15
#define INGRESS_UDP_MATCHED_ACTIVE_STATE 16
#define INGRESS_SERVER_SYN_ACK_RCVD 22
#define INGRESS_SERVER_FIN_RCVD 23
#define INGRESS_SERVER_RST_RCVD 24
#define INGRESS_SERVER_FINAL_ACK_RCVD 25
#define MATCHED_DROP_FILTER 26
#define CLIENT_INITIATED_ICMP_ECHO 29
#define IP6_HEADER_TOO_BIG 30
#define IPV6_TUPLE_TOO_BIG 31
#define REVERSE_MASQUERADE_ENTRY_REMOVED 32
#define MASQUERADE_ENTRY_REMOVED 33
#define REVERSE_MASQUERADE_ENTRY_ADDED 34
#define MASQUERADE_ENTRY_ADDED 35
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))

struct bpf_event{
    __u8 version;
    unsigned long long tstamp;
    __u32 ifindex;
    __u32 tun_ifindex;
    __u32 daddr[4];
    __u32 saddr[4];
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

/*Key to tcp_map and udp_map*/
struct tuple_key {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dst;
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_src;
    __u16 sport;
    __u16 dport;
};

/*Key to icmp_echo_map*/
struct icmp_key {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dst;
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_src;
    __u16 id;
    __u16 seq;
    __u32 ifindex;
};

/*Key to icmp_masquerade_map*/
struct icmp_masq_key {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dest;
    __u16 id;
    __u16 seq;
    __u32 ifindex;
};

/*Value to tcp_map*/
struct tcp_state {
    unsigned long long tstamp;
    __u32 sfseq;
    __u32 cfseq;
    __u8 syn;
    __u8 sfin;
    __u8 cfin;
    __u8 sfack;
    __u8 cfack;
    __u8 ack;
    __u8 rst;
    __u8 est;
};

/*Value to udp_map*/
struct udp_state {
    unsigned long long tstamp;
};

/*Value to icmp_echo_map*/
struct icmp_state {
    unsigned long long tstamp;
};

/*Key to masquerade_map*/
struct masq_key {
    uint32_t ifindex;
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dest;
    __u8 protocol;
    __u16 sport;
    __u16 dport;
};

/*Key to masquerade_reverse_map*/
struct masq_reverse_key {
    uint32_t ifindex;
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_src;
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dest;
    __u8 protocol;
    __u16 sport;
    __u16 dport;
};

/*value to masquerade_map and icmp_masquerade_map*/
struct masq_value {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_origin;
    __u16 o_sport;
};

/*value to diag_map*/
struct diag_ip4 {
    bool echo;
    bool verbose;
    bool per_interface;
    bool ssh_disable;
    bool tc_ingress;
    bool tc_egress;
    bool tun_mode;
    bool vrrp;
    bool eapol;
    bool ddos_filtering;
    bool ipv6_enable;
    bool outbound_filter;
    bool masquerade;
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

struct tproxy_tuple {
    __u16 index_len; /*tracks the number of entries in the index_table*/
    __u16 index_table[MAX_INDEX_ENTRIES];/*Array used as index table to associate 
                                          *port ranges and tproxy ports with prefix tuples/protocol
                                          */    
};

/*key to zt_tproxy_map*/
struct tproxy_key {
    __u32 dst_ip;
    __u32 src_ip;
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

/*key to zt_tproxy_map6*/
struct tproxy6_key {
    __u32 dst_ip[4];
    __u32 src_ip[4];
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

struct range_mapping {
    __u16 high_port;
    __u16 tproxy_port;
    bool deny;
};

struct tproxy_extension_key {
    __u16 tproxy_port;
    __u8 protocol;
    __u8 pad;
};

struct port_extension_key {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dst;
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_src;
    __u16 low_port;
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

struct tproxy_extension_mapping {
    char service_id[23];
};

struct if_list_extension_mapping {
    __u32 if_list[MAX_IF_LIST_ENTRIES];
};

/*value to ifindex_ip_map*/
struct ifindex_ip4 {
    uint32_t ipaddr[MAX_ADDRESSES];
    char ifname[IFNAMSIZ];
    uint8_t count;
};

/*value to ifindex_ip6_map*/
struct ifindex_ip6 {
    char ifname[IFNAMSIZ];
    uint32_t ipaddr[MAX_ADDRESSES][4];
    uint8_t count;
};

/*Value to egress_matched_map*/
struct match_tracker {
    __u16 count;
    struct tproxy_key matched_keys[MATCHED_KEY_DEPTH];
};

/*Key to egress_matched_map*/
struct match_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 ifindex;
    __u32 protocol;
};

/*Key to egress_matched6_map*/
struct match6_key {
    __u32 saddr[4];
    __u32 daddr[4];
    __u16 sport;
    __u16 dport;
    __u32 ifindex;
    __u32 protocol;
};

/* map to track up to 3 key matches per egressing IPv4 packet search.  Map is 
then used to search for port mappings.*/

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct match_key));
    __uint(value_size, sizeof(struct match_tracker));
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_matched_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct match6_key));
    __uint(value_size, sizeof(struct tproxy6_key));
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_matched6_map SEC(".maps");

/*Map for filtering outbound IPv4 traffic*/
struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(key_size, sizeof(struct tproxy_key));
     __uint(value_size,sizeof(struct tproxy_tuple));
     __uint(max_entries, BPF_MAX_ENTRIES);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
     __uint(map_flags, BPF_F_NO_PREALLOC);
} zt_egress_map SEC(".maps");

/*Map for filtering outbound IPv6 traffic*/
struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(key_size, sizeof(struct tproxy6_key));
     __uint(value_size,sizeof(struct tproxy_tuple));
     __uint(max_entries, BPF_MAX_ENTRIES);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
     __uint(map_flags, BPF_F_NO_PREALLOC);
} zt_egress6_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tproxy_extension_key));
    __uint(value_size, sizeof(struct tproxy_extension_mapping));
    __uint(max_entries, BPF_MAX_RANGES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_extension_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct port_extension_key));
    __uint(value_size, sizeof(struct if_list_extension_mapping));
    __uint(max_entries, BPF_MAX_RANGES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_if_list_extension_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct port_extension_key));
    __uint(value_size, sizeof(struct range_mapping));
    __uint(max_entries, BPF_MAX_RANGES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_range_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_count_map SEC(".maps");

//map to keep track of total entries in zt_tproxy6_map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress6_count_map SEC(".maps");

/*tun ifindex map*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct ifindex_tun));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_tun_map SEC(".maps");

//map to keep status of diagnostic rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct diag_ip4));
    __uint(max_entries, MAX_IF_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} diag_map SEC(".maps");

/*Hashmap to track outbound passthrough TCP connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct tcp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_map SEC(".maps");

/*Hashmap to track ingress passthrough TCP connections i.e. to LAN or host
VMs/Containers*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct tcp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_ingress_map SEC(".maps");

/*Hashmap to track outbound passthrough UDP connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct udp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_map SEC(".maps");

/*tracks inbound allowed sessions*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct udp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_ingress_map SEC(".maps");

/*tracks icmp echo sessions*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct icmp_key));
     __uint(value_size,sizeof(struct icmp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} icmp_echo_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct masq_key));
     __uint(value_size,sizeof(struct masq_value));
     __uint(max_entries, BPF_MAX_SESSIONS * 2);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} masquerade_map SEC(".maps");

/*stores reverse lookup table udp and tcp masquerade*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct masq_reverse_key));
     __uint(value_size,sizeof(struct masq_value));
     __uint(max_entries, BPF_MAX_SESSIONS * 2);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} masquerade_reverse_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct icmp_masq_key));
     __uint(value_size,sizeof(struct masq_value));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} icmp_masquerade_map SEC(".maps");

/*Ringbuf map*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb_map SEC(".maps");

/* File system pinned Array Map key mapping to ifindex with used to allow 
 * ebpf program to learn the ip address
 * of the interface it is attached to by reading the mapping
 * provided by user space it can use skb->ifindex __uint(key_size, sizeof(uint32_t));ss_ifindex
 * to find its corresponding ip address. Currently used to limit
 * ssh to only the attached interface ip 
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct ifindex_ip4));
    __uint(max_entries, MAX_IF_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ifindex_ip_map SEC(".maps");

/* File system pinned Array Map key mapping to ifindex with used to allow 
 * ebpf program to learn the ip address
 * of the interface it is attached to by reading the mapping
 * provided by user space it can use skb->ifindex __uint(key_size, sizeof(uint32_t));ss_ifindex
 * to find its corresponding ip6 address. Currently used to limit
 * ssh to only the attached interface ip6 
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct ifindex_ip6));
    __uint(max_entries, MAX_IF_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ifindex_ip6_map SEC(".maps");

/*get entry from tun ifindex map*/
static inline struct ifindex_tun *get_tun_index(uint32_t key){
    struct ifindex_tun *iftun; 
    iftun = bpf_map_lookup_elem(&ifindex_tun_map, &key);
    return iftun;
}

/*Insert entry into tcp state table*/
static inline void insert_tcp(struct tcp_state tstate, struct tuple_key key){
     bpf_map_update_elem(&tcp_map, &key, &tstate,0);
}

static inline void insert_masquerade(struct masq_value mv, struct masq_key key){
     bpf_map_update_elem(&masquerade_map, &key, &mv,0);
}

static inline struct masq_value *get_masquerade(struct masq_key key){
    struct masq_value *mv;
    mv = bpf_map_lookup_elem(&masquerade_map, &key);
	return mv;
}

/*Remove entry from  masq state table*/
static inline void del_masq(struct masq_key key){
     bpf_map_delete_elem(&masquerade_map, &key);
}

static inline void insert_reverse_masquerade(struct masq_value mv, struct masq_reverse_key key){
     bpf_map_update_elem(&masquerade_reverse_map, &key, &mv,0);
}

/*Remove entry from reverse masq state table*/
static inline void del_reverse_masq(struct masq_reverse_key key){
     bpf_map_delete_elem(&masquerade_reverse_map, &key);
}

static inline struct masq_value *get_reverse_masquerade(struct masq_reverse_key key){
    struct masq_value *mv;
    mv = bpf_map_lookup_elem(&masquerade_reverse_map, &key);
	return mv;
}

static inline void insert_icmp_masquerade(struct masq_value mv, struct icmp_masq_key key){
     bpf_map_update_elem(&icmp_masquerade_map, &key, &mv,0);
}


/*Remove entry into tcp state table*/
static inline void del_tcp(struct tuple_key key){
     bpf_map_delete_elem(&tcp_map, &key);
}

/*get entry from tcp state table*/
static inline struct tcp_state *get_tcp(struct tuple_key key){
    struct tcp_state *ts;
    ts = bpf_map_lookup_elem(&tcp_map, &key);
	return ts;
}

/*Remove entry into ingress tcp state table*/
static inline void del_ingress_tcp(struct tuple_key key){
     bpf_map_delete_elem(&tcp_ingress_map, &key);
}

/*get entry from ingress tcp state table*/
static inline struct tcp_state *get_ingress_tcp(struct tuple_key key){
    struct tcp_state *ts;
    ts = bpf_map_lookup_elem(&tcp_ingress_map, &key);
	return ts;
}

/*Insert entry into udp state table*/
static inline void insert_udp(struct udp_state ustate, struct tuple_key key){
     bpf_map_update_elem(&udp_map, &key, &ustate,0);
}

/*get entry from udp state table*/
static inline struct udp_state *get_udp(struct tuple_key key){
    struct udp_state *us;
    us = bpf_map_lookup_elem(&udp_map, &key);
	return us;
}

static inline struct udp_state *get_udp_ingress(struct tuple_key key){
    struct udp_state *us;
    us = bpf_map_lookup_elem(&udp_ingress_map, &key);
	return us;
}

static inline void del_udp_ingress(struct tuple_key key){
     bpf_map_delete_elem(&udp_ingress_map, &key);
}

/*Insert entry into icmp echo state table*/
static inline void insert_icmp(struct icmp_state istate, struct icmp_key key){
     bpf_map_update_elem(&icmp_echo_map, &key, &istate,0);
}

static inline struct diag_ip4 *get_diag_ip4(__u32 key){
    struct diag_ip4 *if_diag;
    if_diag = bpf_map_lookup_elem(&diag_map, &key);

	return if_diag;
}

/* Function used by ebpf program to access ifindex_ip_map
 * in order to lookup the ip associated with its attached interface
 * This allows distinguishing between socket to the local system i.e. ssh
 *  vs socket that need to be forwarded to the tproxy splicing function
 * 
 */
static inline struct ifindex_ip4 *get_local_ip4(__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);
	return ifip4;
}

/* Function used by ebpf program to access ifindex_ip6_map
 * in order to lookup the ipv6 addr associated with its attached interface
 * This allows distinguishing between socket to the local system i.e. ssh
 *  vs socket that need to be forwarded to the tproxy splicing function
 * 
 */
static inline struct ifindex_ip6 *get_local_ip6(__u32 key){
    struct ifindex_ip6 *ifip6;
    ifip6 = bpf_map_lookup_elem(&ifindex_ip6_map, &key);
	return ifip6;
}

/*function to update the matched_map locally from ebpf*/
static inline void insert_matched_key(struct match_tracker matched_keys, struct match_key key){
     bpf_map_update_elem(&egress_matched_map, &key, &matched_keys,0);
}

/*Function to get stored matched tracker*/
static inline struct match_tracker *get_matched_keys(struct match_key key){
    struct match_tracker *mt;
    mt = bpf_map_lookup_elem(&egress_matched_map, &key);
	return mt;
}

/*Function to get stored matched key count*/
static inline __u16 get_matched_count(struct match_key key){
    struct match_tracker *mt;
    __u16 mc = 0;
    mt = bpf_map_lookup_elem(&egress_matched_map,&key);
    if(mt){
        mc = mt->count;
    }
    return mc;
}

/*Function to clear matched tracker*/
static inline void clear_match_tracker(struct match_key key){
    bpf_map_delete_elem(&egress_matched_map, &key);
}

/*function to update the matched_map locally from ebpf*/
static inline void insert_matched6_key(struct tproxy6_key matched6_key, struct match6_key key){
     bpf_map_update_elem(&egress_matched6_map, &key, &matched6_key,0);
}

/*Function to get stored matched tracker*/
static inline struct tproxy6_key *get_matched6_key(struct match6_key key){
    struct tproxy6_key *tp6;
    tp6 = bpf_map_lookup_elem(&egress_matched6_map, &key);
	return tp6;
}

/*Function to clear matched tracker*/
static inline void clear_match6_tracker(struct match6_key key){
    bpf_map_delete_elem(&egress_matched6_map, &key);
}

/* function for ebpf program to access zt_tproxy_map entries
 * based on {prefix,mask,protocol} i.e. {192.168.1.0,24,IPPROTO_TCP}
 */
static inline struct tproxy_tuple *get_egress(struct tproxy_key key){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_egress_map, &key);
	return tu;
}

static inline struct tproxy_tuple *get_egress6(struct tproxy6_key key){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_egress6_map, &key);
	return tu;
}

static inline struct if_list_extension_mapping *get_if_list_ext_mapping(struct port_extension_key key){
    struct if_list_extension_mapping *ifem;
    ifem = bpf_map_lookup_elem(&egress_if_list_extension_map, &key);
    return ifem;
}

static inline struct range_mapping *get_range_ports(struct port_extension_key key){
    struct range_mapping *hp;
    hp = bpf_map_lookup_elem(&egress_range_map, &key);
    return hp;
}

static inline void send_event(struct bpf_event *new_event){
    struct bpf_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&rb_map, sizeof(*rb_event), 0);
    if(rb_event){
        rb_event->version = new_event->version;
        rb_event->ifindex = new_event->ifindex;
        rb_event->tun_ifindex = new_event->tun_ifindex;
        rb_event->tstamp = new_event->tstamp; 
        memcpy(rb_event->daddr, new_event->daddr, sizeof(rb_event->daddr));
        memcpy(rb_event->saddr, new_event->saddr, sizeof(rb_event->saddr));
        rb_event->dport = new_event->dport;
        rb_event->sport = new_event->sport;
        rb_event->tport = new_event->tport;
        rb_event->proto = new_event->proto;
        rb_event->direction = new_event->direction;
        rb_event->tracking_code = new_event->tracking_code;
        rb_event->error_code = new_event->error_code;
        bpf_ringbuf_submit(rb_event, 0);
    }
}

/* function to determine if an incoming packet is a udp/tcp IP tuple
* or not.  If not returns NULL.  If true returns a struct bpf_sock_tuple
* from the combined IP SA|DA and the TCP/UDP SP|DP. 
*/
static struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, struct bpf_event *event,struct diag_ip4 *local_diag){
    struct bpf_sock_tuple *result = NULL;
    __u8 proto = 0;
    
     struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return NULL;
	}
    /* check IP */
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;
    unsigned short eth_proto = eth->h_proto;
    bool ipv4 =false;
    bool ipv6 = false;
    if(eth_proto == bpf_htons(ETH_P_IP)){
        ipv4 = true;
    }
    if(eth_proto == bpf_htons(ETH_P_IPV6)){
        ipv6 = true;
    }
    if (ipv4)
     {
        event->version = 4;
        /* find ip hdr */     
        iph = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
        /* ensure ip header is in packet bounds */
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            event->error_code = IP_HEADER_TOO_BIG;
            send_event(event);
            return NULL;
        }
        /* ip options not allowed */
        if (iph->ihl != 5){
            if(local_diag->verbose){
                event->error_code = NO_IP_OPTIONS_ALLOWED;
                send_event(event);
            }
            return NULL;
        }
        proto = iph->protocol;
    }else if(ipv6){
        event->version = 6;
        ip6h = (struct ipv6hdr *)(skb->data + sizeof(struct ethhdr));
        /* ensure ip header is in packet bounds */
        if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
            event->error_code = IP6_HEADER_TOO_BIG;
            send_event(event);
            return NULL;
        }
        proto = ip6h->nexthdr;
    }else{
        return NULL;
    }
    
    /* check if ip protocol is not UDP or TCP. Return NULL if true */
    if ((proto != IPPROTO_UDP) && (proto != IPPROTO_TCP)) {
        return NULL;
    } 
    /*return bpf_sock_tuple*/
    if(ipv4){
        result = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    }else
    {
        result = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
    }
    return result;
}

static inline void iterate_masks(__u32 *mask, __u32 *exponent){
    if(*mask == 0x00ffffff){
        *exponent=16;
    }
    if(*mask == 0x0000ffff){
        *exponent=8;
    }
    if(*mask == 0x000000ff){
        *exponent=0;
    }
    if((*mask >= 0x80ffffff) && (*exponent >= 24)){
        *mask = *mask - (1 << *exponent);
    }else if((*mask >= 0x0080ffff) && (*exponent >= 16)){
        *mask = *mask - (1 << *exponent);
    }else if((*mask >= 0x000080ff) && (*exponent >= 8)){
        *mask = *mask - (1 << *exponent);
    }else if((*mask >= 0x00000080) && (*exponent >= 0)){
        *mask = *mask - (1 << *exponent);
    }
}

SEC("action")
int bpf_sk_splice(struct __sk_buff *skb){
    struct bpf_sock *sk;
    struct bpf_sock_tuple *tuple, reverse_tuple = {0};
    int tuple_len;
    bool ipv4 = false;
    bool ipv6 = false;
    bool tcp = false;
    struct tuple_key tcp_state_key = {0};
    struct tuple_key udp_state_key ={0};

    unsigned long long tstamp = bpf_ktime_get_ns();
    struct bpf_event event = {
        4,
        tstamp,
        skb->ifindex,
        0,
        {0,0,0,0},
        {0,0,0,0},
        0,
        0,
        0,
        0,
        EGRESS,
        0,
        0,
        {0},
        {0}
     };

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_OK;
    }
    /*get entry from tun ifindex map*/
    struct ifindex_tun *tun_if = get_tun_index(0);

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
	}

     /*check if ARP and pass if true*/
    if((bpf_ntohs(eth->h_proto) == ETH_P_ARP)){
        return TC_ACT_OK;
    }

    /*check if 802.1X and passthrough is enabled*/
    if((bpf_ntohs(eth->h_proto) == 0x888e) && local_diag->eapol){
        return TC_ACT_OK;
    }

    if(eth->h_proto == bpf_ntohs(ETH_P_IP)){
        ipv4 = true;
    }
    
    
    if(eth->h_proto == bpf_ntohs(ETH_P_IPV6)){
        ipv6 = true;
    }

    /* check if incoming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, &event, local_diag);

    //get ipv4 interface addr mappings
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ifindex);

    //get ipv6 interface addr mappings
    struct ifindex_ip6 *local_ip6 = get_local_ip6(skb->ifindex);

    /* if not tuple forward */
    if (!tuple){
        if(ipv4){
            struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
            if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            event.proto = iph->protocol;
            if(event.proto == IPPROTO_ICMP)
            {       
                struct icmphdr *icmph = (struct icmphdr *)((unsigned long)iph + sizeof(*iph));
                if ((unsigned long)(icmph + 1) > (unsigned long)skb->data_end){
                    event.error_code = ICMP_HEADER_TOO_BIG;
                    send_event(&event);
                    return TC_ACT_SHOT;
                }
                if((skb->ifindex != 1) && (icmph->type == 8) && (icmph->code == 0)){
                    struct icmp_key ik = {0};
                    ik.__in46_u_src.ip = iph->saddr;
                    ik.__in46_u_dst.ip = iph->daddr;
                    __u16 *id = (__u16 *)((unsigned long)icmph + 4);
                    __u16 *seq = (__u16 *)((unsigned long)icmph + 6);
                    ik.id = *id;
                    ik.seq = *seq;
                    ik.ifindex = skb->ifindex;
                    if(local_diag->masquerade && local_ip4 && local_ip4->count){
                        __u32 l3_sum = bpf_csum_diff((__u32 *)&iph->saddr, sizeof(iph->saddr), (__u32 *)&local_ip4->ipaddr[0], sizeof(local_ip4->ipaddr[0]), 0);
                        struct masq_value mv = {0};
                        mv.__in46_u_origin.ip =  iph->saddr;
                        struct icmp_masq_key mk = {0};
                        mk.__in46_u_dest.ip =  iph->daddr;
                        __u16 *id = (__u16 *)((unsigned long)icmph + 4);
                        __u16 *seq = (__u16 *)((unsigned long)icmph + 6);
                        mk.id = *id;
                        mk.seq = *seq;
                        mk.ifindex = skb->ifindex;
                        insert_icmp_masquerade(mv, mk);
                        iph->saddr = local_ip4->ipaddr[0];
                        /*Calculate l3 Checksum*/
                        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, l3_sum, 0);
                        iph = (struct iphdr *)(skb->data + sizeof(*eth));
                        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        icmph = (struct icmphdr *)((unsigned long)iph + sizeof(*iph));
                        if ((unsigned long)(icmph + 1) > (unsigned long)skb->data_end){
                            event.error_code = ICMP_HEADER_TOO_BIG;
                            send_event(&event);
                            return TC_ACT_SHOT;
                        }
                    }
                    struct icmp_state is = {
                        tstamp
                    };
                    insert_icmp(is, ik);
                    if(local_diag->verbose){
                        __u32 saddr_array[4] = {iph->saddr,0,0,0};
                        __u32 daddr_array[4] = {iph->daddr,0,0,0};
                        memcpy(event.saddr, saddr_array, sizeof(saddr_array));
                        memcpy(event.daddr, daddr_array, sizeof(daddr_array));
                        event.tracking_code = CLIENT_INITIATED_ICMP_ECHO;
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }

                if((skb->ifindex != 1) && (icmph->type == 0) && (icmph->code == 0)){
                    if(local_diag->echo){
                        return TC_ACT_OK;
                    }else{
                        return TC_ACT_SHOT;
                    }
                }
                return TC_ACT_OK;   
            }
            if(local_diag->vrrp && (event.proto == 112)){
                return TC_ACT_OK;
            }
        }
        if(ipv6){
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
            if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            event.proto = ip6h->nexthdr;
            if(event.proto == IPPROTO_ICMPV6){
                struct icmp6hdr *icmp6h = (struct icmp6hdr *)((unsigned long)ip6h + sizeof(*ip6h));
                if ((unsigned long)(icmp6h + 1) > (unsigned long)skb->data_end){
                    event.error_code = ICMP_HEADER_TOO_BIG;
                    send_event(&event);
                    return TC_ACT_SHOT;
                }
                if((skb->ifindex != 1) && (icmp6h->icmp6_type == 128) && (icmp6h->icmp6_code == 0)){
                    struct icmp_key ik = {0};
                    memcpy(ik.__in46_u_src.ip6, ip6h->saddr.in6_u.u6_addr32, sizeof(ip6h->saddr.in6_u.u6_addr32));
                    memcpy(ik.__in46_u_dst.ip6, ip6h->daddr.in6_u.u6_addr32, sizeof(ip6h->daddr.in6_u.u6_addr32));
                    __u16 *id = (__u16 *)((unsigned long)icmp6h + 4);
                    __u16 *seq = (__u16 *)((unsigned long)icmp6h + 6);
                    ik.id = *id;
                    ik.seq = *seq;
                    ik.ifindex = skb->ifindex;
                    if(local_diag->masquerade && local_ip6 && local_ip6->count){
                        struct masq_value mv = {0};
                        memcpy(mv.__in46_u_origin.ip6, ip6h->saddr.in6_u.u6_addr32, sizeof(mv.__in46_u_origin.ip6));
                        struct icmp_masq_key mk = {0};
                        memcpy(mk.__in46_u_dest.ip6, ip6h->daddr.in6_u.u6_addr32,  sizeof(ip6h->daddr.in6_u.u6_addr32));
                        __u16 *id = (__u16 *)((unsigned long)icmp6h + 4);
                        __u16 *seq = (__u16 *)((unsigned long)icmp6h + 6);
                        mk.id = *id;
                        mk.seq = *seq;
                        mk.ifindex = skb->ifindex;
                        insert_icmp_masquerade(mv, mk );
                        memcpy(ip6h->saddr.in6_u.u6_addr32, local_ip6->ipaddr[0],  sizeof(local_ip6->ipaddr[0]));
                        /*Calculate l4 Checksum*/
                        for(int x = 0; x < 4; x++){
                            bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum), mv.__in46_u_origin.ip6[x], ip6h->saddr.in6_u.u6_addr32[x], BPF_F_PSEUDO_HDR | 4);
                            ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
                            if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
                                return TC_ACT_SHOT;
                            }
                            icmp6h = (struct icmp6hdr *)((unsigned long)ip6h + sizeof(*ip6h));
                            if ((unsigned long)(icmp6h + 1) > (unsigned long)skb->data_end){
                                event.error_code = ICMP_HEADER_TOO_BIG;
                                send_event(&event);
                                return TC_ACT_SHOT;
                            }
                        }
                    }
                    struct icmp_state is = {
                        tstamp
                    };
                    insert_icmp(is, ik);
                    if(local_diag->verbose){
                        memcpy(event.saddr, ip6h->saddr.in6_u.u6_addr32, sizeof(ip6h->saddr.in6_u.u6_addr32));
                        memcpy(event.daddr, ip6h->daddr.in6_u.u6_addr32, sizeof(ip6h->daddr.in6_u.u6_addr32));
                        event.tracking_code = CLIENT_INITIATED_ICMP_ECHO;
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }
                if(skb->ifindex != 1){
                    if((icmp6h->icmp6_type == 129) && (icmp6h->icmp6_code == 0)){ //echo-reply
                        if(local_diag->ipv6_enable && local_diag->echo){
                            return TC_ACT_OK;
                        }
                        else{
                            return TC_ACT_SHOT;
                        }
                    }
                }
                return TC_ACT_OK;
            }
            if(local_diag->vrrp && (event.proto == 112)){
                return TC_ACT_OK;
            }
        }
        return TC_ACT_SHOT;
    }

    /*Allow IPv6 DHCP*/
    if(ipv6){
        tuple_len = sizeof(tuple->ipv6);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            if(local_diag->verbose){
                event.error_code = IPV6_TUPLE_TOO_BIG;
                send_event(&event);
            }
            return TC_ACT_SHOT;
        }
        if((bpf_ntohs(tuple->ipv6.sport) == 546) && (bpf_ntohs(tuple->ipv6.dport) == 547)){
            return TC_ACT_OK;
        }
    }

    if(ipv4)
    {
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        __u8 protocol = iph->protocol;
        if(protocol == IPPROTO_TCP){
            tcp = true;
        }
        tuple_len = sizeof(tuple->ipv4);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            if(local_diag->verbose){
                    event.error_code = IP_TUPLE_TOO_BIG;
                    send_event(&event);
            }
            return TC_ACT_SHOT;
        }
        __u32 saddr_array[4] = {tuple->ipv4.saddr,0,0,0};
        __u32 daddr_array[4] = {tuple->ipv4.daddr,0,0,0};
        memcpy(event.saddr,saddr_array, sizeof(saddr_array));
        memcpy(event.daddr,daddr_array, sizeof(daddr_array));
        event.sport = tuple->ipv4.sport;
        event.dport = tuple->ipv4.dport;
        /*if packet egressing on loopback interface and its source is the ziti0 ip address 
        *redirect the packet to the ziti0 interface. Added to provide support for L2tpV3 over
        *over openziti with ziti-edge-tunnel
        */
        if((skb->ifindex == 1) && tun_if && tun_if->resolver){
            uint32_t tun_ip =  bpf_ntohl(tun_if->resolver) - 1;
            if(tuple->ipv4.saddr == bpf_htonl(tun_ip)){
                return bpf_redirect(tun_if->index, 0);
            }
        }
        if(skb->ifindex == 1){
            return TC_ACT_OK;
        }

        if(!local_diag->outbound_filter){
            return TC_ACT_PIPE;
        }

        /* allow return traffic from ssh to local interface ip addresses 
        *if inbound ssh is enabled
        */
        if(!local_diag->ssh_disable){
            if(tcp && (bpf_ntohs(tuple->ipv4.sport) == 22)){
                if((!local_ip4 || !local_ip4->count)){
                    return TC_ACT_OK;
                }else{
                    uint8_t addresses = 0; 
                    if(local_ip4->count < MAX_ADDRESSES){
                        addresses = local_ip4->count;
                    }else{
                        addresses = MAX_ADDRESSES;
                    }
                    for(int x = 0; x < addresses; x++){
                        if(tuple->ipv4.saddr == local_ip4->ipaddr[x]){
                            if(local_diag->verbose && ((event.tstamp % 2) == 0)){
                                event.proto = IPPROTO_TCP;
                                send_event(&event);
                            }
                            return TC_ACT_OK;
                        }
                    }
                }
            }
        }

        if(tcp)
        {
            event.proto =  IPPROTO_TCP;
            struct tcphdr *tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            reverse_tuple.ipv4.daddr = tuple->ipv4.saddr;
            reverse_tuple.ipv4.dport = tuple->ipv4.sport;
            reverse_tuple.ipv4.saddr = tuple->ipv4.daddr;
            reverse_tuple.ipv4.sport = tuple->ipv4.dport;
            sk = bpf_skc_lookup_tcp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv4),BPF_F_CURRENT_NETNS, 0);
            if(sk && sk->dst_ip4){
                if ((sk->state != BPF_TCP_LISTEN) && (sk->state != BPF_TCP_SYN_SENT)){
                    bpf_sk_release(sk);
                    if(local_diag->verbose){
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }
                bpf_sk_release(sk);
            }else{
                if(sk){
                    bpf_sk_release(sk);
                }
                tcp_state_key.__in46_u_dst.ip = tuple->ipv4.saddr;
                tcp_state_key.__in46_u_src.ip = tuple->ipv4.daddr;
                tcp_state_key.sport = tuple->ipv4.dport;
                tcp_state_key.dport = tuple->ipv4.sport;
                unsigned long long tstamp = bpf_ktime_get_ns();
                struct tcp_state *tstate = get_ingress_tcp(tcp_state_key);
                /*check tcp state and timeout if greater than 60 minutes without traffic*/
                if(tstate && (tstamp < (tstate->tstamp + 3600000000000))){    
                    if(tcph->syn  && tcph->ack){
                        tstate->ack =1;
                        tstate->tstamp = tstamp;
                        if(local_diag->verbose){
                            event.tracking_code = INGRESS_SERVER_SYN_ACK_RCVD;
                            send_event(&event);
                        }
                        return TC_ACT_OK;
                    }
                    else if(tcph->fin){
                        if(tstate->est){
                            tstate->tstamp = tstamp;
                            tstate->sfin = 1;
                            tstate->sfseq = tcph->seq;
                            if(local_diag->verbose){
                                event.tracking_code = INGRESS_SERVER_FIN_RCVD;
                                send_event(&event);
                            }
                            return TC_ACT_OK;
                        }
                    }
                    else if(tcph->rst){
                        del_tcp(tcp_state_key);
                        tstate = get_ingress_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                event.tracking_code = INGRESS_SERVER_RST_RCVD;
                                send_event(&event);
                            }
                        }
                        return TC_ACT_OK;
                    }
                    else if(tcph->ack){
                        if((tstate->est) && (tstate->sfin == 1) && (tstate->cfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->cfseq) + 1))){
                            del_ingress_tcp(tcp_state_key);
                            tstate = get_ingress_tcp(tcp_state_key);
                            if(!tstate){
                                if(local_diag->verbose){
                                    event.tracking_code = INGRESS_SERVER_FINAL_ACK_RCVD;
                                    send_event(&event);
                                }
                            }

                        }
                        else if((tstate->est) && (tstate->cfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->cfseq) + 1))){
                            tstate->sfack = 1;
                            tstate->tstamp = tstamp;
                            return TC_ACT_OK;
                        }
                        else if(tstate->est){
                            tstate->tstamp = tstamp;
                            return TC_ACT_OK;
                        }
                    }
                    return TC_ACT_OK;
                }
                else if(tstate){
                    del_ingress_tcp(tcp_state_key);
                }
            }
        }
        else
        {
            event.proto = IPPROTO_UDP;
            udp_state_key.__in46_u_dst.ip = tuple->ipv4.saddr;
            udp_state_key.__in46_u_src.ip = tuple->ipv4.daddr;
            udp_state_key.sport = tuple->ipv4.dport;
            udp_state_key.dport = tuple->ipv4.sport;
            unsigned long long tstamp = bpf_ktime_get_ns();
            struct udp_state *ustate = get_udp_ingress(udp_state_key);
            if(ustate)
            {
                /*if udp outbound state has been up for 30 seconds without traffic remove it from hashmap*/
                if(tstamp > (ustate->tstamp + 30000000000)){
                    del_udp_ingress(udp_state_key);
                    ustate = get_udp_ingress(udp_state_key);
                    if(!ustate){
                        if(local_diag->verbose){
                            event.tracking_code = INGRESS_UDP_MATCHED_EXPIRED_STATE;
                            send_event(&event);
                        }
                    }
                }
                else{
                    if(local_diag->verbose){
                        event.tracking_code = INGRESS_UDP_MATCHED_ACTIVE_STATE;
                        send_event(&event);
                    }
                    ustate->tstamp = tstamp;
                    return TC_ACT_OK;
                }
            }
            /* forward DHCP messages to local system */
            if((bpf_ntohs(tuple->ipv4.sport) == 68) && (bpf_ntohs(tuple->ipv4.dport) == 67)){
                return TC_ACT_OK;
            }
            
        }
        struct match_key mkey = {tuple->ipv4.saddr, tuple->ipv4.daddr, tuple->ipv4.sport, tuple->ipv4.dport, skb->ifindex, event.proto};
        clear_match_tracker(mkey);
        return TC_ACT_PIPE;
    }else if(ipv6 && (local_diag->ipv6_enable || skb->ifindex == 1)){
        if(skb->ifindex == 1){
            return TC_ACT_OK;
        }
        if(!local_diag->outbound_filter){
            return TC_ACT_PIPE;
        }
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        __u8 protocol = ip6h->nexthdr;
        if(protocol == IPPROTO_TCP){
            tcp = true;
        }
        tuple_len = sizeof(tuple->ipv6);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            if(local_diag->verbose){
                event.error_code = IPV6_TUPLE_TOO_BIG;
                send_event(&event);
            }
            return TC_ACT_SHOT;
        }
        memcpy(event.saddr,tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
        memcpy(event.daddr,tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
        event.sport = tuple->ipv6.sport;
        event.dport = tuple->ipv6.dport;
        /* allow ssh to local interface ip addresses */
        if(!local_diag->ssh_disable){
            if(tcp && (bpf_ntohs(tuple->ipv6.sport) == 22)){
                if((!local_ip6 || !local_ip6->count)){
                    return TC_ACT_OK;
                }else{ 
                    uint8_t addresses = 0; 
                    if(local_ip6->count < MAX_ADDRESSES){
                        addresses = local_ip6->count;
                    }else{
                        addresses = MAX_ADDRESSES;
                    }
                    
                    for(int x = 0; x < addresses; x++){
                        if((local_ip6->ipaddr[x][0] == tuple->ipv6.saddr[0]) && (local_ip6->ipaddr[x][1] == tuple->ipv6.saddr[1]) && 
                        (local_ip6->ipaddr[x][2] == tuple->ipv6.saddr[2]) && (local_ip6->ipaddr[x][3] == tuple->ipv6.saddr[3])){
                            if(local_diag->verbose && ((event.tstamp % 2) == 0)){
                                event.proto = IPPROTO_TCP;
                                send_event(&event);
                            }
                            return TC_ACT_OK;
                        }
                    }
                }
            }
        }
        if(tcp){
            event.proto = IPPROTO_TCP;
            struct tcphdr *tcph = (struct tcphdr *)((unsigned long)ip6h + sizeof(*ip6h));
            if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            memcpy(reverse_tuple.ipv6.daddr, tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
            reverse_tuple.ipv6.dport = tuple->ipv6.sport;
            memcpy(reverse_tuple.ipv6.saddr, tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
            reverse_tuple.ipv6.sport = tuple->ipv6.dport;
            sk = bpf_skc_lookup_tcp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv6),BPF_F_CURRENT_NETNS, 0);
            if(sk && sk->dst_ip6[0]){
                if ((sk->state != BPF_TCP_LISTEN) && (sk->state != BPF_TCP_SYN_SENT)){
                    bpf_sk_release(sk);
                    if(local_diag->verbose){
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }
                bpf_sk_release(sk);
            }else{
                if(sk){
                    bpf_sk_release(sk);
                }
                memcpy(tcp_state_key.__in46_u_dst.ip6,tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
                memcpy(tcp_state_key.__in46_u_src.ip6,tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
                tcp_state_key.sport = tuple->ipv6.dport;
                tcp_state_key.dport = tuple->ipv6.sport;
                unsigned long long tstamp = bpf_ktime_get_ns();
                struct tcp_state *tstate = get_ingress_tcp(tcp_state_key);
                /*check tcp state and timeout if greater than 60 minutes without traffic*/
                if(tstate && (tstamp < (tstate->tstamp + 3600000000000)))
                {    
                    if(tcph->syn  && tcph->ack){
                        tstate->ack =1;
                        tstate->tstamp = tstamp;
                        if(local_diag->verbose){
                            event.tracking_code = INGRESS_SERVER_SYN_ACK_RCVD;
                            send_event(&event);
                        }
                        return TC_ACT_OK;
                    }
                    else if(tcph->fin){
                        if(tstate->est){
                            tstate->tstamp = tstamp;
                            tstate->sfin = 1;
                            tstate->sfseq = tcph->seq;
                            if(local_diag->verbose){
                                event.tracking_code = INGRESS_SERVER_FIN_RCVD;
                                send_event(&event);
                            }
                            return TC_ACT_OK;
                        }
                    }
                    else if(tcph->rst){
                        del_ingress_tcp(tcp_state_key);
                        tstate = get_ingress_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                event.tracking_code = INGRESS_SERVER_RST_RCVD;
                                send_event(&event);
                            }
                        }
                        return TC_ACT_OK;
                    }
                    else if(tcph->ack){
                        if((tstate->est) && (tstate->sfin == 1) && (tstate->cfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->cfseq) + 1))){
                            del_ingress_tcp(tcp_state_key);
                            tstate = get_ingress_tcp(tcp_state_key);
                            if(!tstate){
                                if(local_diag->verbose){
                                    event.tracking_code = INGRESS_SERVER_FINAL_ACK_RCVD;
                                    send_event(&event);
                                }
                            }

                        }
                        else if((tstate->est) && (tstate->cfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->cfseq) + 1))){
                            tstate->sfack = 1;
                            tstate->tstamp = tstamp;
                            return TC_ACT_OK;
                        }
                        else if(tstate->est){
                            tstate->tstamp = tstamp;
                            return TC_ACT_OK;
                        }
                    }
                    return TC_ACT_OK;
                }
                else if(tstate){
                    del_ingress_tcp(tcp_state_key);
                }
            }
        }else
        {
            event.proto = IPPROTO_UDP;
            memcpy(udp_state_key.__in46_u_dst.ip6,tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
            memcpy(udp_state_key.__in46_u_src.ip6,tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
            udp_state_key.sport = tuple->ipv6.dport;
            udp_state_key.dport = tuple->ipv6.sport;
            unsigned long long tstamp = bpf_ktime_get_ns();
            struct udp_state *ustate = get_udp_ingress(udp_state_key);
            if(ustate){
                /*if udp outbound state has been up for 30 seconds without traffic remove it from hashmap*/
                if(tstamp > (ustate->tstamp + 30000000000)){
                    del_udp_ingress(udp_state_key);
                    ustate = get_udp_ingress(udp_state_key);
                    if(!ustate){
                        if(local_diag->verbose){
                            event.tracking_code = INGRESS_UDP_MATCHED_EXPIRED_STATE;
                            send_event(&event);
                        }
                    }
                }
                else{
                    if(local_diag->verbose){
                        event.tracking_code = INGRESS_UDP_MATCHED_ACTIVE_STATE;
                        send_event(&event);
                    }
                    ustate->tstamp = tstamp;
                    return TC_ACT_OK;
                }
            }
        }
        struct match6_key mkey = {0};
        memcpy(mkey.daddr, tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
        memcpy(mkey.saddr, tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr)); 
        mkey.sport = tuple->ipv6.sport;
        mkey.dport = tuple->ipv6.dport;
        mkey.ifindex = skb->ifindex;
        mkey.protocol = event.proto;
        clear_match6_tracker(mkey);
        return TC_ACT_PIPE;
    }
    return TC_ACT_SHOT;
}

SEC("action/1")
int bpf_sk_splice1(struct __sk_buff *skb){
    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_SHOT;
    }
    if(!local_diag->outbound_filter){
        return TC_ACT_PIPE;
    }
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    __u8 protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    struct tproxy_tuple *tproxy = NULL;
    if(eth->h_proto == bpf_htons(ETH_P_IP)){
        /* check if incoming packet is a UDP or TCP tuple */
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        protocol = iph->protocol;
        tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
        tuple_len = sizeof(tuple->ipv4);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        __u32 dexponent=24;  /* unsigned integer used to calculate prefix matches */
        __u32 dmask = 0xffffffff;  /* starting mask value used in prefix match calculation */
        __u32 sexponent=24;  /* unsigned integer used to calculate prefix matches */
        __u32 smask = 0xffffffff;  /* starting mask value used in prefix match calculation */
        __u8 maxlen = 8; /* max number ip ipv4 prefixes */
        __u8 smaxlen = 32; /* max number ip ipv4 prefixes */
        /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
        struct match_tracker key_tracker = {0,{}};
        struct match_key mkey = {tuple->ipv4.saddr, tuple->ipv4.daddr, tuple->ipv4.sport, tuple->ipv4.dport, skb->ifindex, protocol};
        insert_matched_key(key_tracker, mkey);
        struct match_tracker *tracked_key_data = get_matched_keys(mkey);
        if(!tracked_key_data){
            return TC_ACT_SHOT;
        }
        for (__u16 dcount = 0;dcount <= maxlen; dcount++){
                
                /*
                    * lookup based on tuple-ipv4.daddr logically ANDed with
                    * cidr mask starting with /32 and working down to /1 if no match packet is discarded
                    */
                for (__u16 scount = 0; scount <= smaxlen; scount++){
                    
                    struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 32-dcount, smaxlen-scount, protocol, 0};
                    if ((tproxy = get_egress(key))){
                        if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                            tracked_key_data->matched_keys[tracked_key_data->count] = key;
                            tracked_key_data->count++;
                        }
                        if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                            return TC_ACT_PIPE;
                        }
                    }              
                    if(smask == 0x00000000){
                        break;
                    }
                    iterate_masks(&smask, &sexponent);
                    sexponent++;
                }
                /*algorithm used to calculate mask while traversing
                each octet.
                */
                if(dmask == 0x80ffffff){
                    return TC_ACT_PIPE;
                }
                iterate_masks(&dmask, &dexponent);
                smask = 0xffffffff;
                sexponent = 24;
                dexponent++;
        }
    }else{
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
        /* ensure ip header is in packet bounds */
        if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        protocol = ip6h->nexthdr;
        tuple = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
        tuple_len = sizeof(tuple->ipv6);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        unsigned int saddr[4] = {0,0,0,0};
        __u32 maxlen = 32; /* max number ip ipv6 prefixes in quad */
        __u32 mask0 = 0xffffffff;  /* starting mask value used in prefix match calculation */
        __u32 mask1 = 0xffffffff;  /* starting mask value used in prefix match calculation */
        __u32 mask2 = 0xffffffff;  /* starting mask value used in prefix match calculation */
        __u32 mask3 = 0xffffffff;  /* starting mask value used in prefix match calculation */
        __u32 exponent3 = 24;  /* unsigned integer used to calculate prefix matches */
        struct match6_key mkey = {0};
        memcpy(mkey.daddr, tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
        memcpy(mkey.saddr, tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr)); 
        mkey.sport = tuple->ipv6.sport;
        mkey.dport = tuple->ipv6.dport;
        mkey.ifindex = skb->ifindex;
        mkey.protocol = protocol;
        struct tproxy6_key key = {0};
        key.sprefix_len = 0; 
        key.protocol = protocol;
        key.dprefix_len = 128;
        key.pad = 0;

        for (__u16 dcount3 = 0; dcount3 < maxlen; dcount3++){
            unsigned int daddr[4] = {tuple->ipv6.daddr[0], tuple->ipv6.daddr[1], tuple->ipv6.daddr[2], tuple->ipv6.daddr[3] & mask3};
            memcpy(key.dst_ip ,daddr, sizeof(daddr));
            memcpy(key.src_ip, saddr, sizeof(saddr));
            if ((tproxy = get_egress6(key))){
                insert_matched6_key(key, mkey);
                return TC_ACT_PIPE;
            }
            key.dprefix_len--;
            if(mask3 == 0x00000000){
                break;
            }
            iterate_masks(&mask3, &exponent3);
            exponent3++;
        }
        __u32 exponent2 = 24;  //unsigned integer used to calculate prefix matches
        for (__u16 dcount2 = 0; dcount2 < maxlen; dcount2++){ 
            unsigned int daddr[4] = {tuple->ipv6.daddr[0], tuple->ipv6.daddr[1], tuple->ipv6.daddr[2] & mask2, tuple->ipv6.daddr[3] & mask3};
            memcpy(key.dst_ip ,daddr, sizeof(daddr));
            memcpy(key.src_ip, saddr, sizeof(saddr));
            if ((tproxy = get_egress6(key))){
                insert_matched6_key(key, mkey);
                return TC_ACT_PIPE;
            }
            key.dprefix_len--;
            if(mask2 == 0x00000000){
                break;
            }
            iterate_masks(&mask2, &exponent2);
            exponent2++;
        }
        __u32 exponent1 = 24;  //unsigned integer used to calculate prefix matches
        for (__u16 dcount1 = 0; dcount1 < maxlen; dcount1++){
            unsigned int daddr[4] = {tuple->ipv6.daddr[0], tuple->ipv6.daddr[1] & mask1, tuple->ipv6.daddr[2] & mask2, tuple->ipv6.daddr[3] & mask3};
            memcpy(key.dst_ip ,daddr, sizeof(daddr));
            memcpy(key.src_ip, saddr, sizeof(saddr));
            if ((tproxy = get_egress6(key))){
                insert_matched6_key(key, mkey);
                return TC_ACT_PIPE;
            }
            key.dprefix_len--;
            if(mask1 == 0x00000000){
                break;
            }
            iterate_masks(&mask1, &exponent1);
            exponent1++;
        }
        __u32 exponent0 = 24;  // unsigned integer used to calculate prefix matches
        for (__u16 dcount0 = 0; dcount0 <= maxlen; dcount0++){ 
            unsigned int daddr[4] = {tuple->ipv6.daddr[0] & mask0, tuple->ipv6.daddr[1] & mask1, tuple->ipv6.daddr[2] & mask2, tuple->ipv6.daddr[3] & mask3};
            memcpy(key.dst_ip ,daddr, sizeof(daddr));
            memcpy(key.src_ip, saddr, sizeof(saddr));
            if ((tproxy = get_egress6(key))){
                insert_matched6_key(key, mkey);
                return TC_ACT_PIPE;
            }
            key.dprefix_len--;
            if(mask0 == 0x00000000){
                break;
            }
            iterate_masks(&mask0, &exponent0);
            exponent0++;
        }
    }
    if(skb->ifindex == 1){
        return TC_ACT_OK;
    }
    return TC_ACT_SHOT;
}

SEC("action/2")
int bpf_sk_splice2(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    __u8 protocol;

    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_SHOT;
    }
    if(!local_diag->outbound_filter){
        return TC_ACT_PIPE;
    }
    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
        return TC_ACT_PIPE;
    }
    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=16;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xffffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u8 maxlen = 8; /* max number ip ipv4 prefixes */
    __u8 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_key mkey = {tuple->ipv4.saddr, tuple->ipv4.daddr, tuple->ipv4.sport, tuple->ipv4.dport, skb->ifindex, protocol};
    struct match_tracker *tracked_key_data = get_matched_keys(mkey);
    if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 24-dcount, smaxlen-scount, protocol, 0};
               
                if ((tproxy = get_egress(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                        return TC_ACT_PIPE;
                    }
                }              
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x80ffff){
                return TC_ACT_PIPE;
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

SEC("action/3")
int bpf_sk_splice3(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    __u8 protocol;

    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_SHOT;
    }
    if(!local_diag->outbound_filter){
        return TC_ACT_PIPE;
    }
    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
        return TC_ACT_PIPE;
    }
    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=8;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xffff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u8 maxlen = 8; /* max number ip ipv4 prefixes */
    __u8 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_key mkey = {tuple->ipv4.saddr, tuple->ipv4.daddr, tuple->ipv4.sport, tuple->ipv4.dport, skb->ifindex, protocol};
    struct match_tracker *tracked_key_data = get_matched_keys(mkey);
    if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 16-dcount, smaxlen-scount, protocol, 0};
                if ((tproxy = get_egress(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                        return TC_ACT_PIPE;
                    }
                }               
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x80ff){
                return TC_ACT_PIPE;
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

SEC("action/4")
int bpf_sk_splice4(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    __u8 protocol;

    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_SHOT;
    }
    if(!local_diag->outbound_filter){
        return TC_ACT_PIPE;
    }
    /* find ethernet header from skb->data pointer */
   struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    if(eth->h_proto == bpf_htons(ETH_P_IPV6)){
        return TC_ACT_PIPE;
    }
    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=0;  /* unsigned integer used to calulate prefix matches */
    __u32 dmask = 0xff;  /* starting mask value used in prfix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calulate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prfix match calculation */
    __u8 maxlen = 8; /* max number ip ipv4 prefixes */
    __u8 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_key mkey = {tuple->ipv4.saddr, tuple->ipv4.daddr, tuple->ipv4.sport, tuple->ipv4.dport, skb->ifindex, protocol};
    struct match_tracker *tracked_key_data = get_matched_keys(mkey);
    if(!tracked_key_data){
       return TC_ACT_SHOT;
    }
    for (__u16 dcount = 0;dcount <= maxlen; dcount++){
            
            /*
             * lookup based on tuple-ipv4.daddr logically ANDed with
             * cidr mask starting with /32 and working down to /1 if no match packet is discarded
             */
            for (__u16 scount = 0; scount <= smaxlen; scount++){
                
                struct tproxy_key key = {(tuple->ipv4.daddr & dmask),(tuple->ipv4.saddr & smask), 8-dcount, smaxlen-scount, protocol, 0};
                if ((tproxy = get_egress(key))){
                    if(tracked_key_data->count < MATCHED_KEY_DEPTH){
                        tracked_key_data->matched_keys[tracked_key_data->count] = key;
                        tracked_key_data->count++;
                    }
                    if(tracked_key_data->count == MATCHED_KEY_DEPTH){
                        return TC_ACT_PIPE;
                    }
                }              
                if(smask == 0x00000000){
                    break;
                }
                iterate_masks(&smask, &sexponent);
                sexponent++;
            }
            /*algorithm used to calculate mask while traversing
            each octet.
            */
            if(dmask == 0x00000000){
                if((tracked_key_data->count > 0)){
                    return TC_ACT_PIPE;
                }else if(skb->ifindex == 1){
                    return TC_ACT_OK;
                }
            }
            iterate_masks(&dmask, &dexponent);
            smask = 0xffffffff;
            sexponent = 24;
            dexponent++;
    }
    return TC_ACT_SHOT;
}

SEC("action/5")
int bpf_sk_splice5(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple,sockcheck = {0};
    int tuple_len;

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_SHOT;
    }
    if(!local_diag->outbound_filter){
        return TC_ACT_PIPE;
    }

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
    }

    unsigned long long tstamp = bpf_ktime_get_ns();
    struct bpf_event event = {
        0,
        tstamp,
        skb->ifindex,
        0,
        {0},
        {0},
        0,
        0,
        0,
        0,
        EGRESS,
        0,
        0,
        {},
        {}
     };

    struct tproxy_tuple *tproxy = NULL;
    if(eth->h_proto == bpf_htons(ETH_P_IP)){
        struct tproxy_key key;
        /* check if incomming packet is a UDP or TCP tuple */
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        __u8 protocol = iph->protocol;
        tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
        if(!tuple){
            return TC_ACT_SHOT;
        }
        /* determine length of tuple */
        tuple_len = sizeof(tuple->ipv4);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        event.version = iph->version;
        uint32_t daddr[4] = {tuple->ipv4.daddr,0,0,0};
        uint32_t saddr[4] = {tuple->ipv4.saddr,0,0,0};
        memcpy(event.daddr, daddr, sizeof(event.daddr));
        memcpy(event.saddr, saddr, sizeof(event.saddr));  
        event.dport = tuple->ipv4.dport;
        event.sport = tuple->ipv4.sport;
        struct match_tracker *key_tracker;
        struct match_key mkey = {tuple->ipv4.saddr, tuple->ipv4.daddr, tuple->ipv4.sport, tuple->ipv4.dport, skb->ifindex, protocol};
        __u16 match_count = get_matched_count(mkey);
        if (match_count > MATCHED_KEY_DEPTH){
            match_count = MATCHED_KEY_DEPTH;
        }
        for(__u16 count =0; count < match_count; count++)
        {
            key_tracker = get_matched_keys(mkey);
            if(key_tracker){
            key = key_tracker->matched_keys[count];
            }else{
                break;
            }
        
            if((tproxy = get_egress(key)) && tuple)
            {
                __u16 max_entries = tproxy->index_len;
                if (max_entries > MAX_INDEX_ENTRIES) {
                    max_entries = MAX_INDEX_ENTRIES;
                }
                for (int index = 0; index < max_entries; index++){
                    __u16 port_key = tproxy->index_table[index];
                    struct port_extension_key ext_key = {0};
                    ext_key.__in46_u_dst.ip = key.dst_ip;
                    ext_key.__in46_u_src.ip = key.src_ip;
                    ext_key.low_port = port_key;
                    ext_key.dprefix_len = key.dprefix_len;
                    ext_key.sprefix_len = key.sprefix_len; 
                    ext_key.protocol = key.protocol;
                    ext_key.pad = 0;
                    struct range_mapping *range = get_range_ports(ext_key);
                    //check if there is a udp or tcp destination port match
                    if (range && ((bpf_ntohs(tuple->ipv4.dport) >= bpf_ntohs(port_key))
                        && (bpf_ntohs(tuple->ipv4.dport) <= bpf_ntohs(range->high_port)))) 
                    {
                        event.proto = key.protocol;
                        event.tport = range->tproxy_port;
                        if(range->deny){
                            if(local_diag->verbose){
                                event.tracking_code = MATCHED_DROP_FILTER;
                                send_event(&event);
                            }
                            return TC_ACT_SHOT;
                        }
                        /*check if interface is set for per interface rule awarness and if yes check if it is in the rules interface list.  If not in
                        the interface list drop it on all interfaces accept loopback.  If its not aware then forward based on mapping*/
                        sockcheck.ipv4.daddr = 0x0100007f;
                        sockcheck.ipv4.dport = range->tproxy_port;
                        if(!local_diag->per_interface){
                            if(range->tproxy_port == 0){
                                if(local_diag->verbose){
                                    send_event(&event);
                                }
                                return TC_ACT_PIPE;
                            }
                        }
                        struct if_list_extension_mapping *ext_mapping = get_if_list_ext_mapping(ext_key);
                        if(ext_mapping){
                            for(int x = 0; x < MAX_IF_LIST_ENTRIES; x++){
                                if(ext_mapping->if_list[x] == skb->ifindex){
                                    if(range->tproxy_port == 0)
                                    {
                                        if(local_diag->verbose){
                                            send_event(&event);
                                        }
                                        return TC_ACT_PIPE;
                                    }
                                    
                                }
                            }
                        }
                        event.error_code = IF_LIST_MATCH_ERROR;
                        send_event(&event);
                        return TC_ACT_SHOT;
                        
                    }
                }
            }
        }
    }else
    {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
        // ensure ip header is in packet bounds
        if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        tuple = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
        if(!tuple){
            return TC_ACT_SHOT;
        }
        // determine length of tuple
        tuple_len = sizeof(tuple->ipv6);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        memcpy(event.daddr, tuple->ipv6.daddr, sizeof(event.daddr));
        memcpy(event.saddr, tuple->ipv6.saddr, sizeof(event.saddr));  
        event.dport = tuple->ipv6.dport;
        event.sport = tuple->ipv6.sport;
        event.version = ip6h->version;
        __u8 protocol = ip6h->nexthdr;
        tuple = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
        tuple_len = sizeof(tuple->ipv6);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        struct match6_key mkey = {0};
        memcpy(mkey.daddr, tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
        memcpy(mkey.saddr, tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr)); 
        mkey.sport = tuple->ipv6.sport;
        mkey.dport = tuple->ipv6.dport;
        mkey.ifindex = skb->ifindex;
        mkey.protocol = protocol;
        struct tproxy6_key *key = get_matched6_key(mkey);
        if(key)
        {
            if((tproxy = get_egress6(*key)) && tuple)
            {
                __u16 max_entries = tproxy->index_len;
                if (max_entries > MAX_INDEX_ENTRIES) {
                    max_entries = MAX_INDEX_ENTRIES;
                }
                struct port_extension_key ext_key = {0};
                memcpy(ext_key.__in46_u_dst.ip6, key->dst_ip, sizeof(key->dst_ip));
                memcpy(ext_key.__in46_u_src.ip6, key->src_ip, sizeof(key->src_ip));
                ext_key.dprefix_len = key->dprefix_len;
                ext_key.sprefix_len = key->sprefix_len; 
                ext_key.protocol = key->protocol;
                ext_key.pad = 0;
                for (int index = 0; index < max_entries; index++){
                    __u16 port_key = tproxy->index_table[index];
                    ext_key.low_port = port_key;
                    struct range_mapping *range = get_range_ports(ext_key);
                    //check if there is a udp or tcp destination port match
                    if (range && ((bpf_ntohs(tuple->ipv6.dport) >= bpf_ntohs(port_key))
                        && (bpf_ntohs(tuple->ipv6.dport) <= bpf_ntohs(range->high_port)))) 
                    {
                        event.proto = key->protocol;
                        event.tport = range->tproxy_port;
                        if(range->deny){
                            if(local_diag->verbose){
                                event.tracking_code = MATCHED_DROP_FILTER;
                                send_event(&event);
                            }
                            return TC_ACT_SHOT;
                        }
                        /*check if interface is set for per interface rule awarness and if yes check if it is in the rules interface list.  If not in
                        the interface list drop it on all interfaces accept loopback.  If its not aware then forward based on mapping*/
                        sockcheck.ipv6.daddr[0]= 0;
                        sockcheck.ipv6.daddr[1]= 0;
                        sockcheck.ipv6.daddr[2]= 0;
                        sockcheck.ipv6.daddr[3]= 0x1000000;
                        sockcheck.ipv6.dport = range->tproxy_port;
                        if(!local_diag->per_interface){
                            if(range->tproxy_port == 0){
                                if(local_diag->verbose){
                                    send_event(&event);
                                }
                                return TC_ACT_PIPE;
                            }
                        }
                        struct if_list_extension_mapping *ext_mapping = get_if_list_ext_mapping(ext_key);
                        if(ext_mapping)
                        {
                            for(int x = 0; x < MAX_IF_LIST_ENTRIES; x++){
                                if(ext_mapping->if_list[x] == skb->ifindex){
                                    if(range->tproxy_port == 0){
                                        if(local_diag->verbose){
                                            send_event(&event);
                                        } 
                                        return TC_ACT_PIPE;
                                    }
                                }
                            }
                        }
                        event.error_code = IF_LIST_MATCH_ERROR;
                        send_event(&event);
                        return TC_ACT_SHOT;
                    }
                }
            }
        }
    }
    return TC_ACT_SHOT;
}

//ebpf tc code entry program
SEC("action/6")
int bpf_sk_splice6(struct __sk_buff *skb){
    struct bpf_sock *sk;
    struct bpf_sock_tuple *tuple, reverse_tuple = {0};
    int tuple_len;
    bool tcp = false;
    bool ipv4 = false;
    bool ipv6 = false;
    struct tuple_key tcp_state_key = {0};
    struct tuple_key udp_state_key ={0};

    unsigned long long tstamp = bpf_ktime_get_ns();
    struct bpf_event event = {
        4,
        tstamp,
        skb->ifindex,
        0,
        {0,0,0,0},
        {0,0,0,0},
        0,
        0,
        0,
        0,
        EGRESS,
        0,
        0,
        {0},
        {0}
     };

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ifindex);
    if(!local_diag){
        return TC_ACT_OK;
    }

    //get ipv4 interface addr mappings
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ifindex);

    //get ipv6 interface addr mappings
    struct ifindex_ip6 *local_ip6 = get_local_ip6(skb->ifindex);

    /*get entry from tun ifindex map*/
    struct ifindex_tun *tun_if = get_tun_index(0);

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
	}

    if(eth->h_proto == bpf_ntohs(ETH_P_IP)){
        ipv4 = true;
    }

    if(eth->h_proto == bpf_ntohs(ETH_P_IPV6)){
        ipv6 = true;
    }

    /* check if incoming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, &event, local_diag);

    /* if not tuple forward */
    if (!tuple){
        return TC_ACT_OK;
    }
    if(ipv4){
        /* determine length of tuple */
        /* check if incomming packet is a UDP or TCP tuple */
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        __u8 protocol = iph->protocol;
        tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
        if(!tuple){
            return TC_ACT_SHOT;
        }
        /* determine length of tuple */
        tuple_len = sizeof(tuple->ipv4);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        if(protocol == IPPROTO_TCP){
            tcp = true;
        }
        __u32 saddr_array[4] = {tuple->ipv4.saddr,0,0,0};
        __u32 daddr_array[4] = {tuple->ipv4.daddr,0,0,0};
        memcpy(event.saddr,saddr_array, sizeof(saddr_array));
        memcpy(event.daddr,daddr_array, sizeof(daddr_array));
        event.sport = tuple->ipv4.sport;
        event.dport = tuple->ipv4.dport;
        /*if packet egressing on loopback interface and its source is the ziti0 ip address 
        *redirect the packet to the ziti0 interface. Added to provide support for L2tpV3 over
        *over openziti with ziti-edge-tunnel
        */
        if((skb->ifindex == 1) && tun_if && tun_if->resolver){
            uint32_t tun_ip =  bpf_ntohl(tun_if->resolver) - 1;
            if(tuple->ipv4.saddr == bpf_htonl(tun_ip)){
                return bpf_redirect(tun_if->index, 0);
            }
        }
        /* if tcp based tuple implement stateful inspection to see if they were
        * initiated by the local OS if not then its passthrough traffic and so wee need to
        * setup our own state to track the outbound pass through connections in via shared hashmap
        *  with with ingress tc program
        */
        if(tcp){
            event.proto = IPPROTO_TCP;
            struct tcphdr *tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            reverse_tuple.ipv4.daddr = tuple->ipv4.saddr;
            reverse_tuple.ipv4.dport = tuple->ipv4.sport;
            reverse_tuple.ipv4.saddr = tuple->ipv4.daddr;
            reverse_tuple.ipv4.sport = tuple->ipv4.dport;
            sk = bpf_skc_lookup_tcp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv4),BPF_F_CURRENT_NETNS, 0);
            if(sk){
                if (sk->state != BPF_TCP_LISTEN){
                    bpf_sk_release(sk);
                    if(local_diag->verbose){
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }
                bpf_sk_release(sk);
            }
            tcp_state_key.__in46_u_src.ip = tuple->ipv4.saddr;
            tcp_state_key.__in46_u_dst.ip = tuple->ipv4.daddr;
            tcp_state_key.sport = tuple->ipv4.sport;
            tcp_state_key.dport = tuple->ipv4.dport;
            if(local_diag->masquerade && local_ip4 && local_ip4->count){
                struct masq_reverse_key revk = {0};
                revk.__in46_u_src.ip =  tuple->ipv4.saddr;
                revk.__in46_u_dest.ip = tuple->ipv4.daddr;
                revk.dport = tuple->ipv4.dport;
                revk.sport = tuple->ipv4.sport;
                revk.protocol = IPPROTO_TCP;
                revk.ifindex = skb->ifindex;
                __u16 rand_source_port = 0;
                struct masq_value *revv = get_reverse_masquerade(revk);
                if(revv){
                    rand_source_port = revv->o_sport;
                }
                else{
                    rand_source_port = bpf_htons(1024 + bpf_get_prandom_u32() % (65535 -1023));
                    struct masq_value rev_new_val = {0};
                    rev_new_val.o_sport =  rand_source_port;
                    rev_new_val.__in46_u_origin.ip = 0;
                    insert_reverse_masquerade(rev_new_val,revk);
                    if(local_diag->verbose){
                        event.tracking_code = REVERSE_MASQUERADE_ENTRY_ADDED;
                        send_event(&event);
                    }
                }
                __u32 l3_sum = bpf_csum_diff((__u32 *)&tuple->ipv4.saddr, sizeof(tuple->ipv4.saddr), (__u32 *)&local_ip4->ipaddr[0], sizeof(local_ip4->ipaddr[0]), 0);
                struct masq_value mv = {0};
                struct masq_key mk = {0};
                mk.__in46_u_dest.ip =  tuple->ipv4.daddr;
                mk.dport = tuple->ipv4.dport;
                mk.sport = rand_source_port;
                mk.ifindex = skb->ifindex;
                mk.protocol = IPPROTO_TCP;
                struct masq_value *mvptr = get_masquerade(mk);
                if(!mvptr){
                    mv.__in46_u_origin.ip =  tuple->ipv4.saddr;
                    mv.o_sport = tuple->ipv4.sport;
                    insert_masquerade(mv, mk);
                    if(local_diag->verbose){
                        event.tracking_code = MASQUERADE_ENTRY_ADDED;
                        send_event(&event);
                    }
                }else{
                    mv = *mvptr;
                }
                iph->saddr = local_ip4->ipaddr[0];
                /*Calculate l3 Checksum*/
                bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, l3_sum, 0);
                iph = (struct iphdr *)(skb->data + sizeof(*eth));
                if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
                if(!tuple){
                    return TC_ACT_SHOT;
                }
                tuple_len = sizeof(tuple->ipv4);
                if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
                if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                /*Calculate l4 Checksum*/
                int flags = BPF_F_PSEUDO_HDR;
                bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), 0, l3_sum, flags);
                iph = (struct iphdr *)(skb->data + sizeof(*eth));
                if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
                if(!tuple){
                    return TC_ACT_SHOT;
                }
                tuple_len = sizeof(tuple->ipv4);
                if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
                if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tcph->source = rand_source_port;
                bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check), mv.o_sport , rand_source_port, flags | 2);
                iph = (struct iphdr *)(skb->data + sizeof(*eth));
                if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
                if(!tuple){
                    return TC_ACT_SHOT;
                }
                tuple_len = sizeof(tuple->ipv4);
                if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }
                tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
                if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                    return TC_ACT_SHOT;
                }               
            }
            unsigned long long tstamp = bpf_ktime_get_ns();
            struct tcp_state *tstate;
            if(tcph->syn && !tcph->ack){
                struct tcp_state ts = {
                tstamp,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            };
                insert_tcp(ts, tcp_state_key);
                if(local_diag->verbose){
                    event.tracking_code = CLIENT_SYN_RCVD;
                    send_event(&event);
                }
            }
            else if(tcph->fin){
                tstate = get_tcp(tcp_state_key);
                if(tstate){
                    tstate->tstamp = tstamp;
                    tstate->cfin = 1;
                    tstate->cfseq = tcph->seq;
                    if(local_diag->verbose){
                        event.tracking_code = CLIENT_FIN_RCVD;
                        send_event(&event);
                    }
                }
            }
            else if(tcph->rst){
                tstate = get_tcp(tcp_state_key);
                if(tstate){
                    if(local_diag->masquerade){
                        struct masq_reverse_key rk = {0};
                        rk.dport = tcp_state_key.dport;
                        rk.sport = tcp_state_key.sport;
                        rk.ifindex = event.ifindex;
                        rk.__in46_u_dest.ip = tcp_state_key.__in46_u_dst.ip;
                        rk.__in46_u_src.ip = tcp_state_key.__in46_u_src.ip;
                        rk.protocol = IPPROTO_TCP;
                        del_reverse_masq(rk);
                        if(local_diag->verbose){
                            event.tracking_code = REVERSE_MASQUERADE_ENTRY_REMOVED;
                            send_event(&event);
                        }
                        struct masq_key mk = {0};
                        mk.dport = tcph->dest;
                        mk.sport = tcph->source;
                        mk.__in46_u_dest.ip = iph->daddr;
                        mk.ifindex = event.ifindex;
                        mk.protocol = IPPROTO_TCP;
                        del_masq(mk);
                        if(local_diag->verbose){
                            event.tracking_code = MASQUERADE_ENTRY_REMOVED;
                            send_event(&event);
                        }
                    }
                    del_tcp(tcp_state_key);
                    tstate = get_tcp(tcp_state_key);
                    if(!tstate){
                        if(local_diag->verbose){
                            event.tracking_code = CLIENT_RST_RCVD;
                            send_event(&event);
                        }
                    }
                }
            }
            else if(tcph->ack){
                tstate = get_tcp(tcp_state_key);
                if(tstate){
                    if(tstate->ack && tstate->syn){
                        if(local_diag->verbose){
                            event.tracking_code = TCP_CONNECTION_ESTABLISHED;
                            send_event(&event);
                        }
                        tstate->tstamp = tstamp;
                        tstate->syn = 0;
                        tstate->est = 1;
                    }
                    if((tstate->est) && (tstate->sfin == 1) && (tstate->cfin == 1) && (tstate->sfack) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->sfseq) + 1))){
                        if(local_diag->masquerade){
                            struct masq_reverse_key rk = {0};
                            rk.dport = tcp_state_key.dport;
                            rk.sport = tcp_state_key.sport;
                            rk.ifindex = event.ifindex;
                            rk.__in46_u_dest.ip = tcp_state_key.__in46_u_dst.ip;
                            rk.__in46_u_src.ip = tcp_state_key.__in46_u_src.ip;
                            rk.protocol = IPPROTO_TCP;
                            del_reverse_masq(rk);
                            if(local_diag->verbose){
                                event.tracking_code = REVERSE_MASQUERADE_ENTRY_REMOVED;
                                send_event(&event);
                            }
                            struct masq_key mk = {0};
                            mk.dport = tcph->dest;
                            mk.sport = tcph->source;
                            mk.__in46_u_dest.ip = iph->daddr;
                            mk.ifindex = event.ifindex;
                            mk.protocol = IPPROTO_TCP;
                            del_masq(mk);
                            if(local_diag->verbose){
                                event.tracking_code = MASQUERADE_ENTRY_REMOVED;
                                send_event(&event);
                            }
                        }
                        del_tcp(tcp_state_key);
                        tstate = get_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                event.tracking_code = CLIENT_FINAL_ACK_RCVD;
                                send_event(&event);
                            }
                        }
                    }
                    else if((tstate->est) && (tstate->sfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->sfseq) + 1))){
                        tstate->cfack = 1;
                        tstate->tstamp = tstamp;
                    }
                    else{
                        tstate->tstamp = tstamp;
                    }
                }
            }
        }else{
            /* if udp based tuple implement stateful inspection to see if they were
            * initiated by the local OS if not then its passthrough traffic and so wee need to
            * setup our own state to track the outbound pass through connections in via shared hashmap
            * with with ingress tc program */
            event.proto = IPPROTO_UDP;
            struct udphdr *udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            reverse_tuple.ipv4.daddr = tuple->ipv4.saddr;
            reverse_tuple.ipv4.dport = tuple->ipv4.sport;
            reverse_tuple.ipv4.saddr = tuple->ipv4.daddr;
            reverse_tuple.ipv4.sport = tuple->ipv4.dport;
            unsigned long long tstamp = bpf_ktime_get_ns();
            sk = bpf_sk_lookup_udp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
            if(sk){
                bpf_sk_release(sk);
            }else{
                udp_state_key.__in46_u_src.ip = tuple->ipv4.saddr;
                udp_state_key.__in46_u_dst.ip = tuple->ipv4.daddr;
                udp_state_key.sport = tuple->ipv4.sport;
                udp_state_key.dport = tuple->ipv4.dport;
                if(local_diag->masquerade && local_ip4 && local_ip4->count){
                    struct masq_reverse_key revk = {0};
                    revk.__in46_u_src.ip =  tuple->ipv4.saddr;
                    revk.__in46_u_dest.ip = tuple->ipv4.daddr;
                    revk.dport = tuple->ipv4.dport;
                    revk.sport = tuple->ipv4.sport;
                    revk.protocol = IPPROTO_UDP;
                    revk.ifindex = skb->ifindex;
                    __u16 rand_source_port = 0;
                    struct masq_value *revv = get_reverse_masquerade(revk);
                    if(revv){
                        rand_source_port = revv->o_sport;
                    }
                    else{
                        rand_source_port = bpf_htons(1024 + bpf_get_prandom_u32() % (65535 -1023));
                        struct masq_value rev_new_val = {0};
                        rev_new_val.o_sport =  rand_source_port;
                        rev_new_val.__in46_u_origin.ip = 0;
                        insert_reverse_masquerade(rev_new_val,revk);
                        if(local_diag->verbose){
                            event.tracking_code = REVERSE_MASQUERADE_ENTRY_ADDED;
                            send_event(&event);
                        }
                    }
                    __u32 l3_sum = bpf_csum_diff((__u32 *)&tuple->ipv4.saddr, sizeof(tuple->ipv4.saddr), (__u32 *)&local_ip4->ipaddr[0], sizeof(local_ip4->ipaddr[0]), 0);
                    struct masq_value mv = {0};
                    struct masq_key mk = {0};
                    mk.__in46_u_dest.ip =  tuple->ipv4.daddr;
                    mk.dport = tuple->ipv4.dport;
                    mk.sport = rand_source_port;
                    mk.ifindex = skb->ifindex;
                    mk.protocol = IPPROTO_UDP;
                    struct masq_value *mvptr = get_masquerade(mk);
                    if(!mvptr){
                        mv.__in46_u_origin.ip =  tuple->ipv4.saddr;
                        mv.o_sport = tuple->ipv4.sport;
                        insert_masquerade(mv, mk);
                        if(local_diag->verbose){
                            event.tracking_code = MASQUERADE_ENTRY_ADDED;
                            send_event(&event);
                        }
                    }else{
                        mv = *mvptr;
                    }
                    iph->saddr = local_ip4->ipaddr[0];
                    /*Calculate l3 Checksum*/
                    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, l3_sum, 0);
                    iph = (struct iphdr *)(skb->data + sizeof(*eth));
                    if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                        return TC_ACT_SHOT;
                    }
                    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
                    if(!tuple){
                        return TC_ACT_SHOT;
                    }
                    tuple_len = sizeof(tuple->ipv4);
                    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                        return TC_ACT_SHOT;
                    }
                    udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
                    if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                        return TC_ACT_SHOT;
                    }
                    /*Calculate l4 Checksum if checksum not equal to zero*/
                    if(udph->check != 0){
                        int flags = BPF_F_PSEUDO_HDR;
                        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), 0, l3_sum, flags);
                        iph = (struct iphdr *)(skb->data + sizeof(*eth));
                        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
                        if(!tuple){
                            return TC_ACT_SHOT;
                        }
                        tuple_len = sizeof(tuple->ipv4);
                        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        udph = (struct udphdr *)((unsigned long)iph + sizeof(*iph));
                        if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        udph->source = rand_source_port;
                        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check), mv.o_sport , rand_source_port, flags | 2);
                        iph = (struct iphdr *)(skb->data + sizeof(*eth));
                        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
                        if(!tuple){
                            return TC_ACT_SHOT;
                        }
                        tuple_len = sizeof(tuple->ipv4);
                        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        } 
                    }else{
                        udph->source = rand_source_port;
                    }
                }
                struct udp_state *ustate = get_udp(udp_state_key);
                if((!ustate) || (ustate->tstamp > (tstamp + 30000000000))){
                    struct udp_state us = {
                        tstamp
                    };
                    insert_udp(us, udp_state_key);
                    if(local_diag->verbose){
                        event.tracking_code = CLIENT_INITIATED_UDP_SESSION;
                        send_event(&event);
                    }
                }
                else if(ustate){
                    ustate->tstamp = tstamp;
                }
            }
        }
    }else if(ipv6 && local_diag->ipv6_enable){
        /* determine length of tuple */
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        __u8 protocol = ip6h->nexthdr;
        tuple = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
        if(!tuple){
            return TC_ACT_SHOT;
        }
        tuple_len = sizeof(tuple->ipv6);
        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
        if(protocol == IPPROTO_TCP){
            tcp = true;
        }
        memcpy(event.saddr,tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
        memcpy(event.daddr,tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
        event.sport = tuple->ipv6.sport;
        event.dport = tuple->ipv6.dport;
        /* if tcp based tuple implement stateful inspection to see if they were
        * initiated by the local OS if not then its passthrough traffic and so wee need to
        * setup our own state to track the outbound pass through connections in via shared hashmap
        *  with with ingress tc program
        */
        if(tcp){
            event.proto = IPPROTO_TCP;
            struct tcphdr *tcph = (struct tcphdr *)((unsigned long)ip6h + sizeof(*ip6h));
            if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            memcpy(reverse_tuple.ipv6.daddr, tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
            reverse_tuple.ipv6.dport = tuple->ipv6.sport;
            memcpy(reverse_tuple.ipv6.saddr, tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
            reverse_tuple.ipv6.sport = tuple->ipv6.dport;
            sk = bpf_skc_lookup_tcp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv6),BPF_F_CURRENT_NETNS, 0);
            if(sk){
                if (sk->state != BPF_TCP_LISTEN){
                    bpf_sk_release(sk);
                    if(local_diag->verbose){
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }
                bpf_sk_release(sk);
            }
            memcpy(tcp_state_key.__in46_u_src.ip6,tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
            memcpy(tcp_state_key.__in46_u_dst.ip6,tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
            tcp_state_key.sport = tuple->ipv6.sport;
            tcp_state_key.dport = tuple->ipv6.dport;
            if(local_diag->masquerade && local_ip6 && local_ip6->count){
                struct masq_value mv = {0};
                memcpy(mv.__in46_u_origin.ip6, tuple->ipv6.saddr, sizeof(mv.__in46_u_origin.ip6));
                struct masq_key mk = {0};
                memcpy(mk.__in46_u_dest.ip6, tuple->ipv6.daddr,  sizeof(tuple->ipv6.daddr));
                mk.dport = tuple->ipv6.dport;
                mk.sport = tuple->ipv6.sport;
                mk.ifindex = skb->ifindex;
                mk.protocol = IPPROTO_TCP;
                insert_masquerade(mv, mk);
                memcpy(ip6h->saddr.in6_u.u6_addr32, local_ip6->ipaddr[0],  sizeof(local_ip6->ipaddr[0]));
                /*Calculate l4 Checksum*/
                for(int x = 0; x < 4; x++){
                    bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check), mv.__in46_u_origin.ip6[x], ip6h->saddr.in6_u.u6_addr32[x], BPF_F_PSEUDO_HDR | 4);
                    ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
                    if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
                        return TC_ACT_SHOT;
                    }
                    tuple = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
                    if(!tuple){
                        return TC_ACT_SHOT;
                    }
                    tuple_len = sizeof(tuple->ipv6);
                    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                        return TC_ACT_SHOT;
                    }
                    tcph = (struct tcphdr *)((unsigned long)ip6h + sizeof(*ip6h));
                    if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                        return TC_ACT_SHOT;
                    }
                }
            }
            unsigned long long tstamp = bpf_ktime_get_ns();
            struct tcp_state *tstate;
            if(tcph->syn && !tcph->ack){
                struct tcp_state ts = {
                tstamp,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0
                };
                insert_tcp(ts, tcp_state_key);
                if(local_diag->verbose){
                    event.tracking_code = CLIENT_SYN_RCVD;
                    send_event(&event);
                }
            }
            else if(tcph->fin){
                tstate = get_tcp(tcp_state_key);
                if(tstate){
                    tstate->tstamp = tstamp;
                    tstate->cfin = 1;
                    tstate->cfseq = tcph->seq;
                    if(local_diag->verbose){
                        event.tracking_code = CLIENT_FIN_RCVD;
                        send_event(&event);
                    }
                }
            }
            else if(tcph->rst){
                tstate = get_tcp(tcp_state_key);
                if(tstate){
                    del_tcp(tcp_state_key);
                    tstate = get_tcp(tcp_state_key);
                    if(!tstate){
                        if(local_diag->verbose){
                            event.tracking_code = CLIENT_RST_RCVD;
                            send_event(&event);
                        }
                    }
                }
            }
            else if(tcph->ack){
                tstate = get_tcp(tcp_state_key);
                if(tstate){
                    if(tstate->ack && tstate->syn){
                        if(local_diag->verbose){
                            event.tracking_code = TCP_CONNECTION_ESTABLISHED;
                            send_event(&event);
                        }
                        tstate->tstamp = tstamp;
                        tstate->syn = 0;
                        tstate->est = 1;
                    }
                    if((tstate->est) && (tstate->sfin == 1) && (tstate->cfin == 1) && (tstate->sfack) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->sfseq) + 1))){
                        del_tcp(tcp_state_key);
                        tstate = get_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                event.tracking_code = CLIENT_FINAL_ACK_RCVD;
                                send_event(&event);
                            }
                        }
                    }
                    else if((tstate->est) && (tstate->sfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->sfseq) + 1))){
                        tstate->cfack = 1;
                        tstate->tstamp = tstamp;
                    }
                    else{
                        tstate->tstamp = tstamp;
                    }
                }
            }
        }else{
            /* if udp based tuple implement stateful inspection to see if they were
            * initiated by the local OS if not then its passthrough traffic and so wee need to
            * setup our own state to track the outbound pass through connections in via shared hashmap
            * with with ingress tc program */
            event.proto = IPPROTO_UDP;
            struct udphdr *udph = (struct udphdr *)((unsigned long)ip6h + sizeof(*ip6h));
            if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            memcpy(reverse_tuple.ipv6.daddr, tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
            reverse_tuple.ipv6.dport = tuple->ipv6.sport;
            memcpy(reverse_tuple.ipv6.saddr, tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
            reverse_tuple.ipv6.sport = tuple->ipv6.dport;
            unsigned long long tstamp = bpf_ktime_get_ns();
            sk = bpf_sk_lookup_udp(skb, &reverse_tuple, sizeof(reverse_tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
            if(sk){
                bpf_sk_release(sk);
            }else{
                memcpy(udp_state_key.__in46_u_src.ip6,tuple->ipv6.saddr, sizeof(tuple->ipv6.saddr));
                memcpy(udp_state_key.__in46_u_dst.ip6,tuple->ipv6.daddr, sizeof(tuple->ipv6.daddr));
                udp_state_key.sport = tuple->ipv6.sport;
                udp_state_key.dport = tuple->ipv6.dport;
                if(local_diag->masquerade && local_ip6 && local_ip6->count){
                    struct masq_value mv = {0};
                    memcpy(mv.__in46_u_origin.ip6, tuple->ipv6.saddr, sizeof(mv.__in46_u_origin.ip6));
                    struct masq_key mk = {0};
                    memcpy(mk.__in46_u_dest.ip6, tuple->ipv6.daddr,  sizeof(tuple->ipv6.daddr));
                    mk.dport = tuple->ipv6.dport;
                    mk.sport = tuple->ipv6.sport;
                    mk.ifindex = skb->ifindex;
                    mk.protocol = IPPROTO_UDP;
                    insert_masquerade(mv, mk );
                    memcpy(ip6h->saddr.in6_u.u6_addr32, local_ip6->ipaddr[0],  sizeof(local_ip6->ipaddr[0]));
                    /*Calculate l4 Checksum*/
                    for(int x = 0; x < 4; x++){
                        bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct udphdr, check), mv.__in46_u_origin.ip6[x], ip6h->saddr.in6_u.u6_addr32[x], BPF_F_PSEUDO_HDR | 4);
                        ip6h = (struct ipv6hdr *)(skb->data + sizeof(*eth));
                        if ((unsigned long)(ip6h + 1) > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        tuple = (struct bpf_sock_tuple *)(void*)(long)&ip6h->saddr;
                        if(!tuple){
                            return TC_ACT_SHOT;
                        }
                        tuple_len = sizeof(tuple->ipv6);
                        if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                        udph = (struct udphdr *)((unsigned long)ip6h + sizeof(*ip6h));
                        if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                            return TC_ACT_SHOT;
                        }
                    }
                }
                struct udp_state *ustate = get_udp(udp_state_key);
                if((!ustate) || (ustate->tstamp > (tstamp + 30000000000))){
                    struct udp_state us = {
                        tstamp
                    };
                    insert_udp(us, udp_state_key);
                    if(local_diag->verbose){
                        event.tracking_code = CLIENT_INITIATED_UDP_SESSION;
                        send_event(&event);
                    }
                }
                else if(ustate){
                    ustate->tstamp = tstamp;
                }
            }
        }
    }
    return TC_ACT_OK;
}
SEC("license") const char __license[] = "Dual BSD/GPL";
