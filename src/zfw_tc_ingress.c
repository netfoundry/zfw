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
#include <linux/icmp.h>
#include <linux/if.h>
#include <stdio.h>
#include <string.h>

#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES   100 //MAX # PREFIXES
#endif
#define MAX_INDEX_ENTRIES                   100 //MAX port ranges per prefix need to match in user space apps 
#define MAX_TABLE_SIZE                      65536 //needs to match in userspace
#define GENEVE_UDP_PORT                     6081
#define GENEVE_VER                          0
#define AWS_GNV_HDR_OPT_LEN                 32 // Bytes
#define AWS_GNV_HDR_LEN                     40 // Bytes
#define MATCHED_KEY_DEPTH                   3
#define MATCHED_INT_DEPTH                   50
#define MAX_IF_LIST_ENTRIES                 3
#define MAX_IF_ENTRIES                      256
#define SERVICE_ID_BYTES                    32
#define MAX_TRANSP_ROUTES                   256
#define BPF_MAX_SESSIONS                    10000
#define MAX_ADDRESSES                       10
#define IP_HEADER_TOO_BIG                   1
#define NO_IP_OPTIONS_ALLOWED               2
#define UDP_HEADER_TOO_BIG                  3
#define GENEVE_HEADER_TOO_BIG               4
#define GENEVE_HEADER_LENGTH_VERSION_ERROR  5
#define SKB_ADJUST_ERROR                    6
#define ICMP_HEADER_TOO_BIG                 7
#define IP_TUPLE_TOO_BIG                    8
#define IF_LIST_MATCH_ERROR                 9
#define INGRESS                             0
#define SERVER_SYN_ACK_RCVD                 1
#define SERVER_FIN_RCVD                     2
#define SERVER_RST_RCVD                     3
#define SERVER_FINAL_ACK_RCVD               4
#define UDP_MATCHED_EXPIRED_STATE           5
#define UDP_MATCHED_ACTIVE_STATE            6
#define ICMP_INNER_IP_HEADER_TOO_BIG        13
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct tproxy_port_mapping {
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u8 if_list[MAX_IF_LIST_ENTRIES];
};

struct tproxy_tuple {
    __u16 index_len; /*tracks the number of entries in the index_table*/
    __u16 index_table[MAX_INDEX_ENTRIES];/*Array used as index table which point to struct 
                                             *tproxy_port_mapping in the port_maping array
                                             * with each populated index representing a udp or tcp tproxy 
                                             * mapping in the port_mapping array
                                             */
    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];/*Array to store unique tproxy mappings
                                                               *  with each index matches the low_port of
                                                               * struct tproxy_port_mapping {
                                                               *  __u16 low_port;
                                                               *  __u16 high_port;
                                                               * __u16 tproxy_port;
                                                               * __u32 tproxy_ip;
                                                               * }
                                                               */
};

/*key to zt_tproxy_map*/
struct tproxy_key {
    __u32 dst_ip;
    __u32 src_ip;
    __u16 dprefix_len;
    __u16 sprefix_len;
    __u16 protocol;
    __u16 pad;
};


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

/*Key to tcp_map*/
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
unsigned int ifindex;


/*Value to matched_map*/
struct match_tracker {
    __u16 count;
    struct tproxy_key matched_keys[MATCHED_KEY_DEPTH];
};



/*value to ifindex_ip_map*/
struct ifindex_ip4 {
    uint32_t ipaddr[MAX_ADDRESSES];
    char ifname[IFNAMSIZ];
    uint8_t count;
};

/*value to ifindex_tun_map*/
struct ifindex_tun {
    uint32_t index;
    char ifname[IFNAMSIZ];
    char cidr[16];
    char mask[3];
    bool verbose;
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
};

/*Value to tun_map*/
struct tun_state {
    unsigned long long tstamp;
    unsigned int ifindex;
    unsigned char source[6];
    unsigned char dest[6];
};

/*key to transp_map*/
struct transp_key {
    char service_id[SERVICE_ID_BYTES];
};

struct transp_entry {
    struct in_addr saddr;
    __u16 prefix_len;
};

/*Value to transp_map*/
struct transp_value{
    struct transp_entry tentry[MAX_TRANSP_ROUTES];
    __u8 count;
};

struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(key_size, sizeof(struct transp_key));
     __uint(value_size,sizeof(struct transp_value));
     __uint(max_entries, BPF_MAX_ENTRIES);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
     __uint(map_flags, BPF_F_NO_PREALLOC);
} zet_transp_map SEC(".maps");

/*map to track up to 3 key matches per incoming packet search.  Map is 
then used to search for port mappings.  This was required when source filtering was 
added to accommodate the additional instructions per ebpf program.  The search now spans
5 ebpf programs  */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(struct match_tracker));
    __uint(max_entries, MATCHED_INT_DEPTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} matched_map SEC(".maps");

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

//map to keep track of total entries in zt_tproxy_map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tuple_count_map SEC(".maps");

/* File system pinned Hashmap to store the socket mapping with look up key with the 
* following struct format. 
*
* struct tproxy_key {
*    __u32 dst_ip;
*    __u16 dprefix_len;
*    __u16 pad;
*
*    which is a combination of ip prefix and cidr mask length.
*
*    The value is has the format of the following struct
*
*    struct tproxy_tuple {
*    __u32 dst_ip; future use
*	 __u32 src_ip; 
*    __u16 index_len; //tracks the number of entries in the index_table
*    __u16 index_table[MAX_INDEX_ENTRIES];
*    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];
*    }
*/
struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(key_size, sizeof(struct tproxy_key));
     __uint(value_size,sizeof(struct tproxy_tuple));
     __uint(max_entries, BPF_MAX_ENTRIES);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
     __uint(map_flags, BPF_F_NO_PREALLOC);
} zt_tproxy_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct tcp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct udp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_map SEC(".maps");

/*Hashmap to track tun interface inbound passthrough connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tun_key));
     __uint(value_size,sizeof(struct tun_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tun_map SEC(".maps");

/* function for ebpf program to access zt_tproxy_map entries
 * based on {prefix,mask,protocol} i.e. {192.168.1.0,24,IPPROTO_TCP}
 */
static inline struct tproxy_tuple *get_tproxy(struct tproxy_key key){
    struct tproxy_tuple *tu;
    tu = bpf_map_lookup_elem(&zt_tproxy_map, &key);
	return tu;
}

static inline void del_tcp(struct tuple_key key){
     bpf_map_delete_elem(&tcp_map, &key);
}

static inline struct tcp_state *get_tcp(struct tuple_key key){
    struct tcp_state *ts;
    ts = bpf_map_lookup_elem(&tcp_map, &key);
	return ts;
}

static inline void del_udp(struct tuple_key key){
     bpf_map_delete_elem(&udp_map, &key);
}

static inline struct udp_state *get_udp(struct tuple_key key){
    struct udp_state *us;
    us = bpf_map_lookup_elem(&udp_map, &key);
	return us;
}

/*Insert entry into tun state table*/
static inline void insert_tun(struct tun_state tustate, struct tun_key key){
     bpf_map_update_elem(&tun_map, &key, &tustate,0);
}

/*get entry from tun state table*/
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

/*Ringbuf map*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb_map SEC(".maps");

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

static inline struct diag_ip4 *get_diag_ip4(__u32 key){
    struct diag_ip4 *if_diag;
    if_diag = bpf_map_lookup_elem(&diag_map, &key);

	return if_diag;
}

/*function to update the ifindex_ip_map locally from ebpf possible
future use*/
/*static inline void update_local_ip4(__u32 ifindex,__u32 key){
    struct ifindex_ip4 *ifip4;
    ifip4 = bpf_map_lookup_elem(&ifindex_ip_map, &key);
    if(ifip4){
        __sync_fetch_and_add(&ifip4->ifindex, ifindex);
    }
}*/

/*function to update the matched_map locally from ebpf*/
static inline void insert_matched_key(struct match_tracker matched_keys, unsigned int key){
     bpf_map_update_elem(&matched_map, &key, &matched_keys,0);
}

/*Function to get stored matched tracker*/
static inline struct match_tracker *get_matched_keys(unsigned int key){
    struct match_tracker *mt;
    mt = bpf_map_lookup_elem(&matched_map, &key);
	return mt;
}

/*Function to get stored matched key count*/
static inline __u16 get_matched_count(unsigned key){
    struct match_tracker *mt;
    __u16 mc = 0;
    mt = bpf_map_lookup_elem(&matched_map,&key);
    if(mt){
        mc = mt->count;
    }
    return mc;
}

/*Function to clear matched tracker*/
static inline void clear_match_tracker(__u32 key){
    struct match_tracker mt = {0};
    bpf_map_update_elem(&matched_map, &key, &mt,0);
}

static inline void send_event(struct bpf_event *new_event){
    struct bpf_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&rb_map, sizeof(*rb_event), 0);
    if(rb_event){
        rb_event->ifindex = new_event->ifindex;
        rb_event->tun_ifindex = new_event->tun_ifindex;
        rb_event->tstamp = new_event->tstamp;
        //rb_event->tstamp = bpf_ktime_get_ns();   
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

/* function to determine if an incoming packet is a udp/tcp IP tuple
* or not.  If not returns NULL.  If true returns a struct bpf_sock_tuple
* from the combined IP SA|DA and the TCP/UDP SP|DP. 
*/
static struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, __u64 nh_off,
    __u16 eth_proto, bool *ipv4, bool *ipv6, bool *udp, bool *tcp, bool *arp, bool *icmp, bool *vrrp,
     struct bpf_event *event, struct diag_ip4 *local_diag){

    struct bpf_sock_tuple *result;
    __u8 proto = 0;
    int ret;
    
    /* check if ARP */
    if (eth_proto == bpf_htons(ETH_P_ARP)) {
        *arp = true;
        return NULL;
    }
    
    /* check if IPv6 */
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        *ipv6 = true;
        return NULL;
    }
    
    /* check IPv4 */
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        *ipv4 = true;

        /* find ip hdr */
        struct iphdr *iph = (struct iphdr *)(skb->data + nh_off);
        
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
        /* get ip protocol type */
        proto = iph->protocol;
        /* check if ip protocol is UDP */
        if (proto == IPPROTO_UDP) {
            /* check outer ip header */
            struct udphdr *udph = (struct udphdr *)(skb->data + nh_off + sizeof(struct iphdr));
            if ((unsigned long)(udph + 1) > (unsigned long)skb->data_end){
                event->error_code = UDP_HEADER_TOO_BIG;
                send_event(event);
                return NULL;
            }

            /* If geneve port 6081, then do geneve header verification */
            if (bpf_ntohs(udph->dest) == GENEVE_UDP_PORT){
                /* read receive geneve version and header length */
                __u8 *genhdr = (void *)(unsigned long)(skb->data + nh_off + sizeof(struct iphdr) + sizeof(struct udphdr));
                if ((unsigned long)(genhdr + 1) > (unsigned long)skb->data_end){
                    event->error_code = GENEVE_HEADER_TOO_BIG;
                    send_event(event);
                    return NULL;
                }
                __u32 gen_ver  = genhdr[0] & 0xC0 >> 6;
                __u32 gen_hdr_len = genhdr[0] & 0x3F;
                
                /* if the length is not equal to 32 bytes and version 0 */
                if ((gen_hdr_len != AWS_GNV_HDR_OPT_LEN / 4) || (gen_ver != GENEVE_VER)){
                    event->error_code = GENEVE_HEADER_LENGTH_VERSION_ERROR;
                    send_event(event);
                    return NULL;
                }

                /* Updating the skb to pop geneve header */
                ret = bpf_skb_adjust_room(skb, -68, BPF_ADJ_ROOM_MAC, 0);
                if (ret) {
                    event->error_code = SKB_ADJUST_ERROR;
                    send_event(event);
                    return NULL;
                }
                /* Initialize iph for after popping outer */
                iph = (struct iphdr *)(skb->data + nh_off);
                if((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                    event->error_code = IP_HEADER_TOO_BIG;
                    send_event(event);
                    return NULL;
                }
                proto = iph->protocol;
            }
            /* set udp to true if inner is udp, and let all other inner protos to the next check point */
            if (proto == IPPROTO_UDP) {
                *udp = true;
            }
        }
        /* check if ip protocol is TCP */
        if (proto == IPPROTO_TCP) {
            *tcp = true;
        }
        if(proto == IPPROTO_ICMP){
            *icmp = true;
            return NULL;
        }
        if(proto == 112){
            *vrrp = true;
            return NULL;
        }
        /* check if ip protocol is not UDP or TCP. Return NULL if true */
        if ((proto != IPPROTO_UDP) && (proto != IPPROTO_TCP)) {
            return NULL;
        }
        /*return bpf_sock_tuple*/
        result = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    } else {
        return NULL;
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

static inline struct bpf_sock *get_sk(struct tproxy_key key, struct __sk_buff *skb, struct bpf_sock_tuple sockcheck){
    struct bpf_sock *sk;
        if(key.protocol == IPPROTO_TCP){
            sk = bpf_skc_lookup_tcp(skb, &sockcheck, sizeof(sockcheck.ipv4),BPF_F_CURRENT_NETNS, 0);
        }else{
            sk = bpf_sk_lookup_udp(skb, &sockcheck, sizeof(sockcheck.ipv4),BPF_F_CURRENT_NETNS, 0);
        }
        if(sk){
            if((key.protocol == IPPROTO_TCP) && (sk->state != BPF_TCP_LISTEN)){
                bpf_sk_release(sk);
                return NULL;
            }    
        }
    return sk;
}

//ebpf tc code entry program
SEC("action")
int bpf_sk_splice(struct __sk_buff *skb){
    struct bpf_sock *sk; 
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    bool ipv4 = false;
    bool ipv6 = false;
    bool udp=false;
    bool tcp=false;
    bool arp=false;
    bool icmp=false;
    bool vrrp=false;
    int ret;

    unsigned long long tstamp = bpf_ktime_get_ns();
    struct bpf_event event = {
        tstamp,
        skb->ifindex,
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
    
    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ingress_ifindex);
    if(!local_diag){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }else{
            return TC_ACT_SHOT;
        }
    }
    struct tuple_key tcp_state_key;
    struct tuple_key udp_state_key;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
        return TC_ACT_SHOT;
	}
    
    /*check if 802.1X and passthrough is enabled*/
    if((bpf_ntohs(eth->h_proto) == 0x888e) && local_diag->eapol){
        return TC_ACT_OK;
    }

    /* check if incoming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp, &icmp, &vrrp, &event, local_diag);

    /*look up attached interface IP address*/
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ingress_ifindex);

    /* if not tuple forward ARP and drop all other traffic */
    if (!tuple){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }
        else if(arp){
            return TC_ACT_OK;
	    }
        else if(icmp){
            struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
            if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            struct icmphdr *icmph = (struct icmphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(icmph + 1) > (unsigned long)skb->data_end){
                event.error_code = ICMP_HEADER_TOO_BIG;
                send_event(&event);
                return TC_ACT_SHOT;
            }
            else if((icmph->type == 8) && (icmph->code == 0)){
                if(local_diag && local_diag->echo){
                    return TC_ACT_OK;
                }
                else{
                    return TC_ACT_SHOT;
                }
            }
            else if((icmph->type == 0) && (icmph->code == 0)){
                return TC_ACT_OK;
            }
            else if(icmph->type == 3){
                struct iphdr *inner_iph = (struct iphdr *)((unsigned long)icmph + sizeof(*icmph));
                if ((unsigned long)(inner_iph + 1) > (unsigned long)skb->data_end){
                    if(local_diag->verbose){
                        event.error_code = ICMP_INNER_IP_HEADER_TOO_BIG;
                        send_event(&event);
                    }
                    return TC_ACT_SHOT;
                }
                if((inner_iph->protocol == IPPROTO_TCP) || ((inner_iph->protocol == IPPROTO_UDP))){
                    struct bpf_sock_tuple *o_session = (struct bpf_sock_tuple *)(void*)(long)&inner_iph->saddr; 
                    if ((unsigned long)(o_session + 1) > (unsigned long)skb->data_end){
                        event.error_code = IP_TUPLE_TOO_BIG;
                        send_event(&event);
                        return TC_ACT_SHOT;
                    }
                    if(inner_iph->protocol == IPPROTO_TCP){
                        sk = bpf_skc_lookup_tcp(skb, o_session, sizeof(o_session->ipv4),BPF_F_CURRENT_NETNS, 0);
                        if(sk){
                            if (sk->state == BPF_TCP_LISTEN){
                                event.proto = IPPROTO_ICMP;
                                event.saddr = iph->saddr;
                                event.daddr = o_session->ipv4.daddr;
                                event.tracking_code = icmph->code;
                                if(icmph->code == 4){
                                    event.sport = icmph->un.frag.mtu;
                                }else{
                                    event.sport = inner_iph->protocol;
                                }
                                event.dport = o_session->ipv4.dport;
                                send_event(&event);
                                bpf_sk_release(sk);
                                return TC_ACT_OK;
                            }
                            bpf_sk_release(sk);
                        }
                    }
                    else{
                        struct bpf_sock_tuple oudp_session = {0};
                        oudp_session.ipv4.daddr = o_session->ipv4.saddr;
                        oudp_session.ipv4.saddr = o_session->ipv4.daddr;
                        oudp_session.ipv4.dport = o_session->ipv4.sport;
                        oudp_session.ipv4.sport = o_session->ipv4.dport;
                        sk = bpf_sk_lookup_udp(skb, &oudp_session, sizeof(oudp_session.ipv4), BPF_F_CURRENT_NETNS, 0);
                        if(sk){
                            event.proto = IPPROTO_ICMP;
                            event.saddr = iph->saddr;
                            event.daddr = o_session->ipv4.daddr;
                            event.tracking_code = icmph->code;
                            if(icmph->code == 4){
                                event.sport = icmph->un.frag.mtu;
                            }else{
                                event.sport = inner_iph->protocol;
                            }
                            event.dport = o_session->ipv4.dport;
                            send_event(&event);
                            bpf_sk_release(sk);
                            return TC_ACT_OK;
                        }
                    }

                }
                return TC_ACT_SHOT;
            }
            else{
                return TC_ACT_SHOT;
            }
        }else if(vrrp && local_diag && local_diag->vrrp)
        {
            return TC_ACT_OK;
        }
        else{
            return TC_ACT_SHOT;
        }   
    }

    /* determine length of tuple */
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       if(local_diag->verbose){
            event.error_code = IP_TUPLE_TOO_BIG;
            send_event(&event);
       }
       return TC_ACT_SHOT;
    }
    event.saddr = tuple->ipv4.saddr;
    event.daddr = tuple->ipv4.daddr;
    event.sport = tuple->ipv4.sport;
    event.dport = tuple->ipv4.dport;
    if((skb->ingress_ifindex == 1) && udp && (bpf_ntohs(tuple->ipv4.dport) == 53)){
       return TC_ACT_OK;
    }
    /* allow ssh to local interface ip addresses */
    if(tcp && (bpf_ntohs(tuple->ipv4.dport) == 22)){
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
                if((tuple->ipv4.daddr == local_ip4->ipaddr[x]) && !local_diag->ssh_disable){
                    if(local_diag->verbose && ((event.tstamp % 2) == 0)){
                        event.proto = IPPROTO_TCP;
                        send_event(&event);
                    }
                    return TC_ACT_OK;
                }
            }
        }
    }
    /* forward DHCP messages to local system */
    if(udp && (bpf_ntohs(tuple->ipv4.sport) == 67) && (bpf_ntohs(tuple->ipv4.dport) == 68)){
       return TC_ACT_OK;
    }
     /* if tcp based tuple implement stateful inspection to see if they were
     * initiated by the local OS if not pass on to tproxy logic to determine if the
     * openziti router has tproxy intercepts defined for the flow
     */
    if(tcp){
       /*if tcp based tuple implement stateful inspection to see if they were
       * initiated by the local OS and If yes jump to assign. Then check if tuple is a reply to 
       outbound initiated from through the router interface. if not pass on to tproxy logic
       to determine if the openziti router has tproxy intercepts defined for the flow*/
       event.proto = IPPROTO_TCP;
       sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len,BPF_F_CURRENT_NETNS, 0);
       if(sk){
            if (sk->state != BPF_TCP_LISTEN){
                if(local_diag->verbose){
                    send_event(&event);
                }
                goto assign;
            }
            bpf_sk_release(sk);
        /*reply to outbound passthrough check*/
       }else{
            struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
            if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            struct tcphdr *tcph = (struct tcphdr *)((unsigned long)iph + sizeof(*iph));
            if ((unsigned long)(tcph + 1) > (unsigned long)skb->data_end){
                return TC_ACT_SHOT;
            }
            tcp_state_key.daddr = tuple->ipv4.saddr;
            tcp_state_key.saddr = tuple->ipv4.daddr;
            tcp_state_key.sport = tuple->ipv4.dport;
            tcp_state_key.dport = tuple->ipv4.sport;
	        unsigned long long tstamp = bpf_ktime_get_ns();
            struct tcp_state *tstate = get_tcp(tcp_state_key);
            /*check tcp state and timeout if greater than 60 minutes without traffic*/
            if(tstate && (tstamp < (tstate->tstamp + 3600000000000))){    
                if(tcph->syn  && tcph->ack){
                    tstate->ack =1;
                    tstate->tstamp = tstamp;
                    if(local_diag->verbose){
                        event.tracking_code = SERVER_SYN_ACK_RCVD;
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
                            event.tracking_code = SERVER_FIN_RCVD;
                            send_event(&event);
                        }
                        return TC_ACT_OK;
                    }
                }
                else if(tcph->rst){
                    if(tstate->est){
                        del_tcp(tcp_state_key);
                        tstate = get_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                event.tracking_code = SERVER_RST_RCVD;
                                send_event(&event);
                            }
                        }
                        return TC_ACT_OK;
                    }
                }
                else if(tcph->ack){
                    if((tstate->est) && (tstate->sfin == 1) && (tstate->cfin == 1) && (bpf_htonl(tcph->ack_seq) == (bpf_htonl(tstate->cfseq) + 1))){
                        del_tcp(tcp_state_key);
                        tstate = get_tcp(tcp_state_key);
                        if(!tstate){
                            if(local_diag->verbose){
                                event.tracking_code = SERVER_FINAL_ACK_RCVD;
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
            }
            else if(tstate){
                del_tcp(tcp_state_key);
            }
       }
    }else{
       /* if udp based tuple implement stateful inspection to 
        * implement stateful inspection to see if they were initiated by the local OS and If yes jump
        * to assign label. Then check if tuple is a reply to outbound initiated from through the router interface. 
        * if not pass on to tproxy logic to determine if the openziti router has tproxy intercepts
        * defined for the flow*/
        event.proto = IPPROTO_UDP;
        sk = bpf_sk_lookup_udp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
        if(sk){
           /*
            * check if there is a dest ip associated with the local socket. if yes jump to assign if not
            * disregard and release the sk and continue on to check for tproxy mapping.
            */
           if(sk->dst_ip4){
                if(local_diag->verbose){
                    send_event(&event);
                }
                goto assign;
           }
           bpf_sk_release(sk);
        /*reply to outbound passthrough check*/
        }else{
            udp_state_key.daddr = tuple->ipv4.saddr;
            udp_state_key.saddr = tuple->ipv4.daddr;
            udp_state_key.sport = tuple->ipv4.dport;
            udp_state_key.dport = tuple->ipv4.sport;
            unsigned long long tstamp = bpf_ktime_get_ns();
            struct udp_state *ustate = get_udp(udp_state_key);
            if(ustate){
                /*if udp outbound state has been up for 30 seconds without traffic remove it from hashmap*/
                if(tstamp > (ustate->tstamp + 30000000000)){
                    del_udp(udp_state_key);
                    ustate = get_udp(udp_state_key);
                    if(!ustate){
                        if(local_diag->verbose){
                            event.tracking_code = UDP_MATCHED_EXPIRED_STATE;
                            send_event(&event);
                        }
                    }
                }
                else{
                    if(local_diag->verbose){
                        event.tracking_code = UDP_MATCHED_ACTIVE_STATE;
                        send_event(&event);
                    }
                    ustate->tstamp = tstamp;
                    return TC_ACT_OK;
                }
            }
        }
    }
    //init the match_count_map
    clear_match_tracker(skb->ifindex);
    return TC_ACT_PIPE;

    assign:
    /*attempt to splice the skb to the tproxy or local socket*/
    ret = bpf_sk_assign(skb, sk, 0);
    /*release sk*/
    bpf_sk_release(sk);
    if(ret == 0){
        //if succeeded forward to the stack
        return TC_ACT_OK;
    }
    /*else drop packet if not running on loopback*/
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }
}

/*Search for keys with Dest mask lengths from /32 down to /25
* and Source masks /32 down to /0 */
SEC("action/1")
int bpf_sk_splice1(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incoming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    protocol = iph->protocol;
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
	struct tproxy_tuple *tproxy;
    __u32 dexponent=24;  /* unsigned integer used to calculate prefix matches */
    __u32 dmask = 0xffffffff;  /* starting mask value used in prefix match calculation */
    __u32 sexponent=24;  /* unsigned integer used to calculate prefix matches */
    __u32 smask = 0xffffffff;  /* starting mask value used in prefix match calculation */
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker key_tracker = {0,{}};
    insert_matched_key(key_tracker, skb->ifindex);
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
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
                if ((tproxy = get_tproxy(key))){
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
    return TC_ACT_SHOT;
}

/*Search for keys with Dest mask lengths from /24 down to /17
* and Source masks /32 down to /0 */
SEC("action/2")
int bpf_sk_splice2(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
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
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
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
               
                if ((tproxy = get_tproxy(key))){
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

/*Search for keys with Dest mask lengths from /16 down to /9
* and Source masks /32 down to /0 */
SEC("action/3")
int bpf_sk_splice3(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
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
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
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
                if ((tproxy = get_tproxy(key))){
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

/*Search for keys with Dest mask lengths from /8 down to /0
* and Source masks /32 down to /0 */
SEC("action/4")
int bpf_sk_splice4(struct __sk_buff *skb){
    struct bpf_sock_tuple *tuple;
    int tuple_len;
    int protocol;

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    

    /* check if incomming packet is a UDP or TCP tuple */
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
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
    __u16 maxlen = 8; /* max number ip ipv4 prefixes */
    __u16 smaxlen = 32; /* max number ip ipv4 prefixes */
    /*Main loop to lookup tproxy prefix matches in the zt_tproxy_map*/
    struct match_tracker *tracked_key_data = get_matched_keys(skb->ifindex);
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
                if ((tproxy = get_tproxy(key))){
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
    struct bpf_sock *sk;
    int ret; 
    struct bpf_sock_tuple *tuple,sockcheck = {0};
    int tuple_len;

    /*look up attached interface inbound diag status*/
    struct diag_ip4 *local_diag = get_diag_ip4(skb->ingress_ifindex);
    if(!local_diag){
        if(skb->ingress_ifindex == 1){
            return TC_ACT_OK;
        }else{
            return TC_ACT_SHOT;
        }
    }

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
    tuple = (struct bpf_sock_tuple *)(void*)(long)&iph->saddr;
    //tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp);
    if(!tuple){
       return TC_ACT_SHOT;
    }

    unsigned long long tstamp = bpf_ktime_get_ns();
    struct bpf_event event = {
        tstamp,
        skb->ifindex,
        0,
        tuple->ipv4.daddr,
        tuple->ipv4.saddr,
        tuple->ipv4.sport,
        tuple->ipv4.dport,
        0,
        0,
        INGRESS,
        0,
        0,
        {},
        {}
     };

    /* determine length of tuple */
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
    struct tproxy_key key;
     /*look up attached interface IP address*/
    struct ifindex_ip4 *local_ip4 = get_local_ip4(skb->ingress_ifindex);
    if(!local_ip4){
       return TC_ACT_SHOT;
    }   
    struct tproxy_tuple *tproxy;
    struct match_tracker *key_tracker;
    __u16 match_count = get_matched_count(skb->ifindex);
    if (match_count > MATCHED_KEY_DEPTH){
       match_count = MATCHED_KEY_DEPTH;
    }
    for(__u16 count =0; count < match_count; count++)
    {
        key_tracker = get_matched_keys(skb->ifindex);
        if(key_tracker){
           key = key_tracker->matched_keys[count];
        }else{
            break;
        }
        if((tproxy = get_tproxy(key)) && tuple)
        {
            __u16 max_entries = tproxy->index_len;
            if (max_entries > MAX_INDEX_ENTRIES) {
                max_entries = MAX_INDEX_ENTRIES;
            }
            for (int index = 0; index < max_entries; index++){
                int port_key = tproxy->index_table[index];
                //check if there is a udp or tcp destination port match
                if ((bpf_ntohs(tuple->ipv4.dport) >= bpf_ntohs(tproxy->port_mapping[port_key].low_port))
                     && (bpf_ntohs(tuple->ipv4.dport) <= bpf_ntohs(tproxy->port_mapping[port_key].high_port))) 
                {
                    event.proto = key.protocol;
                    event.tport = tproxy->port_mapping[port_key].tproxy_port;
                    /*check if interface is set for per interface rule awarness and if yes check if it is in the rules interface list.  If not in
                    the interface list drop it on all interfaces accept loopback.  If its not aware then forward based on mapping*/
                    sockcheck.ipv4.daddr = 0x0100007f;
                    sockcheck.ipv4.dport = tproxy->port_mapping[port_key].tproxy_port;
                    if(!local_diag->per_interface){
                        if(tproxy->port_mapping[port_key].tproxy_port == 0){
                            return TC_ACT_OK;
                        }
                        if(!local_diag->tun_mode){
                            sk = get_sk(key, skb, sockcheck);
                            if(!sk){
                                return TC_ACT_SHOT;
                            }
                            if(!(key.protocol == IPPROTO_UDP) || local_diag->verbose){
                                send_event(&event);
                            }
                            goto assign;
                        }else
                        {
                            struct tun_key tun_state_key;
                            tun_state_key.daddr = tuple->ipv4.daddr;
                            tun_state_key.saddr = tuple->ipv4.saddr;
                            unsigned long long tstamp = bpf_ktime_get_ns();
                            struct tun_state *tustate = get_tun(tun_state_key);
                            if((!tustate) || (tustate->tstamp > (tstamp + 30000000000))){
                                struct tun_state tus = {
                                    tstamp,
                                    skb->ifindex,
                                    {0},
                                    {0}
                                };
                                memcpy(&tus.source, &eth->h_source, 6);
                                memcpy(&tus.dest, &eth->h_dest, 6);
                                insert_tun(tus, tun_state_key);
                            }
                            else if(tustate){
                                tustate->tstamp = tstamp;
                                insert_tun(*tustate, tun_state_key);
                            }
                            struct ifindex_tun *tun_index = get_tun_index(0);
                            if(tun_index){
                                if(local_diag->verbose){
                                    memcpy(event.source, eth->h_source, 6);
                                    memcpy(event.dest, eth->h_dest, 6);
                                    event.tun_ifindex = tun_index->index;
                                    send_event(&event);
                                }
                                return bpf_redirect(tun_index->index, 0);
                            }
                        }
                    }
                    
                    for(int x = 0; x < MAX_IF_LIST_ENTRIES; x++){
                        if(tproxy->port_mapping[port_key].if_list[x] == skb->ifindex){
                            if(tproxy->port_mapping[port_key].tproxy_port == 0){
                                return TC_ACT_OK;
                            }
                            if(!local_diag->tun_mode){
                                sk = get_sk(key, skb, sockcheck);
                                if(!sk){
                                    return TC_ACT_SHOT;
                                }
                                if(!(key.protocol == IPPROTO_UDP) || local_diag->verbose){
                                    send_event(&event);
                                }
                                goto assign;
                            }else{
                                struct tun_key tun_state_key;
                                tun_state_key.daddr = tuple->ipv4.daddr;
                                tun_state_key.saddr = tuple->ipv4.saddr;
                                
                                unsigned long long tstamp = bpf_ktime_get_ns();
                                struct tun_state *tustate = get_tun(tun_state_key);
                                if((!tustate) || (tustate->tstamp > (tstamp + 30000000000))){
                                    struct tun_state tus = {
                                        tstamp,
                                        skb->ifindex,
                                        {0},
                                        {0}
                                    };
                                    memcpy(&tus.source, &eth->h_source, 6);
                                    memcpy(&tus.dest, &eth->h_dest, 6);
                                    insert_tun(tus, tun_state_key);
                                }
                                else if(tustate){
                                    tustate->tstamp = tstamp;
                                    insert_tun(*tustate, tun_state_key);
                                }
                                struct ifindex_tun *tun_index = get_tun_index(0);
                                if(tun_index){
                                    if(local_diag->verbose){
                                        memcpy(event.source, eth->h_source, 6);
                                        memcpy(event.dest, eth->h_dest, 6);
                                        event.tun_ifindex = tun_index->index;
                                        send_event(&event);
                                    }
                                    return bpf_redirect(tun_index->index, 0);
                                }
                            }
                        }
                    }

                    if(skb->ifindex == 1){
                        event.error_code = IF_LIST_MATCH_ERROR;
                        send_event(&event);
                        return TC_ACT_OK;
                    }
                    else{
                        event.error_code = IF_LIST_MATCH_ERROR;
                        send_event(&event);
                        return TC_ACT_SHOT;
                    }
                }
            }
        }
    }
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }
    assign:
    /*attempt to splice the skb to the tproxy or local socket*/
    ret = bpf_sk_assign(skb, sk, 0);
    /*release sk*/
    bpf_sk_release(sk);
    if(ret == 0){
        //if succedded forward to the stack
        return TC_ACT_OK;
    }
    /*else drop packet if not running on loopback*/
    if(skb->ingress_ifindex == 1){
        return TC_ACT_OK;
    }else{
        return TC_ACT_SHOT;
    }
}

SEC("license") const char __license[] = "Dual BSD/GPL";
