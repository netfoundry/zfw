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
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <stdio.h>

#define MAX_IF_ENTRIES                30
#define BPF_MAX_SESSIONS              10000
#define IP_HEADER_TOO_BIG             1
#define NO_IP_OPTIONS_ALLOWED         2
#define IP_TUPLE_TOO_BIG              8
#define EGRESS                        1
#define CLIENT_SYN_RCVD               7
#define CLIENT_FIN_RCVD               8
#define CLIENT_RST_RCVD               9
#define TCP_CONNECTION_ESTABLISHED    10
#define CLIENT_FINAL_ACK_RCVD         11
#define CLIENT_INITIATED_UDP_SESSION  12


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

/*Key to tcp_map and udp_map*/
struct tuple_key {
    __u32 daddr;
    __u32 saddr;
    __u16 sport;
    __u16 dport;
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

//map to keep status of diagnostic rules
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(struct diag_ip4));
    __uint(max_entries, MAX_IF_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} diag_map SEC(".maps");

/*Hashmap to track outbound passthrough TCP connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct tcp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_map SEC(".maps");

/*Hashmap to track outbound passthrough UDP connections*/
struct {
     __uint(type, BPF_MAP_TYPE_LRU_HASH);
     __uint(key_size, sizeof(struct tuple_key));
     __uint(value_size,sizeof(struct udp_state));
     __uint(max_entries, BPF_MAX_SESSIONS);
     __uint(pinning, LIBBPF_PIN_BY_NAME);
} udp_map SEC(".maps");

/*Ringbuf map*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb_map SEC(".maps");

/*Insert entry into tcp state table*/
static inline void insert_tcp(struct tcp_state tstate, struct tuple_key key){
     bpf_map_update_elem(&tcp_map, &key, &tstate,0);
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

static inline struct diag_ip4 *get_diag_ip4(__u32 key){
    struct diag_ip4 *if_diag;
    if_diag = bpf_map_lookup_elem(&diag_map, &key);

	return if_diag;
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
        bpf_ringbuf_submit(rb_event, 0);
    }
}

/* function to determine if an incoming packet is a udp/tcp IP tuple
* or not.  If not returns NULL.  If true returns a struct bpf_sock_tuple
* from the combined IP SA|DA and the TCP/UDP SP|DP. 
*/
static struct bpf_sock_tuple *get_tuple(struct __sk_buff *skb, __u64 nh_off,
    __u16 eth_proto, bool *ipv4, bool *ipv6, bool *udp, bool *tcp, bool *arp, bool *icmp, struct bpf_event *event,struct diag_ip4 *local_diag){
    struct bpf_sock_tuple *result;
    __u8 proto = 0;
    
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
            if(local_diag->verbose){
                event->error_code = IP_HEADER_TOO_BIG;
                send_event(event);
            }
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
            *udp = true;
        }
        /* check if ip protocol is TCP */
        if (proto == IPPROTO_TCP) {
            *tcp = true;
        }
        if(proto == IPPROTO_ICMP){
            *icmp = true;
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

//ebpf tc code entry program
SEC("action")
int bpf_sk_splice(struct __sk_buff *skb){
    struct bpf_sock *sk;
    struct bpf_sock_tuple *tuple, reverse_tuple = {0};
    int tuple_len;
    bool ipv4 = false;
    bool ipv6 = false;
    bool udp=false;
    bool tcp=false;
    bool arp=false;
    bool icmp=false;
    struct tuple_key tcp_state_key;
    struct tuple_key udp_state_key;

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

    /* find ethernet header from skb->data pointer */
    struct ethhdr *eth = (struct ethhdr *)(unsigned long)(skb->data);
    /* verify its a valid eth header within the packet bounds */
    if ((unsigned long)(eth + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
	}

    /* check if incoming packet is a UDP or TCP tuple */
    tuple = get_tuple(skb, sizeof(*eth), eth->h_proto, &ipv4,&ipv6, &udp, &tcp, &arp, &icmp, &event, local_diag);

    /* if not tuple forward */
    if (!tuple){
        return TC_ACT_OK;
    }

    /* determine length of tuple */
    tuple_len = sizeof(tuple->ipv4);
    if ((unsigned long)tuple + tuple_len > (unsigned long)skb->data_end){
       return TC_ACT_SHOT;
    }
    event.saddr = tuple->ipv4.saddr;
    event.daddr = tuple->ipv4.daddr;
    event.sport = tuple->ipv4.sport;
    event.dport = tuple->ipv4.dport;

    /* if tcp based tuple implement stateful inspection to see if they were
     * initiated by the local OS if not then its passthrough traffic and so wee need to
     * setup our own state to track the outbound pass through connections in via shared hashmap
    * with with ingress tc program*/
    if(tcp){
        event.proto = IPPROTO_TCP;
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
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
        tcp_state_key.daddr = tuple->ipv4.daddr;
        tcp_state_key.saddr = tuple->ipv4.saddr;
        tcp_state_key.sport = tuple->ipv4.sport;
        tcp_state_key.dport = tuple->ipv4.dport;
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
        struct iphdr *iph = (struct iphdr *)(skb->data + sizeof(*eth));
        if ((unsigned long)(iph + 1) > (unsigned long)skb->data_end){
            return TC_ACT_SHOT;
        }
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
            udp_state_key.daddr = tuple->ipv4.daddr;
            udp_state_key.saddr = tuple->ipv4.saddr;
            udp_state_key.sport = tuple->ipv4.sport;
            udp_state_key.dport = tuple->ipv4.dport;
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
    return TC_ACT_OK;
}
SEC("license") const char __license[] = "Dual BSD/GPL";
