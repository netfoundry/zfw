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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <argp.h>
#include <linux/socket.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>

#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES 100 // MAX # PREFIXES
#endif
#define BPF_MAX_RANGES 250000
#define MAX_INDEX_ENTRIES 100 // MAX port ranges per prefix
#define MAX_TABLE_SIZE 65536  // PORT Mapping table size
#define MAX_IF_LIST_ENTRIES 3
#define MAX_IF_ENTRIES 256
#define MAX_ADDRESSES 10
#define IP_HEADER_TOO_BIG 1
#define NO_IP_OPTIONS_ALLOWED 2
#define UDP_HEADER_TOO_BIG 3
#define GENEVE_HEADER_TOO_BIG 4
#define GENEVE_HEADER_LENGTH_VERSION_ERROR 5
#define SKB_ADJUST_ERROR 6
#define ICMP_HEADER_TOO_BIG 7
#define IP_TUPLE_TOO_BIG 8
#define IF_LIST_MATCH_ERROR 9
#define NO_REDIRECT_STATE_FOUND 10
#define INGRESS 0
#define EGRESS 1
#define SERVER_SYN_ACK_RCVD 1
#define SERVER_FIN_RCVD 2
#define SERVER_RST_RCVD 3
#define SERVER_FINAL_ACK_RCVD 4
#define UDP_MATCHED_EXPIRED_STATE 5
#define UDP_MATCHED_ACTIVE_STATE 6
#define CLIENT_SYN_RCVD 7
#define CLIENT_FIN_RCVD 8
#define CLIENT_RST_RCVD 9
#define TCP_CONNECTION_ESTABLISHED 10
#define CLIENT_FINAL_ACK_RCVD 11
#define CLIENT_INITIATED_UDP_SESSION 12
#define ICMP_INNER_IP_HEADER_TOO_BIG 13
#define INGRESS_INITIATED_UDP_SESSION 14
#define INGRESS_UDP_MATCHED_EXPIRED_STATE 15
#define INGRESS_UDP_MATCHED_ACTIVE_STATE 16
#define INGRESS_CLIENT_SYN_RCVD 17
#define INGRESS_CLIENT_FIN_RCVD 18
#define INGRESS_CLIENT_RST_RCVD 19
#define INGRESS_TCP_CONNECTION_ESTABLISHED 20
#define INGRESS_CLIENT_FINAL_ACK_RCVD 21
#define INGRESS_SERVER_SYN_ACK_RCVD 22
#define INGRESS_SERVER_FIN_RCVD 23
#define INGRESS_SERVER_RST_RCVD 24
#define INGRESS_SERVER_FINAL_ACK_RCVD 25
#define MATCHED_DROP_FILTER 26
#define ICMP_MATCHED_EXPIRED_STATE 27
#define ICMP_MATCHED_ACTIVE_STATE 28
#define CLIENT_INITIATED_ICMP_ECHO 29
#define IP6_HEADER_TOO_BIG 30
#define IPV6_TUPLE_TOO_BIG 31
#define REVERSE_MASQUERADE_ENTRY_REMOVED 32
#define MASQUERADE_ENTRY_REMOVED 33
#define REVERSE_MASQUERADE_ENTRY_ADDED 34
#define MASQUERADE_ENTRY_ADDED 35
#define MASQUERADE_NO_FREE_TCP_SRC_PORTS_FOUND 36
#define MASQUERADE_NO_FREE_UDP_SRC_PORTS_FOUND 37
#define DNP3_FUNCTION_CODE_BLOCKED 38
#define MODBUS_STATE_NOT_FOUND 39
#define DNP3_DIRECTION_BIT_SET 40
#define DNP3_FUNCTION_CODE_MATCHED 41
#define MODBUS_STATE_FOUND 42
#define MODBUS_STATE_INSERTED 43

bool ddos = false;
bool add = false;
bool bind_saddr = false;
bool unbind_saddr = false;
bool user_rules = false;
bool delete = false;
bool list = false;
bool list_gc = false;
bool flush = false;
bool lpt = false;
bool hpt = false;
bool tpt = false;
bool dl = false;
bool sl = false;
bool cd = false;
bool cd6 = false;
bool cs = false;
bool cs6 = false;
bool prot = false;
bool non_tuple = false;
bool route = false;
bool passthru = false;
bool intercept = false;
bool bind_flush = false;
bool masquerade = false;
bool echo = false;
bool eapol = false;
bool verbose = false;
bool vrrp = false;
bool per_interface = false;
bool outbound = false;
bool interface = false;
bool disable = false;
bool egress = false;
bool all_interface = false;
bool ssh_disable = false;
bool tc = false;
bool tcfilter = false;
bool init_tc = false;
bool init_xdp = false;
bool direction = false;
bool object;
bool ebpf_disable = false;
bool list_diag = false;
bool monitor = false;
bool tun = false;
bool ot_filter = false;
bool logging = false;
bool dsip = false;
bool ddos_saddr_list = false;
bool ddport = false;
bool dnp3fc = false;
bool ddos_dport_list = false;
bool dnp3_fcode_list = false;
bool service = false;
bool v6 = false;
bool ipv6 = false;
bool ingress = false;
char *service_string;
char *ddos_saddr;
char *ddos_dport;
char *dnp3_fcode;
struct in_addr ddos_scidr;
struct in_addr dcidr;
struct in_addr scidr;
struct in6_addr dcidr6;
struct in6_addr scidr6;
__u8 dplen;
__u8 splen;
unsigned short low_port;
unsigned short high_port;
unsigned short tproxy_port;
char *program_name;
char *protocol_name;
__u8 protocol;
union bpf_attr if_map;
int if_fd = -1;
union bpf_attr if6_map;
int if6_fd = -1;
union bpf_attr ddos_saddr_map;
int ddos_saddr_fd = -1;
union bpf_attr bind_saddr_map;
int bind_saddr_fd = -1;
union bpf_attr ddos_dport_map;
int ddos_dport_fd = -1;
union bpf_attr dnp3_fcode_map;
int dnp3_fcode_fd = -1;
union bpf_attr diag_map;
int diag_fd = -1;
union bpf_attr tun_map;
int tun_fd = -1;
union bpf_attr rb_map;
int rb_fd = -1;
union bpf_attr tp_ext_map;
int tp_ext_fd = -1;
union bpf_attr egress_ext_map;
int egress_ext_fd = -1;
union bpf_attr if_list_ext_map;
int if_list_ext_fd = -1;
union bpf_attr egress_if_list_ext_map;
int egress_if_list_ext_fd = -1;
union bpf_attr range_map;
int range_fd = -1;
union bpf_attr egress_range_map;
int egress_range_fd = -1;

const char *tproxy_map_path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
const char *tproxy6_map_path = "/sys/fs/bpf/tc/globals/zt_tproxy6_map";
const char *count_map_path = "/sys/fs/bpf/tc/globals/tuple_count_map";
const char *count6_map_path = "/sys/fs/bpf/tc/globals/tuple6_count_map";
const char *diag_map_path = "/sys/fs/bpf/tc/globals/diag_map";
const char *if_map_path = "/sys/fs/bpf/tc/globals/ifindex_ip_map";
const char *if6_map_path = "/sys/fs/bpf/tc/globals/ifindex_ip6_map";
const char *matched6_map_path ="/sys/fs/bpf/tc/globals/matched6_map";
const char *matched_map_path = "/sys/fs/bpf/tc//globals/matched_map";
const char *egress_matched6_map_path ="/sys/fs/bpf/tc/globals/egress_matched6_map";
const char *egress_matched_map_path = "/sys/fs/bpf/tc//globals/egress_matched_map";
const char *tcp_map_path = "/sys/fs/bpf/tc/globals/tcp_map";
const char *tcp_ingress_map_path = "/sys/fs/bpf/tc/globals/tcp_ingress_map";
const char *udp_map_path = "/sys/fs/bpf/tc/globals/udp_map";
const char *udp_ingress_map_path = "/sys/fs/bpf/tc/globals/udp_ingress_map";
const char *tun_map_path = "/sys/fs/bpf/tc/globals/tun_map";
const char *if_tun_map_path = "/sys/fs/bpf/tc/globals/ifindex_tun_map";
const char *transp_map_path = "/sys/fs/bpf/tc/globals/zet_transp_map";
const char *rb_map_path = "/sys/fs/bpf/tc/globals/rb_map";
const char *ddos_saddr_map_path = "/sys/fs/bpf/tc/globals/ddos_saddr_map";
const char *ddos_dport_map_path = "/sys/fs/bpf/tc/globals/ddos_dport_map";
const char *dnp3_fcode_map_path = "/sys/fs/bpf/tc/globals/dnp3_fcode_map";
const char *syn_count_map_path = "/sys/fs/bpf/tc/globals/syn_count_map";
const char *tp_ext_map_path = "/sys/fs/bpf/tc/globals/tproxy_extension_map";
const char *if_list_ext_map_path = "/sys/fs/bpf/tc/globals/if_list_extension_map";
const char *wildcard_port_map_path = "/sys/fs/bpf/tc/globals/wildcard_port_map";
const char *range_map_path = "/sys/fs/bpf/tc/globals/range_map";
const char *egress_range_map_path = "/sys/fs/bpf/tc/globals/egress_range_map";
const char *egress_if_list_ext_map_path = "/sys/fs/bpf/tc/globals/egress_if_list_extension_map";
const char *egress_ext_map_path = "/sys/fs/bpf/tc/globals/egress_extension_map";
const char *egress_map_path = "/sys/fs/bpf/tc/globals/zt_egress_map";
const char *egress6_map_path = "/sys/fs/bpf/tc/globals/zt_egress6_map";
const char *egress_count_map_path = "/sys/fs/bpf/tc/globals/egress_count_map";
const char *egress_count6_map_path = "/sys/fs/bpf/tc/globals/egress6_count_map";
const char *masquerade_map_path = "/sys/fs/bpf/tc/globals/masquerade_map";
const char *masquerade_reverse_map_path = "/sys/fs/bpf/tc/globals/masquerade_reverse_map";
const char *icmp_masquerade_map_path = "/sys/fs/bpf/tc/globals/icmp_masquerade_map";
const char *bind_saddr_map_path = "/sys/fs/bpf/tc/globals/bind_saddr_map";
const char *icmp_echo_map_path = "/sys/fs/bpf/tc/globals/icmp_echo_map";
const char *modbus_state_map_path = "/sys/fs/bpf/tc/globals/modbus_state_map";
char doc[] = "zfw -- ebpf firewall configuration tool";
const char *if_map_path;
char *diag_interface;
char *echo_interface;
char *eapol_interface;
char *verbose_interface;
char *ssh_interface;
char *prefix_interface;
char *nt_interface;
char *tun_interface;
char *vrrp_interface;
char *ddos_interface;
char *outbound_interface;
char *monitor_interface;
char *ipv6_interface;
char *tc_interface;
char *ot_interface;
char *xdp_interface;
char *log_file_name;
char *object_file;
char *direction_string;
char *masq_interface;
char check_alt[IF_NAMESIZE];

const char *argp_program_version = "0.9.21";
struct ring_buffer *ring_buffer;

__u32 if_list[MAX_IF_LIST_ENTRIES];
struct interface
{
    uint32_t index;
    char *name;
    uint16_t addr_count;
    uint32_t addresses[MAX_ADDRESSES];
};

/*Key to bind_map*/
struct bind_key {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_dest;
    __u8 mask;
    __u8 type;
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

/*value to masquerade_map and icmp_masquerade_map*/
struct masq_value {
    union {
        __u32 ip;
        __u32 ip6[4];
    }__in46_u_origin;
    __u16 o_sport;
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

/*Key to tcp_map/udp_map*/
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
    __u32 ifindex;
    __u8 type;
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

struct interface6
{
    uint32_t index;
    char *name;
    uint16_t addr_count;
    uint32_t addresses[MAX_ADDRESSES][4];
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
    __u8 type;
};

struct if_list_extension_mapping
{
    __u32 if_list[MAX_IF_LIST_ENTRIES];
};

int ifcount = 0;
int get_key_count();
void interface_tc();
int add_if_index(struct interface intf);
int add_if6_index(struct interface6 intf);
void open_diag_map();
void open_if_map();
void open_if6_map();
void open_rb_map();
void open_tun_map();
void open_egress_range_map();
void open_ddos_saddr_map();
void open_ddos_dport_map();
void open_dnp3_fcode_map();
void delete_dnp3_fcode_map(char *fcode);
void dnp3_fcode_map_flush();
void open_tproxy_ext_map();
void open_egress_ext_map();
void open_if_list_ext_map();
void open_egress_if_list_ext_map();
void open_bind_saddr_map();
void map_insert6();
void map_delete6();
void map_insert();
int flush4();
int flush6();
void open_range_map();
void if_list_ext_delete_key(struct port_extension_key key);
bool interface_map();
void interface_map6();
int get_key_count6();
void close_maps(int code);
void if_delete_key(uint32_t key);
void if6_delete_key(uint32_t key);
void diag_delete_key(uint32_t key);
char *get_ts(unsigned long long tstamp);

struct tproxy_extension_mapping
{
    char service_id[23];
};

struct tproxy_extension_key
{
    __u16 tproxy_port;
    __u8 protocol;
    __u8 pad;
};

struct ifindex_ip4
{
    uint32_t ipaddr[MAX_ADDRESSES];
    char ifname[IF_NAMESIZE];
    uint8_t count;
};

/*value to ifindex_ip6_map*/
struct ifindex_ip6
{
    char ifname[IF_NAMESIZE];
    uint32_t ipaddr[MAX_ADDRESSES][4];
    uint8_t count;
};

/*value to ifindex_tun_map*/
struct ifindex_tun
{
    uint32_t index;
    char ifname[IF_NAMESIZE];
    char cidr[16];
    uint32_t resolver;
    char mask[3];
    bool verbose;
};

struct bpf_event
{
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
    bool pass_non_tuple;
    bool ot_filtering;
};

struct tproxy_tuple
{
    __u16 index_len;
    __u16 index_table[MAX_INDEX_ENTRIES];
};

struct range_mapping {
    __u16 high_port;
    __u16 tproxy_port;
    bool deny;
};

struct tproxy_key
{
    __u32 dst_ip;
    __u32 src_ip;
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

/*key to zt_tproxy_map6*/
struct tproxy6_key
{
    __u32 dst_ip[4];
    __u32 src_ip[4];
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

void INThandler(int sig)
{
    signal(sig, SIG_IGN);
    if (ring_buffer)
    {
        ring_buffer__free(ring_buffer);
    }
    close_maps(1);
}

void ebpf_usage()
{
    if (access(tproxy_map_path, F_OK) != 0)
    {
        printf("Not enough privileges or ebpf not enabled!\n");
        printf("Run as \"sudo\" with ingress tc filter [filter -X, --set-tc-filter] set on at least one interface\n");
        close_maps(1);
    }
}

int check_qdisc(char *ifname){
    FILE *fp;
    char path[2048];
    char command[300];
    snprintf(command, 300, "/usr/sbin/tc qdisc show dev %s clsact", ifname);
    fp = popen(command, "r");
    if(!fp){
        return 1;
    }
    int count = 0;
    while(fgets(path, sizeof(path), fp) !=NULL){
        count++;
    }
    if(!count){
        pclose(fp);
        return 1;
    }
    pclose(fp);
    return 0;
}

int check_filter(uint32_t idx, char *direction){
    char ifname[IF_NAMESIZE];
    if(!if_indextoname(idx, ifname)){
        return 1;
    }
    FILE *fp;
    char path[2048];
    char command[300];
    snprintf(command, 300, "/usr/sbin/tc filter show dev %s %s", ifname, direction);
    fp = popen(command, "r");
    if(!fp){
        return 1;
    }
    int count = 0;
    while(fgets(path, sizeof(path), fp) !=NULL){
        count++;
    }
    if(!count){
        pclose(fp);
        return 1;
    }
    pclose(fp);
    return 0;
}

/*function to add loopback binding for intercept IPv4 prefixes that do not
 * currently exist as a subset of an external interface
 * */
void bind_prefix(struct in_addr *address, unsigned short mask)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("binding route %s to loopback\n", cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "addr", "add", cidr_block, "dev", "lo", "scope", "host", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn bind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error binding");
    }
    free(cidr_block);
}

/*function to add loopback binding for intercept IPv6 prefixes that*/
void bind6_prefix(struct in6_addr *address, unsigned short mask)
{
    char prefix[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, address, prefix, INET6_ADDRSTRLEN);
    char cidr_block[44];
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("binding route %s to loopback\n", cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "addr", "add", cidr_block, "dev", "lo", "scope", "host", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn bind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error binding");
    }
}

/*function to add loopback binding for intercept IPv6 prefixes that*/
void unbind6_prefix(struct in6_addr *address, unsigned short mask)
{
    char prefix[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, address, prefix, INET6_ADDRSTRLEN);
    char cidr_block[44];
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("unbinding route %s from loopback\n", cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "addr", "delete", cidr_block, "dev", "lo", "scope", "host", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn unbind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error unbinding");
    }
}

/*Unbind IPv4 prefixes from lo*/
void unbind_prefix(struct in_addr *address, unsigned short mask)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("unbinding route %s from loopback\n", cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "addr", "delete", cidr_block, "dev", "lo", "scope", "host", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn unbind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error unbinding");
    }
    free(cidr_block);
}

void set_tc(char *action)
{
    if (access("/usr/sbin/tc", F_OK) != 0)
    {
        printf("tc not installed\n");
        close_maps(0);
    }
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/tc", "qdisc", action, "dev", tc_interface, "clsact", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn bind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/tc", parmList);
        printf("execv error: unknown error binding\n");
    }
    else
    {
        int status = 0;
        if(!(waitpid(pid, &status, 0) < 0))
        {
            if(!(WIFEXITED(status) && !WEXITSTATUS(status)))
            {
                printf("waitpid error: could not set tc parent %s : %s\n", action, tc_interface);
            }
        }
    }
}

int set_tc_filter(char *action)
{
    if (access("/usr/sbin/tc", F_OK) != 0)
    {
        printf("tc not installed\n");
        close_maps(1);
    }
    if (!strcmp("add", action) && access(object_file, F_OK) != 0)
    {
        printf("object file %s not in path\n", object_file);
        close_maps(1);
    }
    pid_t pid;
    int o_std_out = dup(STDOUT_FILENO);
    int o_std_err = dup(STDERR_FILENO);
    int fd = open("/dev/null", O_WRONLY);
    if (fd == -1){
        return 1; 
    }
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    if (!strcmp(action, "add") && check_filter(if_nametoindex(tc_interface),direction_string))
    {
        if(check_qdisc(tc_interface)){
            set_tc(action);
        }
        for (int x = 0; x < 7; x++)
        {
            char prio[10];
            sprintf(prio, "%d", x + 1);
            char section[10];
            if (x == 0)
            {
                sprintf(section, "action");
            }
            else
            {
                sprintf(section, "action/%d", x);
            }
            char *const parmList[] = {"/usr/sbin/tc", "filter", action, "dev", tc_interface, direction_string, "prio", prio, "bpf",
                                      "da", "obj", object_file, "sec", section, NULL};
            if ((pid = fork()) == -1)
            {
                perror("fork error: can't attach filter");
            }
            else if (pid == 0)
            {
                execv("/usr/sbin/tc", parmList);
                printf("execv error: unknown error attaching filter\n");
            }
            else
            {
                int status = 0;
                if(!(waitpid(pid, &status, 0) < 0))
                {
                    if(!(WIFEXITED(status) && !WEXITSTATUS(status)))
                    {
                        printf("waitpid error: tc %s filter not set : %s section: %s\n", direction_string, tc_interface, section);
                        set_tc("del");
                        dup2(o_std_out, STDOUT_FILENO);
                        dup2(o_std_err, STDERR_FILENO);
                        close(o_std_out);
                        close(o_std_err); 
                        return 1;
                    }
                }
            }
        }
    }
    else if(!strcmp(action, "del"))
    {
        char *const parmList[] = {"/usr/sbin/tc", "filter", action, "dev", tc_interface, direction_string, NULL};
        if ((pid = fork()) == -1)
        {
            perror("fork error: can't remove filter");
        }
        else if (pid == 0)
        {
            execv("/usr/sbin/tc", parmList);
            printf("execv error: unknown error removing filter");
        }
    }
    dup2(o_std_out, STDOUT_FILENO);
    dup2(o_std_err, STDERR_FILENO);
    close(o_std_out);
    close(o_std_err); 
    return 0;
}

void disable_ebpf()
{
    all_interface = true;
    disable = true;
    tc = true;
    interface_tc();
    const char *maps[40] = {tproxy_map_path, diag_map_path, if_map_path, count_map_path,
                            udp_map_path, matched_map_path, tcp_map_path, tun_map_path, if_tun_map_path,
                            transp_map_path, rb_map_path, ddos_saddr_map_path, ddos_dport_map_path, syn_count_map_path,
                            tp_ext_map_path, if_list_ext_map_path, range_map_path, wildcard_port_map_path, tproxy6_map_path,
                             if6_map_path, count6_map_path, matched6_map_path, egress_range_map_path, egress_if_list_ext_map_path,
                             egress_ext_map_path, egress_map_path, egress6_map_path, egress_count_map_path, egress_count6_map_path,
                             egress_matched6_map_path, egress_matched_map_path, udp_ingress_map_path, tcp_ingress_map_path, 
                             masquerade_map_path, icmp_masquerade_map_path, icmp_echo_map_path, masquerade_reverse_map_path,
                              bind_saddr_map_path, dnp3_fcode_map_path, modbus_state_map_path};
    for (int map_count = 0; map_count < 40; map_count++)
    {

        int stat = remove(maps[map_count]);
        if (!stat)
        {
            printf("removing %s\n", maps[map_count]);
        }
        else
        {
            printf("file does not exist: %s\n", maps[map_count]);
        }
    }
}

uint32_t bits2Mask(int bits)
{
    uint32_t mask = __UINT32_MAX__ << (32 - bits);
    return mask;
}

/*function to check if prefix is subset of interface subnet*/
int is_subset(__u32 network, __u32 netmask, __u32 prefix)
{
    if ((network & netmask) == (prefix & netmask))
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

/* convert string port to unsigned short int */
unsigned short port2s(char *port)
{
    char *endPtr;
    int32_t tmpint = strtol(port, &endPtr, 10);
    if ((tmpint < 0) || (tmpint > 65535) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Port: %s\n", port);
        close_maps(1);
    }
    unsigned short usint = (unsigned short)tmpint;
    return usint;
}

/* convert string protocol to __u8 */
__u8 proto2u8(char *protocol)
{
    char *endPtr;
    int32_t tmpint = strtol(protocol, &endPtr, 10);
    if ((tmpint <= 0) || (tmpint > 255) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Protocol: %s\n", protocol);
        close_maps(1);
    }
    __u8 usint = (__u8)tmpint;
    return usint;
}

/*convert integer ip to dotted decimal string*/
char *nitoa(uint32_t address)
{
    char *ipaddr = malloc(16);
    int b0 = (address & 0xff000000) >> 24;
    int b1 = (address & 0xff0000) >> 16;
    int b2 = (address & 0xff00) >> 8;
    int b3 = address & 0xff;
    sprintf(ipaddr, "%d.%d.%d.%d", b0, b1, b2, b3);
    return ipaddr;
}

/* convert prefix string to __u16 */
__u16 len2u16(char *len)
{
    char *endPtr;
    int32_t tmpint = strtol(len, &endPtr, 10);
    if ((tmpint < 0) || (tmpint > 255) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Prefix Length: %s\n", len);
        close_maps(1);
    }
    __u16 u16int = (__u16)tmpint;
    return u16int;
}

/* convert prefix string to __u16 */
__u8 fcode2u8(char *fcode)
{
    char *endPtr;
    int32_t tmpint = strtol(fcode, &endPtr, 10);
    if ((tmpint < 0) || (tmpint > 255) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid fcode: %s\n", fcode);
        close_maps(1);
    }
    __u8 u8int = (__u8)tmpint;
    return u8int;
}

/* function to add a UDP or TCP port range to a tproxy mapping */
void add_index(__u16 index, struct tproxy_tuple *tuple)
{
    bool is_new = true;
    for (int x = 0; x < tuple->index_len; x++)
    {
        if (tuple->index_table[x] == index)
        {
            is_new = false;
        }
    }
    if (is_new)
    {
        if (tuple->index_len < MAX_INDEX_ENTRIES)
        {
            tuple->index_table[tuple->index_len] = index;
            tuple->index_len += 1;
        }
        else
        {
            printf("max port mapping ranges (%d) reached\n", MAX_INDEX_ENTRIES);
            return;
        }
    }
}

void remove_index(__u16 index, struct tproxy_tuple *tuple)
{
    bool found = false;
    int x = 0;
    for (; x < tuple->index_len; x++)
    {
        if (tuple->index_table[x] == index)
        {
            found = true;
            break;
        }
    }
    if (found)
    {
        for (; x < tuple->index_len - 1; x++)
        {
            tuple->index_table[x] = tuple->index_table[x + 1];
        }
        tuple->index_len -= 1;
        printf("mapping[%d] removed\n", ntohs(index));
    }
    else
    {
        printf("mapping[%d] does not exist\n", ntohs(index));
    }
}

void print_rule6(struct tproxy6_key *key, struct tproxy_tuple *tuple, int *rule_count)
{
    if (if6_fd == -1)
    {
        open_if6_map();
    }
    if (tun_fd == -1)
    {
        open_tun_map();
    }
    if (tp_ext_fd == -1)
    {
        open_tproxy_ext_map();
    }
    if (egress_ext_fd == -1)
    {
        open_egress_ext_map();
    }
    if (if_list_ext_fd == -1)
    {
        open_if_list_ext_map();
    }
    if (egress_if_list_ext_fd == -1)
    {
        open_egress_if_list_ext_map();
    }
    if (range_fd == -1)
    {
        open_range_map();
    }
    if (egress_range_fd == -1)
    {
        open_egress_range_map();
    }
    uint32_t tun_key = 0;
    struct ifindex_tun o_tunif;
    tun_map.map_fd = tun_fd;
    tun_map.key = (uint64_t)&tun_key;
    tun_map.value = (uint64_t)&o_tunif;
    bool tun_mode = false;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tun_map, sizeof(tun_map));
    if (!lookup)
    {
        if (o_tunif.index != 0)
        {
            tun_mode = true;
        }
    }
    uint32_t if_key = 0;
    if6_map.map_fd = if6_fd;
    if6_map.key = (uint64_t)&if_key;
    char *proto;
    if (key->protocol == IPPROTO_UDP)
    {
        proto = "udp";
    }
    else if (key->protocol == IPPROTO_TCP)
    {
        proto = "tcp";
    }
    else
    {
        proto = "unknown";
    }
    union bpf_attr *if_list_map = NULL;
    union bpf_attr *ext_map = NULL;
    union bpf_attr *port_range_map = NULL;
    if(!egress){
        ext_map = &tp_ext_map;
        ext_map->map_fd = tp_ext_fd;
        if_list_map = &if_list_ext_map;
        if_list_map->map_fd = if_list_ext_fd;
        port_range_map = &range_map;
        port_range_map->map_fd = range_fd;
    }else{
        ext_map = &egress_ext_map;
        ext_map->map_fd = egress_ext_fd;
        if_list_map = &egress_if_list_ext_map;
        if_list_map->map_fd = egress_if_list_ext_fd;
        port_range_map = &egress_range_map;
        port_range_map->map_fd = egress_range_fd;
    }
    struct tproxy_extension_key ext_key = {0};
    ext_map->key = (uint64_t)&ext_key;
    struct tproxy_extension_mapping ext_value;
    ext_map->value = (uint64_t)&ext_value;
    
    ext_map->flags = BPF_ANY;
    ext_key.protocol = key->protocol;
    ext_key.pad = 0;

    struct port_extension_key port_ext_key = {0};
    if_list_map->key = (uint64_t)&port_ext_key;
    struct if_list_extension_mapping if_ext_value;
    if_list_map->value = (uint64_t)&if_ext_value;
    if_list_map->flags = BPF_ANY;

    memcpy(port_ext_key.__in46_u_dst.ip6, key->dst_ip, sizeof(key->dst_ip));
    memcpy(port_ext_key.__in46_u_src.ip6, key->src_ip, sizeof(key->src_ip));
    port_ext_key.dprefix_len = key->dprefix_len;
    port_ext_key.sprefix_len = key->sprefix_len;
    port_ext_key.protocol = key->protocol;
    port_ext_key.type = 6;
    char saddr6[INET6_ADDRSTRLEN];
    char daddr6[INET6_ADDRSTRLEN];
    struct in6_addr saddr_6 = {0};
    struct in6_addr daddr_6 = {0};
    memcpy(saddr_6.__in6_u.__u6_addr32, port_ext_key.__in46_u_src.ip6, sizeof(port_ext_key.__in46_u_src.ip6));
    memcpy(daddr_6.__in6_u.__u6_addr32, port_ext_key.__in46_u_dst.ip6, sizeof(port_ext_key.__in46_u_dst.ip6));
    inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &daddr_6, daddr6, INET6_ADDRSTRLEN);
    char dcidr_block[50];
    sprintf(dcidr_block, "%s/%d", daddr6, key->dprefix_len);
    char scidr_block[50];
    sprintf(scidr_block, "%s/%d", saddr6, key->sprefix_len);
    char dpts[17];
    int x = 0;

    port_range_map->key = (uint64_t)&port_ext_key;
    struct range_mapping range_value;
    port_range_map->value = (uint64_t)&range_value;
    port_range_map->flags = BPF_ANY;

    for (; x < tuple->index_len; x++)
    {
        __u16 port_key = tuple->index_table[x];
        port_ext_key.low_port = port_key;
        int range_lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, port_range_map, sizeof(*port_range_map));
        ext_key.tproxy_port = range_value.tproxy_port;
        int ext_lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, ext_map, sizeof(*ext_map));
        if (!range_lookup)
        {
            sprintf(dpts, "dpts=%d:%d", ntohs(port_key),
                    ntohs(range_value.high_port));
            int if_ext_lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, if_list_map, sizeof(*if_list_map));
            if (intercept && !passthru)
            {
                bool entry_exists = false;
                if (tun_mode && (ntohs(range_value.tproxy_port) > 0))
                {
                    printf("%-6s|%-22s|%-5s|%-42s|%-42s | %-17sTU:%-5s | ", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, o_tunif.ifname);
                    entry_exists = true;
                    *rule_count += 1;
                }
                else if (ntohs(range_value.tproxy_port) > 0)
                {
                    printf("%-6s|%-22s|%-5s|%-42s|%-42s | %-17sTP:%-5d | ", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, ntohs(range_value.tproxy_port));
                    entry_exists = true;
                    *rule_count += 1;
                }
                if(ntohs(range_value.tproxy_port) > 0){
                    char interfaces[IF_NAMESIZE * MAX_IF_LIST_ENTRIES + 8] = "";
                    if (!if_ext_lookup)
                    {
                        for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                        {
                            if (if_ext_value.if_list[i])
                            {
                                if_key = if_ext_value.if_list[i];
                                struct ifindex_ip6 ifip6;
                                if6_map.value = (uint64_t)&ifip6;
                                int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if6_map, sizeof(if6_map));
                                if (!lookup)
                                {
                                    strcat(interfaces, ifip6.ifname);
                                    strcat(interfaces, ",");
                                }
                            }
                        }
                    }
                    if (strlen(interfaces))
                    {
                        printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
                    }
                    else if (entry_exists)
                    {
                        printf("%s\n", "[]");
                    }
                }
            }
            else if (passthru && !intercept)
            {
                if (ntohs(range_value.tproxy_port) == 0)
                {
                    printf("%-6s|%-22s|%-5s|%-42s|%-42s | %-17s%-5s | ", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, "PASSTHRU");
                    char interfaces[IF_NAMESIZE * MAX_IF_LIST_ENTRIES + 8] = "";
                    if (!if_ext_lookup)
                    {
                        for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                        {
                            if (if_ext_value.if_list[i])
                            {
                                if_key = if_ext_value.if_list[i];
                                struct ifindex_ip6 ifip6;
                                if6_map.value = (uint64_t)&ifip6;
                                int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if6_map, sizeof(if6_map));
                                if (!lookup)
                                {
                                    strcat(interfaces, ifip6.ifname);
                                    strcat(interfaces, ",");
                                }
                            }
                        }
                    }
                    if (strlen(interfaces))
                    {
                        printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
                    }
                    else
                    {
                        printf("%s\n", "[]");
                    }
                    *rule_count += 1;
                }
            }
            else
            {
                if (tun_mode && (ntohs(range_value.tproxy_port) > 0))
                {
                    printf("%-6s|%-22s|%-5s|%-42s|%-42s | %-17sTU:%-5s | ", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, o_tunif.ifname);
                }
                else if (ntohs(range_value.tproxy_port) > 0)
                {
                    printf("%-6s|%-22s|%-5s|%-42s|%-42s | %-17sTP:%-5d | ", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, ntohs(range_value.tproxy_port));
                }
                else
                {
                    printf("%-6s|%-22s|%-5s|%-42s|%-42s | %-17s%-5s | ", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, "PASSTHRU");
                }
                char interfaces[IF_NAMESIZE * MAX_IF_LIST_ENTRIES + 8] = "";
                if (!if_ext_lookup)
                {
                    for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                    {
                        if (if_ext_value.if_list[i])
                        {
                            if_key = if_ext_value.if_list[i];
                            struct ifindex_ip6 ifip6;
                            if6_map.value = (uint64_t)&ifip6;
                            int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if6_map, sizeof(if6_map));
                            if (!lookup)
                            {
                                strcat(interfaces, ifip6.ifname);
                                strcat(interfaces, ",");
                            }
                        }
                    }
                }
                if (strlen(interfaces))
                {
                    printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
                }
                else
                {
                    printf("%s\n", "[]");
                }
                *rule_count += 1;
            }
        }
    }
}

void print_rule(struct tproxy_key *key, struct tproxy_tuple *tuple, int *rule_count)
{
    if (if_fd == -1)
    {
        open_if_map();
    }
    if (tun_fd == -1)
    {
        open_tun_map();
    }
    if (tp_ext_fd == -1)
    {
        open_tproxy_ext_map();
    }
    if (egress_ext_fd == -1)
    {
        open_egress_ext_map();
    }
    if (if_list_ext_fd == -1)
    {
        open_if_list_ext_map();
    }
    if (egress_if_list_ext_fd == -1)
    {
        open_egress_if_list_ext_map();
    }
    if (range_fd == -1)
    {
        open_range_map();
    }
    if (egress_range_fd == -1)
    {
        open_egress_range_map();
    }

    uint32_t tun_key = 0;
    struct ifindex_tun o_tunif;
    tun_map.map_fd = tun_fd;
    tun_map.key = (uint64_t)&tun_key;
    tun_map.value = (uint64_t)&o_tunif;
    bool tun_mode = false;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tun_map, sizeof(tun_map));
    if (!lookup)
    {
        if (o_tunif.index != 0)
        {
            tun_mode = true;
        }
    }
    uint32_t if_key = 0;
    if_map.map_fd = if_fd;
    if_map.key = (uint64_t)&if_key;
    char *proto;
    if (key->protocol == IPPROTO_UDP)
    {
        proto = "udp";
    }
    else if (key->protocol == IPPROTO_TCP)
    {
        proto = "tcp";
    }
    else
    {
        proto = "unknown";
    }
    char *dprefix = nitoa(ntohl(key->dst_ip));
    char *dcidr_block = malloc(19);
    sprintf(dcidr_block, "%s/%d", dprefix, key->dprefix_len);
    char *sprefix = nitoa(ntohl(key->src_ip));
    char *scidr_block = malloc(19);
    sprintf(scidr_block, "%s/%d", sprefix, key->sprefix_len);
    char *dpts = malloc(17);
    int x = 0;
    
    union bpf_attr *if_list_map = NULL;
    union bpf_attr *ext_map = NULL;
    union bpf_attr *port_range_map = NULL;
    if(!egress){
        ext_map = &tp_ext_map;
        ext_map->map_fd = tp_ext_fd;
        if_list_map = &if_list_ext_map;
        if_list_map->map_fd = if_list_ext_fd;
        port_range_map = &range_map;
        port_range_map->map_fd = range_fd;
    }else{
        ext_map = &egress_ext_map;
        ext_map->map_fd = egress_ext_fd;
        if_list_map = &egress_if_list_ext_map;
        if_list_map->map_fd = egress_if_list_ext_fd;
        port_range_map = &egress_range_map;
        port_range_map->map_fd = egress_range_fd;
    }
    struct tproxy_extension_key ext_key = {0};
    ext_map->key = (uint64_t)&ext_key;
    struct tproxy_extension_mapping ext_value;
    ext_map->value = (uint64_t)&ext_value;
    ext_map->flags = BPF_ANY;
    ext_key.protocol = key->protocol;
    ext_key.pad = 0;

    
    struct port_extension_key port_ext_key = {0};
    if_list_map->key = (uint64_t)&port_ext_key;
    struct if_list_extension_mapping if_ext_value;
    if_list_map->value = (uint64_t)&if_ext_value;
    if_list_map->flags = BPF_ANY;

    port_ext_key.__in46_u_dst.ip = key->dst_ip;
    port_ext_key.__in46_u_src.ip = key->src_ip;
    port_ext_key.dprefix_len = key->dprefix_len;
    port_ext_key.sprefix_len = key->sprefix_len;
    port_ext_key.protocol = key->protocol;
    port_ext_key.type = 4;
    port_range_map->key = (uint64_t)&port_ext_key;

    struct range_mapping range_value;
    port_range_map->value = (uint64_t)&range_value;
    port_range_map->flags = BPF_ANY;

    for (; x < tuple->index_len; x++)
    {
        __u16 port_key = tuple->index_table[x];
        port_ext_key.low_port = port_key;
        int range_lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, port_range_map, sizeof(*port_range_map));
        ext_key.tproxy_port = range_value.tproxy_port;
        int ext_lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, ext_map, sizeof(*ext_map));
        if (!range_lookup)
        {
            sprintf(dpts, "dpts=%d:%d", ntohs(port_key),
                    ntohs(range_value.high_port));
            int if_ext_lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, if_list_map, sizeof(*if_list_map));
            if (intercept && !passthru)
            {
                bool entry_exists = false;
                if (tun_mode && (ntohs(range_value.tproxy_port) > 0))
                {
                    printf("%-6s %-22s\t%-3s\t%-20s\t%-32s%-17s\tTUNMODE redirect:%-15s", range_value.deny ? "deny" : "accept", ext_lookup ? "?" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, o_tunif.ifname);
                    entry_exists = true;
                    *rule_count += 1;
                }
                else if (ntohs(range_value.tproxy_port) > 0)
                {
                    printf("%-6s %-22s\t%-3s\t%-20s\t%-32s%-17s\tTPROXY redirect 127.0.0.1:%-6d", range_value.deny ? "deny" : "accept", ext_lookup ? "?" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, ntohs(range_value.tproxy_port));
                    entry_exists = true;
                    *rule_count += 1;
                }
                char interfaces[IF_NAMESIZE * MAX_IF_LIST_ENTRIES + 8] = "";
                if (!if_ext_lookup)
                {
                    for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                    {
                        if (if_ext_value.if_list[i])
                        {
                            if_key = if_ext_value.if_list[i];
                            struct ifindex_ip4 ifip4;
                            if_map.value = (uint64_t)&ifip4;
                            int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if_map, sizeof(if_map));
                            if (!lookup)
                            {
                                strcat(interfaces, ifip4.ifname);
                                strcat(interfaces, ",");
                            }
                        }
                    }
                }
                if (strlen(interfaces))
                {
                    printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
                }
                else if (entry_exists)
                {
                    printf("%s\n", "[]");
                }
            }
            else if (passthru && !intercept)
            {
                if (ntohs(range_value.tproxy_port) == 0)
                {
                    printf("%-6s %-22s\t%-3s\t%-20s\t%-32s%-17s\t%s to %-20s", range_value.deny ? "deny" : "accept", ext_lookup ? "?" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, "PASSTHRU", dcidr_block);
                    char interfaces[IF_NAMESIZE * MAX_IF_LIST_ENTRIES + 8] = "";
                    if (!if_ext_lookup)
                    {
                        for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                        {
                            if (if_ext_value.if_list[i])
                            {
                                if_key = if_ext_value.if_list[i];
                                struct ifindex_ip4 ifip4;
                                if_map.value = (uint64_t)&ifip4;
                                int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if_map, sizeof(if_map));
                                if (!lookup)
                                {
                                    strcat(interfaces, ifip4.ifname);
                                    strcat(interfaces, ",");
                                }
                            }
                        }
                    }
                    if (strlen(interfaces))
                    {
                        printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
                    }
                    else
                    {
                        printf("%s\n", "[]");
                    }
                    *rule_count += 1;
                }
            }
            else
            {
                if (tun_mode && (ntohs(range_value.tproxy_port) > 0))
                {
                    printf("%-6s %-22s\t%-3s\t%-20s\t%-32s%-17s\tTUNMODE redirect:%-15s", range_value.deny ? "deny" : "accept", ext_lookup ? "?" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, o_tunif.ifname);
                }
                else if (ntohs(range_value.tproxy_port) > 0)
                {
                    printf("%-6s %-22s\t%-3s\t%-20s\t%-32s%-17s\tTPROXY redirect 127.0.0.1:%-6d", range_value.deny ? "deny" : "accept", ext_lookup ? "?" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, ntohs(range_value.tproxy_port));
                }
                else
                {
                    printf("%-6s %-22s\t%-3s\t%-20s\t%-32s%-17s\t%s to %-20s", range_value.deny ? "deny" : "accept", ext_lookup ? "" : ext_value.service_id, proto, scidr_block, dcidr_block,
                           dpts, "PASSTHRU", dcidr_block);
                }
                char interfaces[IF_NAMESIZE * MAX_IF_LIST_ENTRIES + 8] = "";
                if (!if_ext_lookup)
                {
                    for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                    {
                        if (if_ext_value.if_list[i])
                        {
                            if_key = if_ext_value.if_list[i];
                            struct ifindex_ip4 ifip4;
                            if_map.value = (uint64_t)&ifip4;
                            int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if_map, sizeof(if_map));
                            if (!lookup)
                            {
                                strcat(interfaces, ifip4.ifname);
                                strcat(interfaces, ",");
                            }
                        }
                    }
                }
                if (strlen(interfaces))
                {
                    printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
                }
                else
                {
                    printf("%s\n", "[]");
                }
                *rule_count += 1;
            }
        }
    }
    free(dpts);
    free(dcidr_block);
    free(dprefix);
    free(scidr_block);
    free(sprefix);
}

void usage(char *message)
{
    fprintf(stderr, "%s : %s\n", program_name, message);
    fprintf(stderr, "Usage: zfw -I -c <dest cidr> -m <dest cidr len> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol>\n");
    fprintf(stderr, "       zfw -D -c <dest cidr> -m <dest cidr len> -l <low_port> -p <protocol>\n");
    fprintf(stderr, "       zfw -I -c <dest cidr> -m <dest cidr len> -o <origin cidr> -n <origin cidr len> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol>\n");
    fprintf(stderr, "       zfw -D -c <dest cidr> -m <dest cidr len> -o <origin cidr> -n <origin cidr len> -l <low_port> -p <protocol>\n");
    fprintf(stderr, "       zfw -L -c <dest cidr> -m <dest cidr len> -p <protocol>\n");
    fprintf(stderr, "       zfw -L -c <dest cidr> -m <dest cidr len> -o <origin cidr> -n <origin cidr len>\n");
    fprintf(stderr, "       zfw -L\n");
    fprintf(stderr, "       zfw -L -i\n");
    fprintf(stderr, "       zfw -L -f\n");
    fprintf(stderr, "       zfw -L -6 all\n");
    fprintf(stderr, "       zfw -F\n");
    fprintf(stderr, "       zfw -e <ifname>\n");
    fprintf(stderr, "       zfw -e <ifname> -d\n");
    fprintf(stderr, "       zfw -v <ifname>\n");
    fprintf(stderr, "       zfw -v <ifname> -d\n");
    fprintf(stderr, "       zfw -x <ifname>\n");
    fprintf(stderr, "       zfw -x <ifname> -d\n");
    fprintf(stderr, "       zfw -P <ifname>\n");
    fprintf(stderr, "       zfw -P <ifname> -d\n");
    fprintf(stderr, "       zfw -X <ifname> -O <object file name> -z direction\n");
    fprintf(stderr, "       zfw -X <ifname> -O <object file name> -z direction -d\n");
    fprintf(stderr, "       zfw -Q\n");
    fprintf(stderr, "       zfw --vrrp-enable <ifname>\n");
    fprintf(stderr, "       zfw -V\n");
    fprintf(stderr, "       zfw --help\n");
    close_maps(1);
}

bool set_tun_diag()
{
    if (access(tun_map_path, F_OK) != 0)
    {
        ebpf_usage();
    }
    if (tun_fd == -1)
    {
        open_tun_map();
    }
    interface_map();
    interface_map6();
    tun_map.map_fd = tun_fd;
    struct ifindex_tun o_tdiag;
    uint32_t key = 0;
    tun_map.key = (uint64_t)&key;
    tun_map.flags = BPF_ANY;
    tun_map.value = (uint64_t)&o_tdiag;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tun_map, sizeof(tun_map));
    if (lookup)
    {
        printf("Invalid Index\n");
        return false;
    }
    else
    {
        if (!list_diag)
        {
            if (strcmp(o_tdiag.ifname, verbose_interface))
            {
                printf("Invalid tun interface only ziti tun supported\n");
                return false;
            }
            if (verbose)
            {
                if (!disable)
                {
                    o_tdiag.verbose = true;
                }
                else
                {
                    o_tdiag.verbose = false;
                }
                printf("Set verbose to %d for %s\n", !disable, verbose_interface);
            }
            int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &tun_map, sizeof(tun_map));
            if (ret)
            {
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                return false;
            }
            return true;
        }
        else
        {
            if (strcmp(o_tdiag.ifname, diag_interface))
            {
                return false;
            }
            char *tun_resolver = nitoa(ntohl(o_tdiag.resolver));
            printf("%s: %d\n", o_tdiag.ifname, o_tdiag.index);
            printf("--------------------------\n");
            printf("%-24s:%d\n", "verbose", o_tdiag.verbose);
            printf("%-24s:%s\n", "cidr", o_tdiag.cidr);
            if (tun_resolver)
            {
                printf("%-24s:%s\n", "resolver", tun_resolver);
                free(tun_resolver);
            }
            else
            {
                printf("%-24s:%s\n", "resolver", "");
            }
            printf("%-24s:%s\n", "mask", o_tdiag.mask);
            printf("--------------------------\n\n");
        }
    }
    return true;
}

void update_bind_saddr_map(struct bind_key *key)
{
    if (bind_saddr_fd == -1)
    {
        open_bind_saddr_map();
    }
    __u32 count = 0;
    bind_saddr_map.key = (uint64_t)key;
    bind_saddr_map.value = (uint64_t)&count;
    bind_saddr_map.map_fd = bind_saddr_fd;
    bind_saddr_map.flags = BPF_ANY;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bind_saddr_map, sizeof(bind_saddr_map));
    if (lookup)
    {
        count = 1;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bind_saddr_map, sizeof(bind_saddr_map));
        if (result)
        {
            printf("MAP_UPDATE_BIND_ELEM: %s \n", strerror(errno));
        }
        if(key->type == 4){
            struct in_addr addr = {0};
            addr.s_addr = key->__in46_u_dest.ip;
            bind_prefix(&addr, key->mask);
            char *source = inet_ntoa(addr);
            if(source){
                printf("Prefix: %s/%u Added to loopback\n", source, key->mask);
            }
        }else{
            char saddr6[INET6_ADDRSTRLEN];
            struct in6_addr saddr_6 = {0};
            memcpy(saddr_6.__in6_u.__u6_addr32, key->__in46_u_dest.ip6, sizeof(key->__in46_u_dest.ip6));
            inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
            bind6_prefix(&saddr_6, key->mask);
            printf("Prefix: %s/%u Added to loopback\n", saddr6, key->mask);
        }
    }
    else
    {
        count += 1;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bind_saddr_map, sizeof(bind_saddr_map));
        if (result)
        {
            printf("MAP_UPDATE_BIND_ELEM: %s \n", strerror(errno));
        }
        printf("Key already exists: total add count=%u\n", count);
    }
}

void delete_bind_saddr_map(struct bind_key *key)
{
    if (bind_saddr_fd == -1)
    {
        open_bind_saddr_map();
    }
    __u32 count = 0;
    bind_saddr_map.key = (uint64_t)key;
    bind_saddr_map.value = (uint64_t)&count;
    bind_saddr_map.map_fd = bind_saddr_fd;
    bind_saddr_map.flags = BPF_ANY;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &bind_saddr_map, sizeof(bind_saddr_map));
    if (!lookup)
    {
        if(count <= 1 || flush){
            union bpf_attr map;
            memset(&map, 0, sizeof(map));
            map.pathname = (uint64_t)bind_saddr_map_path;
            map.bpf_fd = 0;
            int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                close_maps(1);
            }
            // delete element with specified key
            map.map_fd = fd;
            map.key = (uint64_t)key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
            }
            else
            {
                if(key->type == 4){
                    struct in_addr addr = {0};
                    addr.s_addr = key->__in46_u_dest.ip;
                    unbind_prefix(&addr, key->mask);
                    char *source = inet_ntoa(addr);
                    if(source){
                        printf("Prefix: %s/%u removed from loopback\n", source, key->mask);
                    }
                }else{
                    char saddr6[INET6_ADDRSTRLEN];
                    struct in6_addr saddr_6 = {0};
                    memcpy(saddr_6.__in6_u.__u6_addr32, key->__in46_u_dest.ip6, sizeof(key->__in46_u_dest.ip6));
                    inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
                    unbind6_prefix(&saddr_6, key->mask);
                    printf("Prefix: %s/%u removed from loopback\n", saddr6, key->mask);
                }
            }
            close(fd);
        }else{
            count -= 1;
            printf("add count decremented to: %u\n", count);
            int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &bind_saddr_map, sizeof(bind_saddr_map));
            if (result)
            {
                printf("MAP_UPDATE_BIND_ELEM: %s \n", strerror(errno));
            }
        }
    }else{
        printf("bind prefix does not exist\n");
    }
}

void update_ddos_saddr_map(char *source)
{
    if (ddos_saddr_fd == -1)
    {
        open_ddos_saddr_map();
    }
    struct in_addr cidr;
    if (inet_aton(source, &cidr))
    {
        uint32_t key = cidr.s_addr;
        bool state = false;
        ddos_saddr_map.key = (uint64_t)&key;
        ddos_saddr_map.value = (uint64_t)&state;
        ddos_saddr_map.map_fd = ddos_saddr_fd;
        ddos_saddr_map.flags = BPF_ANY;
        int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &ddos_saddr_map, sizeof(ddos_saddr_map));
        if (lookup)
        {
            state = true;
            int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &ddos_saddr_map, sizeof(ddos_saddr_map));
            if (result)
            {
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            }
            printf("%s: Added to DDOS Whitelist\n", (char *)source);
        }
        else
        {
            printf("Key already exists: %s, state=%d\n", source, state);
        }
    }
    else
    {
        printf("Invalid Source Address");
    }
}

void delete_ddos_saddr_map(char *source)
{
    struct in_addr cidr;
    if (inet_aton(source, &cidr))
    {
        union bpf_attr map;
        memset(&map, 0, sizeof(map));
        map.pathname = (uint64_t)ddos_saddr_map_path;
        map.bpf_fd = 0;
        int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
        if (fd == -1)
        {
            printf("BPF_OBJ_GET: %s\n", strerror(errno));
            close_maps(1);
        }
        // delete element with specified key
        uint32_t key = cidr.s_addr;
        map.map_fd = fd;
        map.key = (uint64_t)&key;
        int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
        if (result)
        {
            printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
        }
        else
        {
            printf("Removed source address %s from ddos_saddr_map\n", source);
        }
        close(fd);
    }
    else
    {
        printf("Invalid Source Address");
    }
}

void update_ddos_dport_map(char *dport)
{
    if (ddos_dport_fd == -1)
    {
        open_ddos_dport_map();
    }
    uint16_t key = htons(port2s(dport));
    bool state = false;
    ddos_dport_map.key = (uint64_t)&key;
    ddos_dport_map.value = (uint64_t)&state;
    ddos_dport_map.map_fd = ddos_dport_fd;
    ddos_dport_map.flags = BPF_ANY;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &ddos_dport_map, sizeof(ddos_dport_map));
    if (lookup)
    {
        state = true;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &ddos_dport_map, sizeof(ddos_dport_map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        }
        printf("%s: Added to ddos port list\n", (char *)dport);
    }
    else
    {
        printf("Key already exists: %s, state=%d\n", dport, state);
    }
}

void delete_ddos_dport_map(char *dport)
{
    uint16_t key = htons(port2s(dport));
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)ddos_dport_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    else
    {
        printf("Removed destination port %s from ddos_dport_map\n", dport);
    }
    close(fd);
}

void update_dnp3_fcode_map(char *fcode)
{
    if (dnp3_fcode_fd == -1)
    {
        open_dnp3_fcode_map();
    }
    uint8_t key = fcode2u8(fcode);
    uint32_t state = 0;
    dnp3_fcode_map.key = (uint64_t)&key;
    dnp3_fcode_map.value = (uint64_t)&state;
    dnp3_fcode_map.map_fd = dnp3_fcode_fd;
    dnp3_fcode_map.flags = BPF_ANY;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
    if (lookup)
    {
        state = 1;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        }else{
            printf("%s: Added to dnp3 function code list\n", (char *)fcode);
        }
    }
    else
    {
        state += 1;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        }else{
            printf("Added instantiation to existing key: %s, instantiations=%d\n", fcode, state);
        }
    }
}

void delete_dnp3_fcode_map(char *fcode)
{
    if (dnp3_fcode_fd == -1)
    {
        open_dnp3_fcode_map();
    }
    uint8_t key = fcode2u8(fcode);
    uint32_t state = 0;
    dnp3_fcode_map.key = (uint64_t)&key;
    dnp3_fcode_map.value = (uint64_t)&state;
    dnp3_fcode_map.map_fd = dnp3_fcode_fd;
    dnp3_fcode_map.flags = BPF_ANY;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
    if (!lookup)
    {
        if(state > 1 && !flush){
            state -= 1;
            int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
            if (result)
            {
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            }else{
                printf("%s: Decremented fcode instantiation count, %d instantiations remaining\n", (char *)fcode, state);
            }
        }else{
            union bpf_attr map;
            memset(&map, 0, sizeof(map));
            map.pathname = (uint64_t)dnp3_fcode_map_path;
            map.bpf_fd = 0;
            int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                close_maps(1);
            }
            // delete element with specified key
            map.map_fd = fd;
            map.key = (uint64_t)&key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
            }
            else
            {
                printf("Removed function code %s from dnp3_fcode_map\n", fcode);
            }
            close(fd);
        }
    }else{
        printf("MAP_LOOKUP_ELEM: %s \n", strerror(errno));
    }
}

void dnp3_fcode_map_flush()
{
    union bpf_attr map;
    uint8_t init_key = 0;
    uint8_t *key = &init_key;
    uint8_t reference_key;
    uint8_t lookup_key;
    uint32_t value;
    uint32_t state;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)dnp3_fcode_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&value;
    int lookup = 0;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1){
            break;
        }
        map.key = map.next_key;
        reference_key = *(uint16_t *)map.key;
        char fcode[4];
        sprintf(fcode, "%d", reference_key);
        delete_dnp3_fcode_map(fcode);
        map.key = (uint64_t)&reference_key;
    }
    close(fd);
}

bool set_diag(uint32_t *idx)
{
    if (access(diag_map_path, F_OK) != 0)
    {
        ebpf_usage();
    }
    diag_map.map_fd = diag_fd;
    struct diag_ip4 o_diag = {0};
    diag_map.key = (uint64_t)idx;
    diag_map.flags = BPF_ANY;
    diag_map.value = (uint64_t)&o_diag;
    syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &diag_map, sizeof(diag_map));
    if (!list_diag)
    {
        if (echo)
        {
            if (!disable || *idx == 1)
            {
                o_diag.echo = true;
            }
            else
            {
                o_diag.echo = false;
            }
            if (*idx != 1)
            {
                printf("Set icmp-echo to %d for %s\n", !disable, echo_interface);
            }
            else
            {
                printf("icmp echo is always set to 1 for lo\n");
            }
        }

        if (non_tuple)
        {
            if (!disable || *idx == 1)
            {
                o_diag.pass_non_tuple = true;
            }
            else
            {
                o_diag.pass_non_tuple = false;
            }
            if (*idx != 1)
            {
                printf("Set pass-non-tuple to %d for %s\n", !disable, nt_interface);
            }
            else
            {
                printf("pass-non-tuple is always set to 1 for lo\n");
            }
        }
        
        if (v6)
        {
            if (!disable || *idx == 1)
            {
                o_diag.ipv6_enable = true;
            }
            else
            {
                o_diag.ipv6_enable = false;
            }
            if (*idx != 1)
            {
                printf("Set ipv6_enable to %d for %s\n", !disable, ipv6_interface);
            }
            else
            {
                printf("ipv6_enable is always set to 1 for lo\n");
            }
        }
        if (verbose)
        {
            if (!disable)
            {
                o_diag.verbose = true;
            }
            else
            {
                o_diag.verbose = false;
            }
            printf("Set verbose to %d for %s\n", !disable, verbose_interface);
        }
        if (eapol)
        {
            if (!disable)
            {
                o_diag.eapol = true;
            }
            else
            {
                o_diag.eapol = false;
            }
            printf("Set eapol to %d for %s\n", !disable, eapol_interface);
        }
        if (per_interface)
        {
            if (!disable)
            {
                o_diag.per_interface = true;
            }
            else
            {
                o_diag.per_interface = false;
            }
            printf("Set per_interface rule aware to %d for %s\n", !disable, prefix_interface);
        }
        if (ssh_disable)
        {
            if (!disable && *idx != 1)
            {
                o_diag.ssh_disable = true;
            }
            else
            {
                o_diag.ssh_disable = false;
            }
            if (*idx != 1)
            {
                printf("Set disable_ssh to %d for %s\n", !disable, ssh_interface);
            }
            else
            {
                printf("Set disable_ssh is always set to 0 for lo\n");
            }
        }
        if (masquerade)
        {
            if (!disable && *idx != 1)
            {
                if(!check_filter(*idx,"egress")){
                    o_diag.masquerade = true;
                }else{
                    printf("masquerade not set, no egress filter exists for %s\n", masq_interface);
                    printf("set first with: sudo zfw -X %s -O /opt/openziti/bin/zfw_tc_outbound_track.o -z egress\n", masq_interface);
                    close_maps(1);
                }
            }
            else
            {
                o_diag.masquerade = false;
            }
            if (*idx != 1)
            {
                printf("Set masquerade to %d for %s\n", !disable, masq_interface);
            }
            else
            {
                printf("Masquerade is always set to 0 for lo\n");
            }
        }
        if (outbound)
        {
            if (!disable && *idx != 1)
            {
                if(!check_filter(*idx,"egress")){
                    o_diag.outbound_filter = true;
                }else{
                    printf("outbound filter not set, no egress filter exists for %s\n", outbound_interface);
                    printf("set first with: sudo zfw -X %s -O /opt/openziti/bin/zfw_tc_outbound_track.o -z egress\n", outbound_interface);
                    close_maps(1);
                }
            }
            else
            {
                o_diag.outbound_filter = false;
            }
            if (*idx != 1)
            {
                printf("Set outbound_filter to %d for %s\n", !disable, outbound_interface);
            }
            else
            {
                printf("Set outbound_filter is always set to 0 for lo\n");
            }
        }
        if (tcfilter && !strcmp("ingress", direction_string))
        {
            if (!disable)
            {
                o_diag.tc_ingress = true;
            }
            else
            {
                o_diag.tc_ingress = false;
            }
            printf("Set tc filter enable to %d for %s on %s\n", !disable, direction_string, tc_interface);
        }
        if (tcfilter && !strcmp("egress", direction_string))
        {
            if (!disable)
            {
                o_diag.tc_egress = true;
            }
            else
            {
                o_diag.tc_egress = false;
            }
            printf("Set tc filter enable to %d for %s on %s\n", !disable, direction_string, tc_interface);
        }
        if (tun)
        {
            if (!disable)
            {
                o_diag.tun_mode = true;
            }
            else
            {
                o_diag.tun_mode = false;
            }
            printf("Set tun mode to %d for %s\n", !disable, tun_interface);
        }
        if (vrrp)
        {
            if (!disable)
            {
                o_diag.vrrp = true;
            }
            else
            {
                o_diag.vrrp = false;
            }
            printf("Set vrrp mode to %d for %s\n", !disable, vrrp_interface);
        }
        if (ddos)
        {
            if (!disable)
            {
                o_diag.ddos_filtering = true;
            }
            else
            {
                o_diag.ddos_filtering = false;
            }
            printf("Set ddos detect to %d for %s\n", !disable, ddos_interface);
        }
        if (ot_filter)
        {
            if (!disable)
            {
                o_diag.ot_filtering = true;
            }
            else
            {
                o_diag.ot_filtering = false;
            }
            printf("Set ot filtering to %d for %s\n", !disable, ot_interface);
        }
        int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &diag_map, sizeof(diag_map));
        if (ret)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            return false;
        }
        return true;
    }
    else
    {
        printf("%s: %u\n", diag_interface, *idx);
        printf("--------------------------\n");
        if (*idx != 1)
        {
            printf("%-24s:%d\n", "icmp echo", o_diag.echo);
            printf("%-24s:%d\n", "pass non tuple", o_diag.pass_non_tuple);
            printf("%-24s:%d\n", "ipv6 enable", o_diag.ipv6_enable);
        }
        else
        {
            printf("%-24s:%d\n", "icmp echo", 1);
            printf("%-24s:%d\n", "pass non tuple", 1);
            printf("%-24s:%d\n", "ipv6 enable", 1);
        }
        printf("%-24s:%d\n", "verbose", o_diag.verbose);
        printf("%-24s:%d\n", "ssh disable", o_diag.ssh_disable);
        printf("%-24s:%d\n", "outbound_filter", o_diag.outbound_filter);
        printf("%-24s:%d\n", "per interface", o_diag.per_interface);
        printf("%-24s:%d\n", "tc ingress filter", o_diag.tc_ingress);
        printf("%-24s:%d\n", "tc egress filter", o_diag.tc_egress);
        printf("%-24s:%d\n", "tun mode intercept", o_diag.tun_mode);
        printf("%-24s:%d\n", "vrrp enable", o_diag.vrrp);
        printf("%-24s:%d\n", "eapol enable", o_diag.eapol);
        printf("%-24s:%d\n", "ddos filtering", o_diag.ddos_filtering);
        printf("%-24s:%d\n", "masquerade", o_diag.masquerade);
        printf("%-24s:%d\n", "ot filtering", o_diag.ot_filtering);
        printf("--------------------------\n\n");
    }
    return true;
}

void interface_tc()
{
    struct ifaddrs *addrs;
    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        close_maps(1);
    }
    struct ifaddrs *address = addrs;
    uint32_t idx = 0;
    uint32_t cur_idx = 0;
    uint32_t index_count = 0;
    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ip address
     *  as the value
     */
    while (address && (index_count < MAX_IF_ENTRIES))
    {
        if (address->ifa_addr && ((!strncmp(address->ifa_name, "ziti0", 4) && (address->ifa_addr->sa_family == AF_INET)) || (!strncmp(address->ifa_name, "tun", 3) && (address->ifa_addr->sa_family == AF_INET)) || (address->ifa_addr->sa_family == AF_PACKET)))
        {
            idx = if_nametoindex(address->ifa_name);
            if (!idx)
            {
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if (all_interface)
            {
                tc_interface = address->ifa_name;
            }
            if (!strncmp(address->ifa_name, "ziti", 4))
            {
                if (!strncmp(tc_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow tc filters on ziti tun interfaces!\n", address->ifa_name);
                }
                address = address->ifa_next;
                continue;
            }
            if (cur_idx == idx)
            {
                address = address->ifa_next;
                continue;
            }
            else
            {
                index_count++;
                cur_idx = idx;
            }
            if (tc || tcfilter)
            {
                if (!strcmp(tc_interface, address->ifa_name))
                {
                    if (tc)
                    {
                        if (!disable)
                        {
                            if(check_qdisc(address->ifa_name)){
                                set_tc("add");
                            }
                        }
                        else
                        {
                            if(!check_qdisc(address->ifa_name)){
                                set_tc("del");
                            }
                        }
                    }
                    if (tcfilter)
                    {
                        if (!disable)
                        {
                            int res = set_tc_filter("add");
                            interface_map();
                            interface_map6();
                            if (diag_fd == -1)
                            {
                                open_diag_map();
                            }
                            if(!res){
                                set_diag(&idx);
                            }
                        }
                        else
                        {
                            set_tc_filter("del");
                            if(egress){
                                outbound = true;
                                masquerade = true;
                                outbound_interface = tc_interface;
                                masq_interface = tc_interface;
                            }
                            if (diag_fd == -1)
                            {
                                open_diag_map();
                            }
                            set_diag(&idx);
                        }
                    }
                }
            }
        }
        address = address->ifa_next;
    }
    freeifaddrs(addrs);
}

void interface_diag()
{
    if (diag_fd == -1)
    {
        open_diag_map();
    }
    interface_map();
    interface_map6();
    struct ifaddrs *addrs;

    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        close_maps(1);
    }
    struct ifaddrs *address = addrs;
    uint32_t idx = 0;
    uint32_t cur_idx = 0;
    uint32_t index_count = 0;
    while (address && (index_count < MAX_IF_ENTRIES))
    {
        if (address->ifa_addr && ((!strncmp(address->ifa_name, "ziti0", 4) && (address->ifa_addr->sa_family == AF_INET)) || (!strncmp(address->ifa_name, "tun", 3) && (address->ifa_addr->sa_family == AF_INET)) || (address->ifa_addr->sa_family == AF_PACKET)))
        {
            idx = if_nametoindex(address->ifa_name);
            if (!idx)
            {
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if (cur_idx == idx)
            {
                address = address->ifa_next;
                continue;
            }
            else
            {
                index_count++;
                cur_idx = idx;
            }
            if (all_interface)
            {
                nt_interface = address->ifa_name;
                echo_interface = address->ifa_name;
                verbose_interface = address->ifa_name;
                prefix_interface = address->ifa_name;
                ssh_interface = address->ifa_name;
                diag_interface = address->ifa_name;
                tun_interface = address->ifa_name;
                vrrp_interface = address->ifa_name;
                eapol_interface = address->ifa_name;
                ddos_interface = address->ifa_name;
                ot_interface = address->ifa_name;
                ipv6_interface = address->ifa_name;
                outbound_interface = address->ifa_name;
                masq_interface = address->ifa_name;
            }
            if (!strncmp(address->ifa_name, "ziti", 4) && (tun || per_interface || ssh_disable || echo || vrrp || eapol || ddos || v6 || outbound || masquerade || ot_filter))
            {
                if (per_interface && !strncmp(prefix_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (non_tuple && !strncmp(nt_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (tun && !strncmp(tun_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (ssh_disable && !strncmp(ssh_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (echo && !strncmp(echo_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (vrrp && !strncmp(vrrp_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (eapol && !strncmp(eapol_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (ddos && !strncmp(ddos_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (ot_filter && !strncmp(ot_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (masquerade && !strncmp(masq_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (v6 && !strncmp(ipv6_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                if (outbound && !strncmp(outbound_interface, "ziti", 4))
                {
                    printf("%s:zfw does not allow setting on ziti tun interfaces!\n", address->ifa_name);
                }
                address = address->ifa_next;
                continue;
            }
            if (echo)
            {
                if (!strcmp(echo_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }
            if (non_tuple)
            {
                if (!strcmp(nt_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }
            if (masquerade)
            {
                if (!strcmp(masq_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }
            if (outbound)
            {
                if (!strcmp(outbound_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (vrrp)
            {
                if (!strcmp(vrrp_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (ddos)
            {
                if (!strcmp(ddos_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (ot_filter)
            {
                if (!strcmp(ot_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (eapol)
            {
                if (!strcmp(eapol_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (verbose)
            {
                if (!strncmp(address->ifa_name, "ziti", 4) && !strncmp(verbose_interface, "ziti", 4))
                {
                    set_tun_diag();
                }
                else if (!strcmp(verbose_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (tun)
            {
                if (!strcmp(tun_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (per_interface)
            {
                if (!strcmp(prefix_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (list_diag)
            {
                if (!strncmp(address->ifa_name, "ziti", 4) && !strncmp(diag_interface, "ziti", 4))
                {
                    set_tun_diag();
                }
                else if (!strcmp(diag_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (ssh_disable)
            {
                if (!strcmp(ssh_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (v6)
            {
                if (!strcmp(ipv6_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (access(diag_map_path, F_OK) != 0)
            {
                ebpf_usage();
            }
        }
        address = address->ifa_next;
    }
    freeifaddrs(addrs);
}

// remove stale ifindex_ip_map entries
int prune_diag_map(struct interface if_array[], uint32_t if_count)
{
    if (diag_fd == -1)
    {
        open_diag_map();
    }
    uint32_t init_key = {0};
    uint32_t *key = &init_key;
    uint32_t current_key;
    struct diag_ip4 o_diagip4;
    diag_map.file_flags = BPF_ANY;
    diag_map.map_fd = diag_fd;
    diag_map.key = (uint64_t)key;
    diag_map.value = (uint64_t)&o_diagip4;
    int lookup = 0;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &diag_map, sizeof(diag_map));
        if (ret == -1)
        {
            break;
        }
        diag_map.key = diag_map.next_key;
        current_key = *(uint32_t *)diag_map.key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &diag_map, sizeof(diag_map));
        if (!lookup)
        {
            bool match = false;
            for (uint32_t x = 0; x < if_count; x++)
            {
                if (current_key == if_array[x].index)
                {
                    match = true;
                }
            }
            if (!match)
            {
                diag_delete_key(current_key);
            }
        }
        else
        {
            printf("Not Found\n");
        }
        diag_map.key = (uint64_t)&current_key;
    }
    return 0;
}

// remove stale ifindex_ip_map entries
int prune_if_map(struct interface if_array[], uint32_t if_count)
{
    if (if_fd == -1)
    {
        open_if_map();
    }
    uint32_t init_key = {0};
    uint32_t *key = &init_key;
    uint32_t current_key;
    struct ifindex_ip4 o_ifip4;
    if_map.file_flags = BPF_ANY;
    if_map.map_fd = if_fd;
    if_map.key = (uint64_t)key;
    if_map.value = (uint64_t)&o_ifip4;
    int lookup = 0;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &if_map, sizeof(if_map));
        if (ret == -1)
        {
            break;
        }
        if_map.key = if_map.next_key;
        current_key = *(uint32_t *)if_map.key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if_map, sizeof(if_map));
        if (!lookup)
        {
            bool match = false;
            for (uint32_t x = 0; x < if_count; x++)
            {
                if (current_key == if_array[x].index)
                {
                    match = true;
                }
            }
            if (!match)
            {
                if_delete_key(current_key);
            }
        }
        else
        {
            printf("Not Found\n");
        }
        if_map.key = (uint64_t)&current_key;
    }
    return 0;
}

// remove stale ifindex_ip6_map entries
int prune_if6_map(struct interface6 if6_array[], uint32_t if6_count)
{
    if (if6_fd == -1)
    {
        open_if6_map();
    }
    uint32_t init_key = {0};
    uint32_t *key = &init_key;
    uint32_t current_key;
    struct ifindex_ip6 o_ifip;
    if6_map.file_flags = BPF_ANY;
    if6_map.map_fd = if6_fd;
    if6_map.key = (uint64_t)key;
    if6_map.value = (uint64_t)&o_ifip;
    int lookup = 0;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &if6_map, sizeof(if6_map));
        if (ret == -1)
        {
            break;
        }
        if6_map.key = if6_map.next_key;
        current_key = *(uint32_t *)if6_map.key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if6_map, sizeof(if6_map));
        if (!lookup)
        {
            bool match = false;
            for (uint32_t x = 0; x < if6_count; x++)
            {
                if (current_key == if6_array[x].index)
                {
                    match = true;
                }
            }
            if (!match)
            {
                if6_delete_key(current_key);
            }
        }
        else
        {
            printf("Not Found\n");
        }
        if6_map.key = (uint64_t)&current_key;
    }
    return 0;
}

void if6_delete_key(uint32_t key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)if6_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    else
    {
        printf("Pruned index %u from ifindex_ip6_map\n", key);
    }
    close(fd);
}

int add_if6_index(struct interface6 intf)
{
    if (intf.addr_count > 0)
    {
        if (if6_fd == -1)
        {
            open_if6_map();
        }
        if6_map.map_fd = if6_fd;
        struct ifindex_ip6 o_ifip6 = {0};
        if6_map.key = (uint64_t)&intf.index;
        if6_map.flags = BPF_ANY;
        if6_map.value = (uint64_t)&o_ifip6;
        for (int x = 0; x < MAX_ADDRESSES; x++)
        {
            if (x < intf.addr_count)
            {
                memcpy(o_ifip6.ipaddr[x], intf.addresses[x], sizeof(o_ifip6.ipaddr[x]));
            }
            else
            {
                memset(o_ifip6.ipaddr[x], 0, sizeof(o_ifip6.ipaddr[x]));
            }
        }
        o_ifip6.count = intf.addr_count;
        sprintf(o_ifip6.ifname, "%s", intf.name);
        int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &if6_map, sizeof(if6_map));
        if (ret)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            return 1;
        }
    }
    return 0;
}

int add_if_index(struct interface intf)
{
    if (intf.addr_count > 0)
    {
        if (if_fd == -1)
        {
            open_if_map();
        }
        if_map.map_fd = if_fd;
        struct ifindex_ip4 o_ifip4 = {0};
        if_map.key = (uint64_t)&intf.index;
        if_map.flags = BPF_ANY;
        if_map.value = (uint64_t)&o_ifip4;
        for (int x = 0; x < MAX_ADDRESSES; x++)
        {
            if (x < intf.addr_count)
            {
                o_ifip4.ipaddr[x] = intf.addresses[x];
            }
            else
            {
                o_ifip4.ipaddr[x] = 0;
            }
        }
        o_ifip4.count = intf.addr_count;
        sprintf(o_ifip4.ifname, "%s", intf.name);
        int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &if_map, sizeof(if_map));
        if (ret)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            return 1;
        }
    }
    return 0;
}

void interface_map6()
{
    struct ifaddrs *addrs;
    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        close_maps(1);
    }
    struct ifaddrs *address = addrs;
    uint32_t idx = 0;
    int lo_count = 0;

    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ipv6 address
     *  as the value
     */

    uint32_t ip6_index_count = 0;
    uint32_t addr6_array[MAX_ADDRESSES][4];
    struct interface6 ip6_index_array[MAX_IF_ENTRIES] = {0};
    char *cur_name;
    uint32_t cur_idx;
    uint8_t addr6_count = 0;
    while (address && (ip6_index_count < MAX_IF_ENTRIES))
    {
        idx = if_nametoindex(address->ifa_name);
        if (address->ifa_addr && ((address->ifa_addr->sa_family == AF_INET) || (address->ifa_addr->sa_family == AF_INET6)))
        {
            if (!idx)
            {
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if (!strncmp(address->ifa_name, "lo", 2))
            {
                lo_count++;
                if (lo_count > 1)
                {
                    address = address->ifa_next;
                    continue;
                }
            }
            if (strncmp(address->ifa_name, "ziti", 4))
            {
                if (addr6_count == 0)
                {
                    cur_name = address->ifa_name;
                    cur_idx = idx;
                    if (!strncmp(address->ifa_name, "lo", 2))
                    {
                        __u32 loipv6[4] = {0, 0, 0, 0x1000000};
                        memcpy(addr6_array[addr6_count], loipv6, sizeof(loipv6));
                    }
                    else
                    {
                        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)address->ifa_addr;
                        memcpy(addr6_array[addr6_count], sa->sin6_addr.__in6_u.__u6_addr32, sizeof(sa->sin6_addr.__in6_u.__u6_addr32));
                    }
                    addr6_count++;
                }
                else if (cur_idx != idx)
                {
                    struct interface6 intf6 = {
                        cur_idx,
                        cur_name,
                        addr6_count,
                        {0}};
                    memcpy(intf6.addresses, addr6_array, sizeof(intf6.addresses));
                    ip6_index_array[ip6_index_count] = intf6;
                    ip6_index_count++;
                    addr6_count = 0;
                    cur_idx = idx;
                    cur_name = address->ifa_name;
                    struct sockaddr_in6 *sa = (struct sockaddr_in6 *)address->ifa_addr;
                    memcpy(addr6_array[addr6_count], sa->sin6_addr.__in6_u.__u6_addr32, sizeof(sa->sin6_addr.__in6_u.__u6_addr32));
                    addr6_count++;
                }
                else
                {
                    if (addr6_count < MAX_ADDRESSES)
                    {
                        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)address->ifa_addr;
                        memcpy(addr6_array[addr6_count], sa->sin6_addr.__in6_u.__u6_addr32, sizeof(sa->sin6_addr.__in6_u.__u6_addr32));
                        addr6_count++;
                    }
                }
            }
        }
        address = address->ifa_next;
    }
    if ((idx > 0) && (addr6_count > 0) && (addr6_count <= MAX_ADDRESSES))
    {
        struct interface6 intf6 = {
            cur_idx,
            cur_name,
            addr6_count,
            {0}};
        memcpy(intf6.addresses, addr6_array, sizeof(addr6_array));
        ip6_index_array[ip6_index_count] = intf6;
        ip6_index_count++;
    }
    prune_if6_map(ip6_index_array, ip6_index_count);
    for (uint32_t x = 0; x < ip6_index_count; x++)
    {
        add_if6_index(ip6_index_array[x]);
    }
    freeifaddrs(addrs);
}

bool interface_map()
{
    if (tun_fd == -1)
    {
        open_tun_map();
    }
    struct ifaddrs *addrs;
    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        close_maps(1);
    }
    struct ifaddrs *address = addrs;
    uint32_t idx = 0;
    int lo_count = 0;
    struct sockaddr_in *ipaddr;
    in_addr_t ifip;
    int ipcheck = 0;
    bool create_route = true;
    struct in_addr tuncidr;
    uint32_t tunip = 0x01004064;
    char *tunmask = NULL;
    char *static_tun_mask = "10";
    char *tunipstr;
    char *dns_range = "ZITI_DNS_IP_RANGE";
    char *tunif = getenv(dns_range);
    char *tmptun = NULL;
    if (tunif)
    {
        tmptun = strdup(tunif);
    }
    if (tmptun)
    {

        if (tmptun && ((strlen(tmptun) > 8) && (strlen(tmptun) < 19)))
        {
            char *tok = strtok(tmptun, "/");
            tunipstr = strdup(tok);
            while (tok != NULL)
            {
                if (tunmask)
                {
                    free(tunmask);
                }
                tunmask = strdup(tok);
                tok = strtok(NULL, "/");
            }
            if (tmptun)
            {
                free(tmptun);
            }
            if (!((strlen(tunmask) > 0) && (strlen(tunmask) <= 2)))
            {
                free(tunmask);
                free(tunipstr);
            }
            else
            {
                if (inet_aton(tunipstr, &tuncidr))
                {
                    tunip = tuncidr.s_addr;
                }
                free(tunipstr);
            }
        }
    }
    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ip address
     *  as the value
     */

    uint32_t ip_index_count = 0;
    uint32_t all_index_count = 0;
    uint32_t addr_array[MAX_ADDRESSES];
    struct interface ip_index_array[MAX_IF_ENTRIES] = {0};
    struct interface all_index_array[MAX_IF_ENTRIES] = {0};
    char *cur_name;
    uint32_t cur_idx;
    uint8_t addr_count = 0;
    while (address && (ip_index_count < MAX_IF_ENTRIES))
    {
        idx = if_nametoindex(address->ifa_name);
        if (address->ifa_addr && (address->ifa_addr->sa_family == AF_INET))
        {
            if (!idx)
            {
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if (strncmp(address->ifa_name, "lo", 2))
            {
                ipaddr = (struct sockaddr_in *)address->ifa_addr;
                ifip = ipaddr->sin_addr.s_addr;
                struct sockaddr_in *network_mask = (struct sockaddr_in *)address->ifa_netmask;
                __u32 netmask = ntohl(network_mask->sin_addr.s_addr);
                ipcheck = is_subset(ntohl(ifip), netmask, ntohl(dcidr.s_addr));
                if (!ipcheck)
                {
                    create_route = false;
                }
            }
            else
            {
                ifip = 0x0100007f;
                lo_count++;
                if (lo_count > 1)
                {
                    address = address->ifa_next;
                    continue;
                }
            }
            if (strncmp(address->ifa_name, "ziti", 4))
            {
                if (addr_count == 0)
                {
                    cur_name = address->ifa_name;
                    cur_idx = idx;
                    addr_array[addr_count] = ifip;
                    addr_count++;
                }
                else if (cur_idx != idx)
                {
                    struct interface intf = {
                        cur_idx,
                        cur_name,
                        addr_count,
                        {0}};
                    memcpy(intf.addresses, addr_array, sizeof(intf.addresses));
                    ip_index_array[ip_index_count] = intf;
                    if (all_index_count < MAX_IF_ENTRIES)
                    {
                        all_index_array[all_index_count] = intf;
                    }
                    ip_index_count++;
                    all_index_count++;
                    addr_count = 0;
                    cur_idx = idx;
                    cur_name = address->ifa_name;
                    addr_array[addr_count] = ifip;
                    addr_count++;
                }
                else
                {
                    if (addr_count < MAX_ADDRESSES)
                    {
                        addr_array[addr_count] = ifip;
                        addr_count++;
                    }
                }
            }

            if ((ifip == tunip) && !strncmp(address->ifa_name, "ziti", 4))
            {
                bool change_detected = true;
                struct ifindex_tun o_iftun;
                int tun_key = 0;
                tun_map.map_fd = tun_fd;
                tun_map.key = (uint64_t)&tun_key;
                tun_map.flags = BPF_ANY;
                tun_map.value = (uint64_t)&o_iftun;
                int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tun_map, sizeof(tun_map));
                if (lookup)
                {
                    printf("Unable to access tun ArrayMap Index\n");
                }
                else
                {
                    if (o_iftun.index != idx)
                    {
                        o_iftun.index = idx;
                        change_detected = true;
                    }
                    uint32_t tun_net_integer = 0;
                    if (tunmask)
                    {
                        if (strcmp(o_iftun.mask, tunmask))
                        {
                            sprintf(o_iftun.mask, "%s", tunmask);
                            change_detected = true;
                        }
                        if (strcmp(o_iftun.ifname, address->ifa_name))
                        {
                            sprintf(o_iftun.ifname, "%s", address->ifa_name);
                            change_detected = true;
                        }
                        tun_net_integer = ntohl(ifip) & bits2Mask(len2u16(tunmask));
                        free(tunmask);
                    }
                    else
                    {
                        if (strcmp(o_iftun.mask, static_tun_mask))
                        {
                            sprintf(o_iftun.mask, "%s", static_tun_mask);
                            change_detected = true;
                        }
                        if (strcmp(o_iftun.ifname, address->ifa_name))
                        {
                            sprintf(o_iftun.ifname, "%s", address->ifa_name);
                            change_detected = true;
                        }
                        tun_net_integer = ntohl(ifip) & bits2Mask(len2u16(static_tun_mask));
                    }
                    char *tuncidr_string = nitoa(tun_net_integer);
                    if (tuncidr_string)
                    {
                        if (strcmp(o_iftun.cidr, tuncidr_string))
                        {
                            sprintf(o_iftun.cidr, "%s", tuncidr_string);
                            change_detected = true;
                        }
                        free(tuncidr_string);
                        o_iftun.resolver = htonl(tun_net_integer + 2);
                    }

                    if (change_detected)
                    {
                        int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &tun_map, sizeof(tun_map));
                        if (ret)
                        {
                            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                            return 1;
                        }
                    }
                }
            }
            else if (!strncmp(address->ifa_name, "ziti", 4) && tunmask)
            {
                free(tunmask);
            }
        }
        else
        {
            struct interface intf = {
                idx,
                cur_name,
                0,
                {0}};
            if (all_index_count < MAX_IF_ENTRIES)
            {
                all_index_array[all_index_count] = intf;
            }
            all_index_count++;
            address = address->ifa_next;
            continue;
        }
        address = address->ifa_next;
    }
    if ((idx > 0) && (addr_count > 0) && (addr_count <= MAX_ADDRESSES))
    {
        struct interface intf = {
            cur_idx,
            cur_name,
            addr_count,
            {0}};
        memcpy(intf.addresses, addr_array, sizeof(addr_array));
        ip_index_array[ip_index_count] = intf;
        if (all_index_count < MAX_IF_ENTRIES)
        {
            all_index_array[all_index_count] = intf;
        }
        ip_index_count++;
        all_index_count++;
    }
    prune_if_map(ip_index_array, ip_index_count);
    for (uint32_t x = 0; x < ip_index_count; x++)
    {
        add_if_index(ip_index_array[x]);
    }
    prune_diag_map(all_index_array, all_index_count);
    freeifaddrs(addrs);
    return create_route;
}

int write_log(char *dest, char *source)
{
    FILE *dstfile;
    size_t len = strlen(source);
    if (len)
    {
        dstfile = fopen(dest, "a");
        if (dstfile == NULL)
        {
            return 1;
        }
        fprintf(dstfile, "%s", source);
        fclose(dstfile);
    }
    return 0;
}

static int process_events(void *ctx, void *data, size_t len)
{
    struct bpf_event *evt = (struct bpf_event *)data;
    char buf[IF_NAMESIZE];
    char *ifname = if_indextoname(evt->ifindex, buf);
    char *ts = get_ts(evt->tstamp);
    char message[250];
    int res = 0;
    if (((ifname && monitor_interface && !strcmp(monitor_interface, ifname)) || all_interface) && ts)
    {
        if (evt->version == 4)
        {
            if (evt->error_code)
            {
                if (evt->error_code == IP_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : IP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == NO_IP_OPTIONS_ALLOWED)
                {
                    sprintf(message, "%s : %s : %s : No IP Options Allowed\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == UDP_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : UDP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == GENEVE_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : Geneve Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == GENEVE_HEADER_LENGTH_VERSION_ERROR)
                {
                    sprintf(message, "%s : %s : %s : Geneve Header Length: Version Error\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == SKB_ADJUST_ERROR)
                {
                    sprintf(message, "%s : %s : %s : SKB Adjust Error\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == ICMP_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : ICMP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == ICMP_INNER_IP_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : ICMP Inner IP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == IF_LIST_MATCH_ERROR)
                {
                    sprintf(message, "%s : %s : %s : Interface did not match and per interface filtering is enabled\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == NO_REDIRECT_STATE_FOUND)
                {
                    sprintf(message, "%s : %s : %s : No Redirect State found\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
            }
            else
            {
                char *saddr = nitoa(ntohl(evt->saddr[0]));
                char *daddr = nitoa(ntohl(evt->daddr[0]));
                char *protocol;
                if (evt->proto == IPPROTO_TCP)
                {
                    protocol = "TCP";
                }
                else if (evt->proto == IPPROTO_ICMP)
                {
                    protocol = "ICMP";
                }
                else
                {
                    protocol = "UDP";
                }
                if (evt->tun_ifindex && ifname)
                {
                    char tbuf[IF_NAMESIZE];
                    char *tun_ifname = if_indextoname(evt->tun_ifindex, tbuf);
                    if (tun_ifname)
                    {
                        sprintf(message, "%s : %s : %s : %s :%s:%d[%x:%x:%x:%x:%x:%x] > %s:%d[%x:%x:%x:%x:%x:%x] redirect ---> %s\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, ntohs(evt->sport),
                                evt->source[0], evt->source[1], evt->source[2], evt->source[3], evt->source[4], evt->source[5], daddr, ntohs(evt->dport),
                                evt->dest[0], evt->dest[1], evt->dest[2], evt->dest[3], evt->dest[4], evt->dest[5], tun_ifname);
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                }
                else if (evt->tport && ifname)
                {
                    sprintf(message, "%s : %s : %s : %s :%s:%d > %s:%d | tproxy ---> 127.0.0.1:%d\n",
                            ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, ntohs(evt->sport),
                            daddr, ntohs(evt->dport), ntohs(evt->tport));
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (((evt->proto == IPPROTO_TCP) | (evt->proto == IPPROTO_UDP)) && evt->tracking_code && ifname)
                {
                    char *state = NULL;
                    __u16 code = evt->tracking_code;

                    if (code == SERVER_SYN_ACK_RCVD)
                    {
                        state = "SERVER_SYN_ACK_RCVD";
                    }
                    else if (code == SERVER_FIN_RCVD)
                    {
                        state = "SERVER_FIN_RCVD";
                    }
                    else if (code == SERVER_RST_RCVD)
                    {
                        state = "SERVER_RST_RCVD";
                    }
                    else if (code == SERVER_FINAL_ACK_RCVD)
                    {
                        state = "SERVER_FINAL_ACK_RCVD";
                    }
                    else if (code == UDP_MATCHED_EXPIRED_STATE)
                    {
                        state = "UDP_MATCHED_EXPIRED_STATE";
                    }
                    else if (code == UDP_MATCHED_ACTIVE_STATE)
                    {
                        state = "UDP_MATCHED_ACTIVE_STATE";
                    }
                    else if (code == CLIENT_SYN_RCVD)
                    {
                        state = "CLIENT_SYN_RCVD";
                    }
                    else if (code == CLIENT_FIN_RCVD)
                    {
                        state = "CLIENT_FIN_RCVD";
                    }
                    else if (code == CLIENT_RST_RCVD)
                    {
                        state = "CLIENT_RST_RCVD";
                    }
                    else if (code == TCP_CONNECTION_ESTABLISHED)
                    {
                        state = "TCP_CONNECTION_ESTABLISHED";
                    }
                    else if (code == CLIENT_FINAL_ACK_RCVD)
                    {
                        state = "CLIENT_FINAL_ACK_RCVD";
                    }
                    else if (code == CLIENT_INITIATED_UDP_SESSION)
                    {
                        state = "CLIENT_INITIATED_UDP_SESSION";
                    }
                    else if (code == INGRESS_INITIATED_UDP_SESSION)
                    {
                        state = "INGRESS_INITIATED_UDP_SESSION";
                    }
                    else if (code == INGRESS_UDP_MATCHED_EXPIRED_STATE)
                    {
                        state = "INGRESS_UDP_MATCHED_EXPIRED_STATE";
                    }
                    else if (code == INGRESS_UDP_MATCHED_ACTIVE_STATE)
                    {
                        state = "INGRESS_UDP_MATCHED_ACTIVE_STATE";
                    }
                    else if (code == INGRESS_CLIENT_SYN_RCVD)
                    {
                        state = "INGRESS_CLIENT_SYN_RCVD";
                    }else if (code == INGRESS_CLIENT_FIN_RCVD)
                    {
                        state = "INGRESS_CLIENT_FIN_RCVD";
                    }else if (code == INGRESS_CLIENT_RST_RCVD)
                    {
                        state = "INGRESS_CLIENT_RST_RCVD";
                    }else if (code == INGRESS_SERVER_RST_RCVD)
                    {
                        state = "INGRESS_SERVER_RST_RCVD";
                    }else if (code == INGRESS_TCP_CONNECTION_ESTABLISHED)
                    {
                        state = "INGRESS_TCP_CONNECTION_ESTABLISHED";
                    }else if (code == INGRESS_CLIENT_FINAL_ACK_RCVD)
                    {
                        state = "INGRESS_CLIENT_FINAL_ACK_RCVD";
                    }else if (code == INGRESS_SERVER_SYN_ACK_RCVD)
                    {
                        state = "INGRESS_SERVER_SYN_ACK_RCVD";
                    }else if (code == INGRESS_SERVER_FIN_RCVD)
                    {
                        state = "INGRESS_SERVER_FIN_RCVD";
                    }
                    else if (code == INGRESS_SERVER_FINAL_ACK_RCVD)
                    {
                        state = "INGRESS_SERVER_FINAL_ACK_RCVD";
                    }
                    else if (code == MATCHED_DROP_FILTER)
                    {
                        state = "MATCHED_DROP_FILTER";
                    }
                    else if (code == MATCHED_DROP_FILTER)
                    {
                        state = "MATCHED_DROP_FILTER";
                    }
                    else if (code == REVERSE_MASQUERADE_ENTRY_ADDED)
                    {
                        state = "REVERSE_MASQUERADE_ENTRY_ADDED";
                    }
                    else if (code == REVERSE_MASQUERADE_ENTRY_REMOVED)
                    {
                        state = "REVERSE_MASQUERADE_ENTRY_REMOVED";
                    }
                    else if (code == MASQUERADE_ENTRY_ADDED)
                    {
                        state = "MASQUERADE_ENTRY_ADDED";
                    }
                    else if (code == MASQUERADE_ENTRY_REMOVED)
                    {
                        state = "MASQUERADE_ENTRY_REMOVED";
                    }
                    else if (code == MASQUERADE_NO_FREE_TCP_SRC_PORTS_FOUND)
                    {
                        state = "MASQUERADE_NO_FREE_TCP_SRC_PORTS_FOUND";
                    }
                    else if (code == MASQUERADE_NO_FREE_UDP_SRC_PORTS_FOUND)
                    {
                        state = "MASQUERADE_NO_FREE_UDP_SRC_PORTS_FOUND";
                    }
                    else if (code == DNP3_FUNCTION_CODE_BLOCKED){
                        state = "DNP3_FUNCTION_CODE_BLOCKED";
                    }
                    else if (code == MODBUS_STATE_NOT_FOUND){
                        state = "MODBUS_STATE_NOT_FOUND";
                    }
                    else if (code == DNP3_DIRECTION_BIT_SET){
                        state = "DNP3_DIRECTION_BIT_SET";
                    }
                    else if (code == MODBUS_STATE_FOUND){
                        state = "MODBUS_STATE_FOUND";
                    }
                    else if (code == DNP3_FUNCTION_CODE_MATCHED){
                        state = "DNP3_FUNCTION_CODE_MATCHED";
                    }
                    else if (code == MODBUS_STATE_INSERTED){
                        state = "MODBUS_STATE_INSERTED";
                    }
                   

                    if (state)
                    {
                        sprintf(message, "%s : %s : %s : %s :%s:%d > %s:%d outbound_tracking ---> %s\n", ts, ifname,
                                (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, ntohs(evt->sport), daddr, ntohs(evt->dport), state);
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                }
                else if (evt->proto == IPPROTO_ICMP && ifname)
                {
                    char *state = NULL;
                    __u16 code = evt->tracking_code;
                    __u8 inner_ttl = evt->dest[0];
                    __u8 outer_ttl = evt->source[0];
                    if (code == ICMP_MATCHED_ACTIVE_STATE)
                    {
                        state = "ICMP_MATCHED_ACTIVE_STATE";
                    }
                    else if (code == ICMP_MATCHED_EXPIRED_STATE)
                    {
                        state = "ICMP_MATCHED_EXPIRED_STATE";
                    }
                    else if (code == CLIENT_INITIATED_ICMP_ECHO)
                    {
                        state = "CLIENT_INITIATED_ICMP_ECHO";
                    }
                    if(state)
                    {
                        sprintf(message, "%s : %s : %s : %s : %s > %s outbound_tracking ICMP %s ---> %s\n", ts, ifname,
                                (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, daddr,(evt->direction == INGRESS) ? "ECHO-REPLY" : "ECHO" ,state);
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                    else if (code == 4)
                    {
                        /*evt->sport is use repurposed store next hop mtu*/
                        sprintf(message, "%s : %s : %s : %s :%s --> reported next hop mtu:%d > FRAGMENTATION NEEDED IN PATH TO:%s:%d\n", ts, ifname,
                                (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, ntohs(evt->sport), daddr, ntohs(evt->dport));
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                    else
                    {
                        char *code_string = NULL;
                        char *protocol_string = NULL;
                        if (evt->dest[1] == IPPROTO_TCP)
                        {
                            protocol_string = "TCP";
                        }
                        else
                        {
                            protocol_string = "UDP";
                        }
                        if (code == 0)
                        {
                            code_string = "NET UNREACHABLE";
                        }
                        else if (code == 1)
                        {
                            code_string = "HOST UNREACHABLE";
                        }
                        else if (code == 2)
                        {
                            code_string = "PROTOCOL UNREACHABLE";
                        }
                        else if (code == 3)
                        {
                            code_string = "PORT UNREACHABLE";
                        }

                        if (code_string)
                        {
                            sprintf(message, "%s : %s : %s : %s :%s --> REPORTED:%s > in PATH TO:%s:%s:%d OUTER-TTL:%d INNER-TTL:%d\n", ts, ifname,
                                    (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, code_string, daddr, protocol_string, ntohs(evt->dport), outer_ttl, inner_ttl);
                            if (logging)
                            {
                                res = write_log(log_file_name, message);
                            }
                            else
                            {
                                printf("%s", message);
                            }
                        }
                    }
                }
                else if (ifname)
                {
                    sprintf(message, "%s : %s : %s : %s :%s:%d > %s:%d\n", ts, ifname,
                            (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr, ntohs(evt->sport), daddr, ntohs(evt->dport));
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                if (saddr)
                {
                    free(saddr);
                }
                if (daddr)
                {
                    free(daddr);
                }
            }
            if (ts)
            {
                free(ts);
            }
        }
        else
        {
            if (evt->error_code)
            {
                if (evt->error_code == IP6_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : IPv6 Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == UDP_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : UDP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == ICMP_HEADER_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : ICMP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
                else if (evt->error_code == IPV6_TUPLE_TOO_BIG)
                {
                    sprintf(message, "%s : %s : %s : ICMP Inner IP Header Too Big\n", ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS");
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
            }
            else
            {
                char saddr6[INET6_ADDRSTRLEN];
                char daddr6[INET6_ADDRSTRLEN];
                struct in6_addr saddr_6 = {0};
                struct in6_addr daddr_6 = {0};
                memcpy(saddr_6.__in6_u.__u6_addr32, evt->saddr, sizeof(evt->saddr));
                memcpy(daddr_6.__in6_u.__u6_addr32, evt->daddr, sizeof(evt->daddr));
                inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &daddr_6, daddr6, INET6_ADDRSTRLEN);
                char *protocol;
                if (evt->proto == IPPROTO_TCP)
                {
                    protocol = "TCP";
                }
                else if (evt->proto == IPPROTO_ICMP)
                {
                    protocol = "ICMP";
                }
                else
                {
                    protocol = "UDP";
                }
                if (evt->tun_ifindex && ifname)
                {
                    char tbuf[IF_NAMESIZE];
                    char *tun_ifname = if_indextoname(evt->tun_ifindex, tbuf);
                    if (tun_ifname)
                    {
                        sprintf(message, "%s : %s : %s : %s :%s:%d[%x:%x:%x:%x:%x:%x] > %s:%d[%x:%x:%x:%x:%x:%x] redirect ---> %s\n",
                         ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr6, ntohs(evt->sport),
                                evt->source[0], evt->source[1], evt->source[2], evt->source[3], evt->source[4], evt->source[5], daddr6, ntohs(evt->dport),
                                evt->dest[0], evt->dest[1], evt->dest[2], evt->dest[3], evt->dest[4], evt->dest[5], tun_ifname);
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                }
                else if (evt->tport && ifname)
                {
                    sprintf(message, "%s : %s : %s : %s :%s:%d > %s:%d | tproxy ---> ::1:%d\n",
                            ts, ifname, (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr6, ntohs(evt->sport),
                            daddr6, ntohs(evt->dport), ntohs(evt->tport));
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }else if (((evt->proto == IPPROTO_TCP) | (evt->proto == IPPROTO_UDP)) && evt->tracking_code && ifname)
                {
                    char *state = NULL;
                    __u16 code = evt->tracking_code;

                    if (code == SERVER_SYN_ACK_RCVD)
                    {
                        state = "SERVER_SYN_ACK_RCVD";
                    }
                    else if (code == SERVER_FIN_RCVD)
                    {
                        state = "SERVER_FIN_RCVD";
                    }
                    else if (code == SERVER_RST_RCVD)
                    {
                        state = "SERVER_RST_RCVD";
                    }
                    else if (code == SERVER_FINAL_ACK_RCVD)
                    {
                        state = "SERVER_FINAL_ACK_RCVD";
                    }
                    else if (code == UDP_MATCHED_EXPIRED_STATE)
                    {
                        state = "UDP_MATCHED_EXPIRED_STATE";
                    }
                    else if (code == UDP_MATCHED_ACTIVE_STATE)
                    {
                        state = "UDP_MATCHED_ACTIVE_STATE";
                    }
                    else if (code == CLIENT_SYN_RCVD)
                    {
                        state = "CLIENT_SYN_RCVD";
                    }
                    else if (code == CLIENT_FIN_RCVD)
                    {
                        state = "CLIENT_FIN_RCVD";
                    }
                    else if (code == CLIENT_RST_RCVD)
                    {
                        state = "CLIENT_RST_RCVD";
                    }
                    else if (code == TCP_CONNECTION_ESTABLISHED)
                    {
                        state = "TCP_CONNECTION_ESTABLISHED";
                    }
                    else if (code == CLIENT_FINAL_ACK_RCVD)
                    {
                        state = "CLIENT_FINAL_ACK_RCVD";
                    }
                    else if (code == CLIENT_INITIATED_UDP_SESSION)
                    {
                        state = "CLIENT_INITIATED_UDP_SESSION";
                    }
                    else if (code == INGRESS_INITIATED_UDP_SESSION)
                    {
                        state = "INGRESS_INITIATED_UDP_SESSION";
                    }
                    else if (code == INGRESS_UDP_MATCHED_EXPIRED_STATE)
                    {
                        state = "INGRESS_UDP_MATCHED_EXPIRED_STATE";
                    }
                    else if (code == INGRESS_UDP_MATCHED_ACTIVE_STATE)
                    {
                        state = "INGRESS_UDP_MATCHED_ACTIVE_STATE";
                    }
                    else if (code == INGRESS_CLIENT_SYN_RCVD)
                    {
                        state = "INGRESS_CLIENT_SYN_RCVD";
                    }else if (code == INGRESS_CLIENT_FIN_RCVD)
                    {
                        state = "INGRESS_CLIENT_FIN_RCVD";
                    }else if (code == INGRESS_CLIENT_RST_RCVD)
                    {
                        state = "INGRESS_CLIENT_RST_RCVD";
                    }else if (code == INGRESS_SERVER_RST_RCVD)
                    {
                        state = "INGRESS_SERVER_RST_RCVD";
                    }else if (code == INGRESS_TCP_CONNECTION_ESTABLISHED)
                    {
                        state = "INGRESS_TCP_CONNECTION_ESTABLISHED";
                    }else if (code == INGRESS_CLIENT_FINAL_ACK_RCVD)
                    {
                        state = "INGRESS_CLIENT_FINAL_ACK_RCVD";
                    }else if (code == INGRESS_SERVER_SYN_ACK_RCVD)
                    {
                        state = "INGRESS_SERVER_SYN_ACK_RCVD";
                    }else if (code == INGRESS_SERVER_FIN_RCVD)
                    {
                        state = "INGRESS_SERVER_FIN_RCVD";
                    }
                    else if (code == INGRESS_SERVER_FINAL_ACK_RCVD)
                    {
                        state = "INGRESS_SERVER_FINAL_ACK_RCVD";
                    }
                    else if (code == MATCHED_DROP_FILTER)
                    {
                        state = "MATCHED_DROP_FILTER";
                    }
                    else if (code == REVERSE_MASQUERADE_ENTRY_ADDED)
                    {
                        state = "REVERSE_MASQUERADE_ENTRY_ADDED";
                    }
                    else if (code == REVERSE_MASQUERADE_ENTRY_REMOVED)
                    {
                        state = "REVERSE_MASQUERADE_ENTRY_REMOVED";
                    }
                    else if (code == MASQUERADE_ENTRY_ADDED)
                    {
                        state = "MASQUERADE_ENTRY_ADDED";
                    }
                    else if (code == MASQUERADE_ENTRY_REMOVED)
                    {
                        state = "MASQUERADE_ENTRY_REMOVED";
                    }


                    if (state)
                    {
                        sprintf(message, "%s : %s : %s : %s :%s:%d > %s:%d outbound_tracking ---> %s\n", ts, ifname,
                                (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr6, ntohs(evt->sport), daddr6, ntohs(evt->dport), state);
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                }else if (evt->proto == IPPROTO_ICMPV6 && ifname)
                {
                    char *state = NULL;
                    __u16 code = evt->tracking_code;
                    if (code == ICMP_MATCHED_ACTIVE_STATE)
                    {
                        state = "ICMP_MATCHED_ACTIVE_STATE";
                    }
                    else if (code == ICMP_MATCHED_EXPIRED_STATE)
                    {
                        state = "ICMP_MATCHED_EXPIRED_STATE";
                    }
                    else if (code == CLIENT_INITIATED_ICMP_ECHO)
                    {
                        state = "CLIENT_INITIATED_ICMP_ECHO";
                    }
                    if(state)
                    {
                        sprintf(message, "%s : %s : %s : %s : %s > %s outbound_tracking ICMP %s ---> %s\n", ts, ifname,
                                (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr6, daddr6,(evt->direction == INGRESS) ? "ECHO-REPLY" : "ECHO" ,state);
                        if (logging)
                        {
                            res = write_log(log_file_name, message);
                        }
                        else
                        {
                            printf("%s", message);
                        }
                    }
                }
                else if (ifname)
                {
                    sprintf(message, "%s : %s : %s : %s :%s:%d > %s:%d\n", ts, ifname,
                            (evt->direction == INGRESS) ? "INGRESS" : "EGRESS", protocol, saddr6, ntohs(evt->sport), daddr6, ntohs(evt->dport));
                    if (logging)
                    {
                        res = write_log(log_file_name, message);
                    }
                    else
                    {
                        printf("%s", message);
                    }
                }
            }
            if (ts)
            {
                free(ts);
            }
        }
    }
    if (res)
    {
        printf("Unable to write to log\n");
        if (ring_buffer)
        {
            ring_buffer__free(ring_buffer);
            close_maps(1);
        }
    }
    fflush(stdout);
    return 0;
}

void set_tp_ext_data(struct tproxy_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tp_ext_map_path;
    }else{
        map.pathname = (uint64_t)egress_ext_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    struct tproxy_extension_mapping ext_value = {0};
    char *sid = "0000000000000000000000";
    if (service)
    {
        memcpy(ext_value.service_id, service_string, strlen(service_string) + 1);
    }
    else
    {
        memcpy(ext_value.service_id, sid, strlen(sid) + 1);
    }
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&ext_value;
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM_DATA: %s \n", strerror(errno));
    }
    close(fd);
}

void set_if_list_ext_data(struct port_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)if_list_ext_map_path;
    }else{
        map.pathname = (uint64_t)egress_if_list_ext_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    struct if_list_extension_mapping ext_value = {0};
    if (interface)
    {
        for (int x = 0; x < MAX_IF_LIST_ENTRIES; x++)
        {
            ext_value.if_list[x] = if_list[x];
        }
    }
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&ext_value;
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM_DATA: %s \n", strerror(errno));
    }
    close(fd);
}

void set_range(struct port_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)range_map_path;
    }else{
        map.pathname = (uint64_t)egress_range_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    struct range_mapping range_ports = {0};
    range_ports.high_port = htons(high_port),
    range_ports.tproxy_port = htons(tproxy_port);
    if(disable){
        range_ports.deny = true;
    }else{
        range_ports.deny = false;
    }
    map.value = (uint64_t)&range_ports;
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM_DATA: %s \n", strerror(errno));
    }
    close(fd);
}

void map_insert6()
{
    if (low_port > high_port)
    {
        printf("INSERT FAILURE -- INVALID PORT RANGE: low_port(%u) > high_port(%u)\n", low_port, high_port);
        close_maps(1);
    }
    if (get_key_count6() == BPF_MAX_ENTRIES)
    {
        printf("INSERT FAILURE -- MAX PREFIX TUPLES REACHED\n");
        close_maps(1);
    }
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    struct tproxy6_key *key = (struct tproxy6_key *)malloc(sizeof(struct tproxy6_key));
    memset(key, 0, sizeof(struct tproxy6_key));
    memcpy(key->dst_ip, dcidr6.__in6_u.__u6_addr32, sizeof(key->dst_ip));
    memcpy(key->src_ip, scidr6.__in6_u.__u6_addr32, sizeof(key->src_ip));
    key->dprefix_len = dplen;
    key->sprefix_len = splen;
    key->protocol = protocol;
    key->pad = 0;
    struct tproxy_tuple *rule = (struct tproxy_tuple *)malloc(sizeof(struct tproxy_tuple));
    memset(rule, 0, sizeof(struct tproxy_tuple));
    struct tproxy_tuple *orule = (struct tproxy_tuple *)malloc(sizeof(struct tproxy_tuple));
    memset(orule, 0, sizeof(struct tproxy_tuple));
    /* set path name with location of map in filesystem */
    if(!egress){
        map.pathname = (uint64_t)tproxy6_map_path;
    }else{
        map.pathname = (uint64_t)egress6_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    /* make system call to get fd for map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        free(key);
        free(rule);
        free(orule);
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)orule;
    /* make system call to lookup prefix/mask in map */
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short *index = (unsigned short *)malloc(sizeof(unsigned short));
    memset(index, 0, sizeof(unsigned short));
    *index = htons(low_port);
    struct port_extension_key port_ext_key = {0};
    memcpy(port_ext_key.__in46_u_dst.ip6, dcidr6.__in6_u.__u6_addr32, sizeof(dcidr6.__in6_u.__u6_addr32));
    memcpy(port_ext_key.__in46_u_src.ip6, scidr6.__in6_u.__u6_addr32, sizeof(scidr6.__in6_u.__u6_addr32));
    port_ext_key.low_port = htons(low_port);
    port_ext_key.dprefix_len = dplen;
    port_ext_key.sprefix_len = splen;
    port_ext_key.protocol = protocol;
    port_ext_key.type = 6;
    if (protocol == IPPROTO_UDP)
    {
        printf("Adding UDP mapping\n");
    }
    else if (protocol == IPPROTO_TCP)
    {
        printf("Adding TCP mapping\n");
    }
    else
    {
        printf("Unsupported Protocol\n");
        free(key);
        free(index);
        free(rule);
        free(orule);
        close(fd);
        close_maps(1);
    }
    if (lookup)
    {
        /* create a new tproxy prefix entry and add port range to it */
        rule->index_len = 1;
        rule->index_table[0] = *index;
        map.value = (uint64_t)rule;
        union bpf_attr count_map;
        memset(&count_map, 0, sizeof(count_map));
        /* set path name with location of map in filesystem */
        if(!egress){
            count_map.pathname = (uint64_t)count6_map_path;
        }else{
            count_map.pathname = (uint64_t)egress_count6_map_path;
        }
        count_map.bpf_fd = 0;
        count_map.file_flags = 0;
        /* make system call to get fd for map */
        int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
        if (count_fd == -1)
        {
            printf("BPF_OBJ_GET: %s \n", strerror(errno));
            free(key);
            free(index);
            free(rule);
            free(orule);
            close(fd);
            close_maps(1);
        }
        uint32_t count_key = 0;
        uint32_t count_value = 0;
        count_map.map_fd = count_fd;
        count_map.key = (uint64_t)&count_key;
        count_map.value = (uint64_t)&count_value;
        int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
        if (!lookup)
        {
            count_value++;
            count_map.flags = BPF_ANY;
            int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
            if (result)
            {
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            }
        }
        close(count_fd);
    }
    else
    {
        /* modify existing prefix entry and add or modify existing port mapping entry  */
        printf("lookup success\n");
        /*clear existing if_list_key if present*/
        if_list_ext_delete_key(port_ext_key);
        add_index(*index, orule);
    }
    free(index);
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        free(key);
        free(rule);
        free(orule);
        close(fd);
        close_maps(1);
    }
    free(key);
    free(rule);
    free(orule);
    close(fd);
    struct tproxy_extension_key tp_ext_key = {
        htons(tproxy_port),
        protocol,
        0};
    set_tp_ext_data(tp_ext_key);
    set_range(port_ext_key);
    /*add if_list_mapping*/
    if (interface)
    {
        set_if_list_ext_data(port_ext_key);
    }
}

void map_insert()
{
    if (low_port > high_port)
    {
        printf("INSERT FAILURE -- INVALID PORT RANGE: low_port(%u) > high_port(%u)\n", low_port, high_port);
        close_maps(1);
    }
    if (get_key_count() == BPF_MAX_ENTRIES)
    {
        printf("INSERT FAILURE -- MAX PREFIX TUPLES REACHED\n");
        close_maps(1);
    }
    bool route_insert = false;
    if (route && !egress)
    {
        route_insert = interface_map();
    }
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    struct tproxy_key *key = (struct tproxy_key *)malloc(sizeof(struct tproxy_key));
    memset(key, 0, sizeof(struct tproxy_key));
    key->dst_ip = dcidr.s_addr;
    key->src_ip = scidr.s_addr;
    key->dprefix_len = dplen;
    key->sprefix_len = splen;
    key->protocol = protocol;
    key->pad = 0;
    struct tproxy_tuple *rule = (struct tproxy_tuple *)malloc(sizeof(struct tproxy_tuple));
    memset(rule, 0, sizeof(struct tproxy_tuple));
    struct tproxy_tuple *orule = (struct tproxy_tuple *)malloc(sizeof(struct tproxy_tuple));
    memset(orule, 0, sizeof(struct tproxy_tuple));
    /* set path name with location of map in filesystem */
    if(!egress){
        map.pathname = (uint64_t)tproxy_map_path;
    }else{
        map.pathname = (uint64_t)egress_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    /* make system call to get fd for map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        free(key);
        free(rule);
        free(orule);
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)orule;
    /* make system call to lookup prefix/mask in map */
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short *index = (unsigned short *)malloc(sizeof(unsigned short));
    memset(index, 0, sizeof(unsigned short));
    *index = htons(low_port);
    struct port_extension_key port_ext_key = {0};
    port_ext_key.__in46_u_dst.ip = dcidr.s_addr;
    port_ext_key.__in46_u_src.ip = scidr.s_addr;
    port_ext_key.low_port = htons(low_port);
    port_ext_key.dprefix_len = dplen;
    port_ext_key.sprefix_len = splen;
    port_ext_key.protocol = protocol;
    port_ext_key.type = 4;
    if (protocol == IPPROTO_UDP)
    {
        printf("Adding UDP mapping\n");
    }
    else if (protocol == IPPROTO_TCP)
    {
        printf("Adding TCP mapping\n");
    }
    else
    {
        printf("Unsupported Protocol\n");
        free(key);
        free(index);
        free(rule);
        free(orule);
        close(fd);
        close_maps(1);
    }
    if (lookup)
    {
        /* create a new tproxy prefix entry and add port range to it */
        rule->index_len = 1;
        rule->index_table[0] = *index;
        map.value = (uint64_t)rule;
        union bpf_attr count_map;
        memset(&count_map, 0, sizeof(count_map));
        /* set path name with location of map in filesystem */
        if(!egress){
            count_map.pathname = (uint64_t)count_map_path;
        }else{
            count_map.pathname = (uint64_t)egress_count_map_path;
        }
        count_map.bpf_fd = 0;
        count_map.file_flags = 0;
        /* make system call to get fd for map */
        int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
        if (count_fd == -1)
        {
            printf("BPF_OBJ_GET: %s \n", strerror(errno));
            free(key);
            free(index);
            free(rule);
            free(orule);
            close(fd);
            close_maps(1);
        }
        uint32_t count_key = 0;
        uint32_t count_value = 0;
        count_map.map_fd = count_fd;
        count_map.key = (uint64_t)&count_key;
        count_map.value = (uint64_t)&count_value;
        int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
        if (!lookup)
        {
            count_value++;
            count_map.flags = BPF_ANY;
            int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
            if (result)
            {
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            }
        }
        close(count_fd);
        if (route_insert)
        {
            bind_prefix(&dcidr, dplen);
        }
    }
    else
    {
        /* modify existing prefix entry and add or modify existing port mapping entry  */
        printf("lookup success\n");
        /*clear existing if_list_key if present*/
        if_list_ext_delete_key(port_ext_key);
        add_index(*index, orule);
    }
    free(index);
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        free(key);
        free(rule);
        free(orule);
        close(fd);
        close_maps(1);
    }
    free(key);
    free(rule);
    free(orule);
    close(fd);
    struct tproxy_extension_key tp_ext_key = {
        htons(tproxy_port),
        protocol,
        0};
    set_tp_ext_data(tp_ext_key);
    set_range(port_ext_key);
    /*add if_list_mapping*/
    if (interface)
    {
        set_if_list_ext_data(port_ext_key);
    }
}

void if_delete_key(uint32_t key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)if_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    else
    {
        printf("Pruned index %u from ifindex_map\n", key);
    }
    close(fd);
}

void if_list_ext_delete_key(struct port_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)if_list_ext_map_path;
    }else{
        map.pathname = (uint64_t)egress_if_list_ext_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (!result && !flush)
    {
        printf("cleared if_list_ext_map entry\n");
    }
    close(fd);
}

void range_delete_key(struct port_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)range_map_path;
    }else{
        map.pathname = (uint64_t)egress_range_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if ((!result) && (!flush))
    {
        char *saddr;
        char *daddr;
        if (key.type == 4)
        {
            saddr = nitoa(ntohl(key.__in46_u_src.ip));
            daddr = nitoa(ntohl(key.__in46_u_dst.ip));
            if (saddr && daddr)
            {
                printf("cleared range_map entry: Range dest=%s/%u, source=%s/%u, protocol=%s, low_port=%u\n", daddr, key.dprefix_len, saddr,
                       key.sprefix_len, key.protocol == 6 ? "tcp" : "udp", htons(key.low_port));
            }
            if (saddr)
            {
                free(saddr);
            }
            if (daddr)
            {
                free(daddr);
            }
        }
        else
        {
            char saddr6[INET6_ADDRSTRLEN];
            char daddr6[INET6_ADDRSTRLEN];
            struct in6_addr saddr_6 = {0};
            struct in6_addr daddr_6 = {0};
            memcpy(saddr_6.__in6_u.__u6_addr32, key.__in46_u_src.ip6, sizeof(key.__in46_u_src.ip6));
            memcpy(daddr_6.__in6_u.__u6_addr32, key.__in46_u_dst.ip6, sizeof(key.__in46_u_dst.ip6));
            inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &daddr_6, daddr6, INET6_ADDRSTRLEN);
            printf("cleared range_map entry: Range dest=%s/%u, source=%s/%u, protocol=%s, low_port=%u\n", daddr6, key.dprefix_len, saddr6,
                   key.sprefix_len, key.protocol == 6 ? "tcp" : "udp", htons(key.low_port));
        }
    }
    close(fd);
}

void tp_ext_delete_key(struct tproxy_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tp_ext_map_path;
    }else{
        map.pathname = (uint64_t)egress_ext_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if ((!result) && (!flush))
    {
        printf("cleared tp_ext_map entry\n");
    }
    close(fd);
}

void diag_delete_key(uint32_t key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)diag_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    else
    {
        printf("Pruned index %u from diag_map\n", key);
    }
    close(fd);
}

void map_delete6_key(struct tproxy6_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy6_map_path;
    }else{
        map.pathname = (uint64_t)egress6_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    close(fd);
}

void map_delete_key(struct tproxy_key key)
{
    char *prefix = nitoa(ntohl(key.dst_ip));
    inet_aton(prefix, &dcidr);
    dplen = key.dprefix_len;
    free(prefix);
    bool route_delete = false;
    if (route && !egress)
    {
        route_delete = interface_map();
    }
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy_map_path;
    }else{
        map.pathname = (uint64_t)egress_map_path;
    }
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
    }
    else
    {
        if (route && route_delete)
        {
            unbind_prefix(&dcidr, dplen);
        }
    }
    close(fd);
}

void map_delete6()
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    struct tproxy6_key *key = (struct tproxy6_key *)malloc(sizeof(struct tproxy6_key));
    memset(key, 0, sizeof(struct tproxy6_key));
    memcpy(key->dst_ip, dcidr6.__in6_u.__u6_addr32, sizeof(key->dst_ip));
    memcpy(key->src_ip, scidr6.__in6_u.__u6_addr32, sizeof(key->src_ip));
    key->dprefix_len = dplen;
    key->sprefix_len = splen;
    key->protocol = protocol;
    key->pad = 0;
    struct tproxy_tuple *orule = (struct tproxy_tuple *)malloc(sizeof(struct tproxy_tuple));
    memset(orule, 0, sizeof(struct tproxy_tuple));
    if(!egress){
        map.pathname = (uint64_t)tproxy6_map_path;
    }else{
        map.pathname = (uint64_t)egress6_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    struct port_extension_key port_ext_key = {0};
    memcpy(port_ext_key.__in46_u_dst.ip6, dcidr6.__in6_u.__u6_addr32, sizeof(dcidr6.__in6_u.__u6_addr32));
    memcpy(port_ext_key.__in46_u_src.ip6, scidr6.__in6_u.__u6_addr32, sizeof(scidr6.__in6_u.__u6_addr32));
    port_ext_key.low_port = htons(low_port);
    port_ext_key.dprefix_len = dplen;
    port_ext_key.sprefix_len = splen;
    port_ext_key.protocol = protocol;
    port_ext_key.type = 6;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)orule;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(low_port);
    if (lookup)
    {
        printf("MAP_LOOKUP_v6_DEL_ELEM: %s\n", strerror(errno));
        free(key);
        free(orule);
        close_maps(1);
    }
    else
    {
        printf("lookup success\n");
        if (protocol == IPPROTO_UDP)
        {
            printf("Attempting to remove UDP mapping\n");
        }
        else if (protocol == IPPROTO_TCP)
        {
            printf("Attempting to remove TCP mapping\n");
        }
        else
        {
            printf("Unsupported Protocol\n");
            close(fd);
            free(orule);
            free(key);
            close_maps(1);
        }
        remove_index(index, orule);
        if (orule->index_len == 0)
        {
            memset(&map, 0, sizeof(map));
            if(!egress){
                map.pathname = (uint64_t)tproxy6_map_path;
            }else{
                map.pathname = (uint64_t)egress6_map_path;
            }
            map.bpf_fd = 0;
            int end_fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (end_fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                free(key);
                free(orule);
                close_maps(1);
            }
            // delete element with specified key
            map.map_fd = end_fd;
            map.key = (uint64_t)key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_V6_LAST_ELEM: %s\n", strerror(errno));
                close(end_fd);
                close(fd);
                free(orule);
                free(key);
                close_maps(1);
            }
            else
            {
                union bpf_attr count_map;
                memset(&count_map, 0, sizeof(count_map));
                /* set path name with location of map in filesystem */
                if(!egress){
                    count_map.pathname = (uint64_t)count6_map_path;
                }else{
                    count_map.pathname = (uint64_t)egress_count6_map_path;
                }
                count_map.bpf_fd = 0;
                count_map.file_flags = 0;
                /* make system call to get fd for map */
                int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
                if (count_fd == -1)
                {
                    printf("BPF_OBJ_GET: %s \n", strerror(errno));
                    free(key);
                    close(end_fd);
                    close(fd);
                    free(orule);
                    close_maps(1);
                }
                uint32_t count_key = 0;
                uint32_t count_value = 0;
                count_map.map_fd = count_fd;
                count_map.key = (uint64_t)&count_key;
                count_map.value = (uint64_t)&count_value;
                int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
                if (!lookup)
                {
                    count_value--;
                    count_map.flags = BPF_ANY;
                    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
                    if (result)
                    {
                        printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                    }
                }
                close(count_fd);
                printf("Last Element: Hash Entry Deleted\n");
                close(end_fd);
                close(fd);
                free(orule);
                free(key);
                range_delete_key(port_ext_key);
                if_list_ext_delete_key(port_ext_key);
                close_maps(0);
            }
        }
        map.value = (uint64_t)orule;
        map.flags = BPF_ANY;
        /*Flush Map changes to system -- Needed when removing an entry that is not the last range associated
         *with a prefix/protocol pair*/
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            close(fd);
            free(orule);
            close_maps(1);
        }
    }
    free(orule);
    free(key);
    close(fd);
    range_delete_key(port_ext_key);
    if_list_ext_delete_key(port_ext_key);
}

void map_delete()
{
    bool route_delete = false;
    if (route && !egress)
    {
        route_delete = interface_map();
    }
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    struct tproxy_key *key = (struct tproxy_key *)malloc(sizeof(struct tproxy_key));
    memset(key, 0, sizeof(struct tproxy_key));
    key->dst_ip = dcidr.s_addr;
    key->src_ip = scidr.s_addr;
    key->dprefix_len = dplen;
    key->sprefix_len = splen;
    key->protocol = protocol;
    key->pad = 0;
    struct tproxy_tuple *orule = (struct tproxy_tuple *)malloc(sizeof(struct tproxy_tuple));
    memset(orule, 0, sizeof(struct tproxy_tuple));
    if(!egress){
        map.pathname = (uint64_t)tproxy_map_path;
    }
    else{
        map.pathname = (uint64_t)egress_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    struct port_extension_key port_ext_key = {0};
    port_ext_key.__in46_u_dst.ip = dcidr.s_addr;
    port_ext_key.__in46_u_src.ip = scidr.s_addr;
    port_ext_key.low_port = htons(low_port);
    port_ext_key.dprefix_len = dplen;
    port_ext_key.sprefix_len = splen;
    port_ext_key.protocol = protocol;
    port_ext_key.type = 4;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)orule;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(low_port);
    if (lookup)
    {
        printf("MAP_LOOKUP_v4_DEL_ELEM: %s\n", strerror(errno));
        free(key);
        free(orule);
        close_maps(1);
    }
    else
    {
        printf("lookup success\n");
        if (protocol == IPPROTO_UDP)
        {
            printf("Attempting to remove UDP mapping\n");
        }
        else if (protocol == IPPROTO_TCP)
        {
            printf("Attempting to remove TCP mapping\n");
        }
        else
        {
            printf("Unsupported Protocol\n");
            close(fd);
            free(orule);
            free(key);
            close_maps(1);
        }
        remove_index(index, orule);
        if (orule->index_len == 0)
        {
            memset(&map, 0, sizeof(map));
            if(!egress){
                map.pathname = (uint64_t)tproxy_map_path;
            }else{
                map.pathname = (uint64_t)egress_map_path;
            }
            map.bpf_fd = 0;
            int end_fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (end_fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                free(key);
                free(orule);
                close_maps(1);
            }
            // delete element with specified key
            map.map_fd = end_fd;
            map.key = (uint64_t)key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_V4_LAST_ELEM: %s\n", strerror(errno));
                close(end_fd);
                close(fd);
                free(orule);
                free(key);
                close_maps(1);
            }
            else
            {
                union bpf_attr count_map;
                memset(&count_map, 0, sizeof(count_map));
                /* set path name with location of map in filesystem */
                if(!egress){
                    count_map.pathname = (uint64_t)count_map_path;
                }else{
                    count_map.pathname = (uint64_t)egress_count_map_path;
                }
                count_map.bpf_fd = 0;
                count_map.file_flags = 0;
                /* make system call to get fd for map */
                int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
                if (count_fd == -1)
                {
                    printf("BPF_OBJ_GET: %s \n", strerror(errno));
                    free(key);
                    close(end_fd);
                    close(fd);
                    free(orule);
                    close_maps(1);
                }
                uint32_t count_key = 0;
                uint32_t count_value = 0;
                count_map.map_fd = count_fd;
                count_map.key = (uint64_t)&count_key;
                count_map.value = (uint64_t)&count_value;
                int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
                if (!lookup)
                {
                    count_value--;
                    count_map.flags = BPF_ANY;
                    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
                    if (result)
                    {
                        printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                    }
                }
                close(count_fd);
                printf("Last Element: Hash Entry Deleted\n");
                if (route_delete)
                {
                    unbind_prefix(&dcidr, dplen);
                }
                close(end_fd);
                close(fd);
                free(orule);
                free(key);
                range_delete_key(port_ext_key);
                if_list_ext_delete_key(port_ext_key);
                close_maps(0);
            }
        }
        map.value = (uint64_t)orule;
        map.flags = BPF_ANY;
        /*Flush Map changes to system -- Needed when removing an entry that is not the last range associated
         *with a prefix/protocol pair*/
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            close(fd);
            free(orule);
            close_maps(1);
        }
    }
    free(orule);
    free(key);
    close(fd);
    range_delete_key(port_ext_key);
    if_list_ext_delete_key(port_ext_key);
}

struct masq_value get_reverse_masquerade(struct masq_reverse_key key){
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)masquerade_reverse_map_path;
    map.bpf_fd = 0;
    struct masq_value mstate = {0};
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return mstate;
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&mstate;
    syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    close(fd);
    return mstate;
}

struct masq_value get_masquerade(struct masq_key key){
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)masquerade_map_path;
    map.bpf_fd = 0;
    struct masq_value mstate = {0};
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return mstate;
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&mstate;
    syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    close(fd);
    return mstate;
}

void del_reverse_masq(struct masq_reverse_key key){
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)masquerade_reverse_map_path;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    close(fd);
}

void del_masq(struct masq_key key){
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)masquerade_map_path;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    close(fd);
}

void tcp_egress_map_delete_key(struct tuple_key *key)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tcp_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    struct tcp_state tstate = {0};
    map.value = (uint64_t)&tstate;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    if(!lookup){
        //delete masquerade state if tstamp is more than 3600 seconds old
        struct masq_reverse_key rk = {0};
        rk.dport = key->dport;
        rk.sport = key->sport;
        rk.ifindex = key->ifindex;
        rk.__in46_u_dest.ip = key->__in46_u_dst.ip;
        rk.__in46_u_src.ip = key->__in46_u_src.ip;
        rk.protocol = IPPROTO_TCP;
        struct masq_value rv = get_reverse_masquerade(rk);
        if(rv.o_sport){
            char *saddr = nitoa(ntohl(key->__in46_u_src.ip));
            char *daddr = nitoa(ntohl(key->__in46_u_dst.ip));
            if(saddr && daddr){
                printf("found tcp egress masquerade -> source: %s | dest: %s | sport: %d | dport: %d, ifindex: %u age (sec): %lld\n" 
                    , saddr, daddr, ntohs(key->sport), ntohs(key->dport), key->ifindex,
                    ((long long)((ts.tv_sec * 1000000000) + ts.tv_nsec) -  tstate.tstamp)/1000000000);
            }
            if(saddr){
                free(saddr);
            }
            if(daddr){
                free(daddr);
            }
            if((((ts.tv_sec * 1000000000) + ts.tv_nsec) - tstate.tstamp) > 3600000000000){
                struct masq_reverse_key rk = {0};
                rk.dport = key->dport;
                rk.sport = key->sport;
                rk.ifindex = key->ifindex;
                rk.__in46_u_dest.ip = key->__in46_u_dst.ip;
                rk.__in46_u_src.ip = key->__in46_u_src.ip;
                rk.protocol = IPPROTO_TCP;
                struct masq_value rv = get_reverse_masquerade(rk);
                if(rv.o_sport){

                    struct masq_key mk = {0};
                    mk.dport = key->dport;
                    mk.sport = rv.o_sport;
                    mk.__in46_u_dest.ip = key->__in46_u_dst.ip;
                    mk.ifindex = key->ifindex;
                    mk.protocol = IPPROTO_TCP;
                    del_masq(mk);
                }
                del_reverse_masq(rk);
            }
        }
    }
    close(fd);
}

void tcp_ipv6_egress_map_delete_key(struct tuple_key *key)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tcp_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    struct tcp_state tstate = {0};
    map.value = (uint64_t)&tstate;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    if(!lookup){
        struct masq_key mk = {0};
        mk.dport = key->dport;
        mk.sport = key->sport;
        memcpy(mk.__in46_u_dest.ip6, key->__in46_u_dst.ip6, sizeof(key->__in46_u_dst.ip6));
        mk.ifindex = key->ifindex;
        mk.protocol = IPPROTO_TCP;
        struct masq_value mv = get_masquerade(mk);
        //delete masquerade state if tstamp is more than 3600 seconds old
        if(mv.__in46_u_origin.ip6[0]){
            char saddr6[INET6_ADDRSTRLEN];
            char daddr6[INET6_ADDRSTRLEN];
            struct in6_addr saddr_6 = {0};
            struct in6_addr daddr_6 = {0};
            memcpy(saddr_6.__in6_u.__u6_addr32, key->__in46_u_src.ip6, sizeof(key->__in46_u_src.ip6));
            memcpy(daddr_6.__in6_u.__u6_addr32, key->__in46_u_dst.ip6, sizeof(key->__in46_u_dst.ip6));
            inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &daddr_6, daddr6, INET6_ADDRSTRLEN);
            printf("found ipv6 tcp egress masquerade -> source: %s | dest: %s | sport: %d | dport: %d, ifindex: %u age (sec): %lld\n" 
                , saddr6, daddr6, ntohs(key->sport), ntohs(key->dport), key->ifindex,
                 ((long long)((ts.tv_sec * 1000000000) + ts.tv_nsec) -  tstate.tstamp)/1000000000);
            if((((ts.tv_sec * 1000000000) + ts.tv_nsec) - tstate.tstamp) > 3600000000000){
                del_masq(mk);
            }
        }
    }
    close(fd);
}

void udp_egress_map_delete_key(struct tuple_key *key)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)udp_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    struct udp_state ustate = {0};
    map.value = (uint64_t)&ustate;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    if(!lookup){
        //delete masquerade state if tstamp is more than 30 seconds old
        struct masq_reverse_key rk = {0};
        rk.dport = key->dport;
        rk.sport = key->sport;
        rk.ifindex = key->ifindex;
        rk.__in46_u_dest.ip = key->__in46_u_dst.ip;
        rk.__in46_u_src.ip = key->__in46_u_src.ip;
        rk.protocol = IPPROTO_UDP;
        struct masq_value rv = get_reverse_masquerade(rk);
        if(rv.o_sport){
            char *saddr = nitoa(ntohl(key->__in46_u_src.ip));
            char *daddr = nitoa(ntohl(key->__in46_u_dst.ip));
            if(saddr && daddr){
                printf("found udp egress masquerade -> source: %s | dest: %s | sport: %d | dport: %d, ifindex: %u age (sec): %lld\n" 
                    , saddr, daddr, ntohs(key->sport), ntohs(key->dport), key->ifindex,
                    ((long long)((ts.tv_sec * 1000000000) + ts.tv_nsec) -  ustate.tstamp)/1000000000);
            }
            if(saddr){
                free(saddr);
            }
            if(daddr){
                free(daddr);
            }
            if(((((ts.tv_sec * 1000000000) + ts.tv_nsec) - ustate.tstamp) > 30000000000) && rv.o_sport)
            {
                struct masq_key mk = {0};
                mk.dport = key->dport;
                mk.sport = rv.o_sport;
                mk.__in46_u_dest.ip = key->__in46_u_dst.ip;
                mk.ifindex = key->ifindex;
                mk.protocol = IPPROTO_UDP;
                del_masq(mk);
                del_reverse_masq(rk);
            }
        }
    }
    close(fd);
}

void udp_ipv6_egress_map_delete_key(struct tuple_key *key)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)udp_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    struct udp_state ustate = {0};
    map.value = (uint64_t)&ustate;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    if(!lookup){
        struct masq_key mk = {0};
        mk.dport = key->dport;
        mk.sport = key->sport;
        memcpy(mk.__in46_u_dest.ip6, key->__in46_u_dst.ip6, sizeof(key->__in46_u_dst.ip6));
        mk.ifindex = key->ifindex;
        mk.protocol = IPPROTO_UDP;
        struct masq_value mv = get_masquerade(mk);
        //delete masquerade state if tstamp is more than 30 seconds old
        if(mv.__in46_u_origin.ip6[0]){
            char saddr6[INET6_ADDRSTRLEN];
            char daddr6[INET6_ADDRSTRLEN];
            struct in6_addr saddr_6 = {0};
            struct in6_addr daddr_6 = {0};
            memcpy(saddr_6.__in6_u.__u6_addr32, key->__in46_u_src.ip6, sizeof(key->__in46_u_src.ip6));
            memcpy(daddr_6.__in6_u.__u6_addr32, key->__in46_u_dst.ip6, sizeof(key->__in46_u_dst.ip6));
            inet_ntop(AF_INET6, &saddr_6, saddr6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &daddr_6, daddr6, INET6_ADDRSTRLEN);
            printf("found ipv6 udp egress masquerade -> source: %s | dest: %s | sport: %d | dport: %d, ifindex: %u age (sec): %lld\n" 
                , saddr6, daddr6, ntohs(key->sport), ntohs(key->dport), key->ifindex,
                 ((long long)((ts.tv_sec * 1000000000) + ts.tv_nsec) -  ustate.tstamp)/1000000000);
            if((((ts.tv_sec * 1000000000) + ts.tv_nsec) - ustate.tstamp) > 30000000000){
                del_masq(mk);
            }
        }
    }
    close(fd);
}

void map_flush6()
{
    union bpf_attr map;
    struct tproxy6_key init_key = {0};
    struct tproxy6_key *key = &init_key;
    struct tproxy6_key current_key;
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy6_key *)map.key;
        map_delete6_key(current_key);
    }
    close(fd);
    union bpf_attr tp_map;
    struct tproxy_extension_key tp_init_key = {0};
    struct tproxy_extension_key *tp_key = &tp_init_key;
    struct tproxy_extension_key tp_current_key;
    struct tproxy_extension_mapping tp_orule;
    // Open BPF zt_tproxy_map map
    memset(&tp_map, 0, sizeof(tp_map));
    tp_map.pathname = (uint64_t)tp_ext_map_path;
    tp_map.bpf_fd = 0;
    tp_map.file_flags = 0;
    int tp_fd = syscall(__NR_bpf, BPF_OBJ_GET, &tp_map, sizeof(tp_map));
    if (tp_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    tp_map.map_fd = tp_fd;
    tp_map.key = (uint64_t)tp_key;
    tp_map.value = (uint64_t)&tp_orule;
    int tp_ret = 0;
    while (true)
    {
        tp_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &tp_map, sizeof(tp_map));
        if (tp_ret == -1)
        {
            break;
        }
        tp_map.key = tp_map.next_key;
        tp_current_key = *(struct tproxy_extension_key *)tp_map.key;
        tp_ext_delete_key(tp_current_key);
    }
    close(tp_fd);
    union bpf_attr ra_map;
    struct port_extension_key ra_init_key = {0};
    struct port_extension_key *ra_key = &ra_init_key;
    struct port_extension_key ra_current_key;
    struct range_mapping ra_orule;
    // Open BPF zt_tproxy_map map
    memset(&ra_map, 0, sizeof(ra_map));
    ra_map.pathname = (uint64_t)range_map_path;
    ra_map.bpf_fd = 0;
    ra_map.file_flags = 0;
    int ra_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ra_map, sizeof(ra_map));
    if (ra_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    ra_map.map_fd = ra_fd;
    ra_map.key = (uint64_t)ra_key;
    ra_map.value = (uint64_t)&ra_orule;
    int ra_ret = 0;
    while (true)
    {
        ra_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &ra_map, sizeof(ra_map));
        if (ra_ret == -1)
        {
            break;
        }
        ra_map.key = ra_map.next_key;
        ra_current_key = *(struct port_extension_key *)ra_map.key;
        range_delete_key(ra_current_key);
    }
    close(ra_fd);
    union bpf_attr ix_map;
    struct port_extension_key ix_init_key = {0};
    struct port_extension_key *ix_key = &ix_init_key;
    struct port_extension_key ix_current_key;
    struct if_list_extension_mapping ix_orule;
    // Open BPF zt_tproxy_map map
    memset(&ix_map, 0, sizeof(ix_map));
    ix_map.pathname = (uint64_t)if_list_ext_map_path;
    ix_map.bpf_fd = 0;
    ix_map.file_flags = 0;
    int ix_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ix_map, sizeof(ix_map));
    if (ix_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    ix_map.map_fd = ix_fd;
    ix_map.key = (uint64_t)ix_key;
    ix_map.value = (uint64_t)&ix_orule;
    int ix_ret = 0;
    while (true)
    {
        ix_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &ix_map, sizeof(ix_map));
        if (ix_ret == -1)
        {
            break;
        }
        ix_map.key = ix_map.next_key;
        ix_current_key = *(struct port_extension_key *)ix_map.key;
        if_list_ext_delete_key(ix_current_key);
    }
    close(ix_fd);
    union bpf_attr count_map;
    memset(&count_map, 0, sizeof(count_map));
    /* set path name with location of map in filesystem */
    count_map.pathname = (uint64_t)count_map_path;
    count_map.bpf_fd = 0;
    count_map.file_flags = 0;
    /* make system call to get fd for map */
    int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
    if (count_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    uint32_t count_key = 0;
    uint32_t count_value = 0;
    count_map.map_fd = count_fd;
    count_map.key = (uint64_t)&count_key;
    count_map.value = (uint64_t)&count_value;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
    if (!lookup)
    {
        count_value = 0;
        count_map.flags = BPF_ANY;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        }
    }
    close(count_fd);
}

int flush6()
{
    union bpf_attr map;
    struct tproxy6_key init_key = {0};
    struct tproxy6_key *key = &init_key;
    struct tproxy6_key current_key;
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy6_map_path;
    }else{
        map.pathname = (uint64_t)egress6_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return 1;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy6_key *)map.key;
        map_delete6_key(current_key);
    }
    close(fd);
    union bpf_attr count_map;
    memset(&count_map, 0, sizeof(count_map));
    /* set path name with location of map in filesystem */
    if(!egress){
        count_map.pathname = (uint64_t)count6_map_path;
    }else{
        count_map.pathname = (uint64_t)egress_count6_map_path;
    }
    count_map.bpf_fd = 0;
    count_map.file_flags = 0;
    /* make system call to get fd for map */
    int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
    if (count_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    uint32_t count_key = 0;
    uint32_t count_value = 0;
    count_map.map_fd = count_fd;
    count_map.key = (uint64_t)&count_key;
    count_map.value = (uint64_t)&count_value;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
    if (!lookup)
    {
        count_value = 0;
        count_map.flags = BPF_ANY;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        }
    }
    close(count_fd);
    union bpf_attr tp_map;
    struct tproxy_extension_key tp_init_key = {0};
    struct tproxy_extension_key *tp_key = &tp_init_key;
    struct tproxy_extension_key tp_current_key;
    struct tproxy_extension_mapping tp_orule;
    // Open BPF zt_tproxy_map map
    memset(&tp_map, 0, sizeof(tp_map));
    if(egress){
        tp_map.pathname = (uint64_t)egress_ext_map_path;
    }else{
        tp_map.pathname = (uint64_t)tp_ext_map_path;
    }
    tp_map.bpf_fd = 0;
    tp_map.file_flags = 0;
    int tp_fd = syscall(__NR_bpf, BPF_OBJ_GET, &tp_map, sizeof(tp_map));
    if (tp_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    tp_map.map_fd = tp_fd;
    tp_map.key = (uint64_t)tp_key;
    tp_map.value = (uint64_t)&tp_orule;
    int tp_ret = 0;
    while (true)
    {
        tp_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &tp_map, sizeof(tp_map));
        if (tp_ret == -1)
        {
            break;
        }
        tp_map.key = tp_map.next_key;
        tp_current_key = *(struct tproxy_extension_key *)tp_map.key;
        tp_ext_delete_key(tp_current_key);
    }
    close(tp_fd);
    union bpf_attr ra_map;
    struct port_extension_key ra_init_key = {0};
    struct port_extension_key *ra_key = &ra_init_key;
    struct port_extension_key ra_current_key;
    struct range_mapping ra_orule;
    // Open BPF zt_tproxy_map map
    memset(&ra_map, 0, sizeof(ra_map));
    if(egress){
        ra_map.pathname = (uint64_t)egress_range_map_path;
    }else{
        ra_map.pathname = (uint64_t)range_map_path;
    }
    ra_map.bpf_fd = 0;
    ra_map.file_flags = 0;
    int ra_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ra_map, sizeof(ra_map));
    if (ra_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    ra_map.map_fd = ra_fd;
    ra_map.key = (uint64_t)ra_key;
    ra_map.value = (uint64_t)&ra_orule;
    int ra_ret = 0;
    while (true)
    {
        ra_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &ra_map, sizeof(ra_map));
        if (ra_ret == -1)
        {
            break;
        }
        ra_map.key = ra_map.next_key;
        ra_current_key = *(struct port_extension_key *)ra_map.key;
        range_delete_key(ra_current_key);
    }
    close(ra_fd);
    union bpf_attr ix_map;
    struct port_extension_key ix_init_key = {0};
    struct port_extension_key *ix_key = &ix_init_key;
    struct port_extension_key ix_current_key;
    struct if_list_extension_mapping ix_orule;
    // Open BPF zt_tproxy_map map
    memset(&ix_map, 0, sizeof(ix_map));
    if(egress){
        ix_map.pathname = (uint64_t)egress_if_list_ext_map_path;
    }else{
        ix_map.pathname = (uint64_t)if_list_ext_map_path;
    }
    ix_map.bpf_fd = 0;
    ix_map.file_flags = 0;
    int ix_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ix_map, sizeof(ix_map));
    if (ix_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    ix_map.map_fd = ix_fd;
    ix_map.key = (uint64_t)ix_key;
    ix_map.value = (uint64_t)&ix_orule;
    int ix_ret = 0;
    while (true)
    {
        ix_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &ix_map, sizeof(ix_map));
        if (ix_ret == -1)
        {
            break;
        }
        ix_map.key = ix_map.next_key;
        ix_current_key = *(struct port_extension_key *)ix_map.key;
        if_list_ext_delete_key(ix_current_key);
    }
    close(ix_fd);
    return 0;
}

int flush4()
{
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy_map_path;
    }else{
        map.pathname = (uint64_t)egress_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return 1;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy_key *)map.key;
        map_delete_key(current_key);
    }
    close(fd);
    union bpf_attr count_map;
    memset(&count_map, 0, sizeof(count_map));
    /* set path name with location of map in filesystem */
    if(!egress){
        count_map.pathname = (uint64_t)count_map_path;
    }else{
        count_map.pathname = (uint64_t)egress_count_map_path;
    }
    count_map.bpf_fd = 0;
    count_map.file_flags = 0;
    /* make system call to get fd for map */
    int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
    if (count_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    uint32_t count_key = 0;
    uint32_t count_value = 0;
    count_map.map_fd = count_fd;
    count_map.key = (uint64_t)&count_key;
    count_map.value = (uint64_t)&count_value;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
    if (!lookup)
    {
        count_value = 0;
        count_map.flags = BPF_ANY;
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &count_map, sizeof(count_map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        }
    }
    close(count_fd);
    union bpf_attr tp_map;
    struct tproxy_extension_key tp_init_key = {0};
    struct tproxy_extension_key *tp_key = &tp_init_key;
    struct tproxy_extension_key tp_current_key;
    struct tproxy_extension_mapping tp_orule;
    // Open BPF zt_tproxy_map map
    memset(&tp_map, 0, sizeof(tp_map));
    if(egress){
        tp_map.pathname = (uint64_t)egress_ext_map_path;
    }else{
        tp_map.pathname = (uint64_t)tp_ext_map_path;
    }
    tp_map.bpf_fd = 0;
    tp_map.file_flags = 0;
    int tp_fd = syscall(__NR_bpf, BPF_OBJ_GET, &tp_map, sizeof(tp_map));
    if (tp_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    tp_map.map_fd = tp_fd;
    tp_map.key = (uint64_t)tp_key;
    tp_map.value = (uint64_t)&tp_orule;
    int tp_ret = 0;
    while (true)
    {
        tp_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &tp_map, sizeof(tp_map));
        if (tp_ret == -1)
        {
            break;
        }
        tp_map.key = tp_map.next_key;
        tp_current_key = *(struct tproxy_extension_key *)tp_map.key;
        tp_ext_delete_key(tp_current_key);
    }
    close(tp_fd);
    union bpf_attr ra_map;
    struct port_extension_key ra_init_key = {0};
    struct port_extension_key *ra_key = &ra_init_key;
    struct port_extension_key ra_current_key;
    struct range_mapping ra_orule;
    // Open BPF zt_tproxy_map map
    memset(&ra_map, 0, sizeof(ra_map));
    if(egress){
        ra_map.pathname = (uint64_t)egress_range_map_path;
    }else{
        ra_map.pathname = (uint64_t)range_map_path;
    }
    ra_map.bpf_fd = 0;
    ra_map.file_flags = 0;
    int ra_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ra_map, sizeof(ra_map));
    if (ra_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    ra_map.map_fd = ra_fd;
    ra_map.key = (uint64_t)ra_key;
    ra_map.value = (uint64_t)&ra_orule;
    int ra_ret = 0;
    while (true)
    {
        ra_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &ra_map, sizeof(ra_map));
        if (ra_ret == -1)
        {
            break;
        }
        ra_map.key = ra_map.next_key;
        ra_current_key = *(struct port_extension_key *)ra_map.key;
        range_delete_key(ra_current_key);
    }
    close(ra_fd);
    union bpf_attr ix_map;
    struct port_extension_key ix_init_key = {0};
    struct port_extension_key *ix_key = &ix_init_key;
    struct port_extension_key ix_current_key;
    struct if_list_extension_mapping ix_orule;
    // Open BPF zt_tproxy_map map
    memset(&ix_map, 0, sizeof(ix_map));
    if(egress){
        ix_map.pathname = (uint64_t)egress_if_list_ext_map_path;
    }else{
        ix_map.pathname = (uint64_t)if_list_ext_map_path;
    }
    ix_map.bpf_fd = 0;
    ix_map.file_flags = 0;
    int ix_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ix_map, sizeof(ix_map));
    if (ix_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    ix_map.map_fd = ix_fd;
    ix_map.key = (uint64_t)ix_key;
    ix_map.value = (uint64_t)&ix_orule;
    int ix_ret = 0;
    while (true)
    {
        ix_ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &ix_map, sizeof(ix_map));
        if (ix_ret == -1)
        {
            break;
        }
        ix_map.key = ix_map.next_key;
        ix_current_key = *(struct port_extension_key *)ix_map.key;
        if_list_ext_delete_key(ix_current_key);
    }
    close(ix_fd);
    return 0;
}

void map_flush()
{
    if(ingress && !egress){
        flush4();
        flush6();
    }else if(!ingress && !egress){
        flush4();
        flush6();
        if(!(access(egress6_map_path, F_OK) != 0)){
            egress = true;
            flush4();
            flush6();
        }
    }else{
        flush4();
        flush6();
    }
}

int flush_udp_egress()
{
    union bpf_attr map;
    struct tuple_key init_key = {0};
    struct tuple_key *key = &init_key;
    struct tuple_key current_key = {0};
    struct udp_state ostate;
    // Open BPF udp_map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)udp_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return 1;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&ostate;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tuple_key *)map.key;
        struct tuple_key *pass_key = malloc(sizeof(struct tuple_key));
        memcpy(pass_key,&current_key, sizeof(struct tuple_key));
        if(current_key.type == 4){
            udp_egress_map_delete_key(pass_key);
        }
        else{
            udp_ipv6_egress_map_delete_key(pass_key);
        }
        free(pass_key);
    }
    close(fd);
    return 0;
}

int flush_tcp_egress()
{
    union bpf_attr map;
    struct tuple_key init_key = {0};
    struct tuple_key *key = &init_key;
    struct tuple_key current_key = {0};
    struct udp_state ostate;
    // Open BPF tcp_map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tcp_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return 1;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&ostate;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tuple_key *)map.key;
        struct tuple_key *pass_key = malloc(sizeof(struct tuple_key));
        memcpy(pass_key,&current_key, sizeof(struct tuple_key));
        if(current_key.type == 4){
            tcp_egress_map_delete_key(pass_key);
        }
        else{
            tcp_ipv6_egress_map_delete_key(pass_key);
        }
        free(pass_key);
    }
    close(fd);
    return 0;
}

int flush_bind()
{
    union bpf_attr map;
    struct bind_key init_key = {0};
    struct bind_key *key = &init_key;
    struct bind_key current_key = {0};
    bool bstate;
    // Open BPF tcp_map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)bind_saddr_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return 1;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&bstate;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            break;
        }
        map.key = map.next_key;
        current_key = *(struct bind_key *)map.key;
        struct bind_key *pass_key = malloc(sizeof(struct bind_key));
        memcpy(pass_key,&current_key, sizeof(struct bind_key));
        delete_bind_saddr_map(pass_key);
        free(pass_key);
    }
    close(fd);
    return 0;
}

void map_list()
{
    union bpf_attr map;
    struct tproxy_key key = {dcidr.s_addr, scidr.s_addr, dplen, splen, protocol, 0};
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy_map_path;
    }else{
        map.pathname = (uint64_t)egress_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    if(!egress){
        printf("INGRESS FILTERS:\n");
    }else{
        printf("EGRESS FILTERS:\n");
    }
    printf("%-7s%-22s\t%-3s\t%-20s\t%-32s%-24s\t\t\t\t%-32s\n", "type", "service id", "proto", "origin", "destination", "mapping:", "interface list");
    printf("------ ----------------------\t-----\t-----------------\t------------------\t\t-------------------------------------------------------\t-----------------\n");
    int rule_count = 0;
    if (prot)
    {
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            print_rule((struct tproxy_key *)map.key, &orule, &rule_count);
            printf("Rule Count: %d\n", rule_count);
        }
    }
    else
    {
        int vprot[] = {IPPROTO_UDP, IPPROTO_TCP};
        int x = 0;
        for (; x < 2; x++)
        {
            rule_count = 0;
            struct tproxy_key vkey = {dcidr.s_addr, scidr.s_addr, dplen, splen, vprot[x], 0};
            map.key = (uint64_t)&vkey;
            lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
            if (!lookup)
            {
                print_rule((struct tproxy_key *)map.key, &orule, &rule_count);
                printf("Rule Count: %d\n", rule_count);
                if (x == 0)
                {
                    printf("%-7s%-22s\t%-3s\t%-20s\t%-32s%-24s\t\t\t\t%-32s\n", "type", "service id", "proto", "origin", "destination", "mapping:", "interface list");
                    printf("------ ----------------------\t-----\t-----------------\t------------------\t\t-------------------------------------------------------\t-----------------\n");
                }
            }
        }
    }

    close(fd);
}

void map_list6()
{
    union bpf_attr map;
    struct tproxy6_key key = {0};
    memcpy(key.dst_ip, dcidr6.__in6_u.__u6_addr32, sizeof(key.dst_ip));
    memcpy(key.src_ip, scidr6.__in6_u.__u6_addr32, sizeof(key.src_ip));
    key.dprefix_len = dplen;
    key.sprefix_len = splen;
    key.protocol = protocol;
    key.pad = 0;
    struct tproxy_tuple orule;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy6_map_path;
    }else{
        map.pathname = (uint64_t)egress6_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    if(!egress){
        printf("INGRESS FILTERS:\n");
    }else{
        printf("EGRESS FILTERS:\n");
    }
    printf("%-7s%-23s%-6s%-43s%-45s%-28s%s\n", "type","service id", "proto", "origin", "destination", "mapping:", "interface list");
    printf("------ ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------\n");
    int rule_count = 0;
    if (prot)
    {
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            print_rule6((struct tproxy6_key *)map.key, &orule, &rule_count);
            printf("Rule Count: %d\n", rule_count);
        }
    }
    else
    {
        int vprot[] = {IPPROTO_UDP, IPPROTO_TCP};
        int x = 0;
        for (; x < 2; x++)
        {
            rule_count = 0;
            struct tproxy6_key vkey = {0};
            memcpy(vkey.dst_ip, dcidr6.__in6_u.__u6_addr32, sizeof(vkey.dst_ip));
            memcpy(vkey.src_ip, scidr6.__in6_u.__u6_addr32, sizeof(vkey.src_ip));
            vkey.dprefix_len = dplen;
            vkey.sprefix_len = splen;
            vkey.protocol = vprot[x];
            vkey.pad = 0;
            map.key = (uint64_t)&vkey;
            lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
            if (!lookup)
            {
                print_rule6((struct tproxy6_key *)map.key, &orule, &rule_count);
                printf("Rule Count: %d\n", rule_count);
                if (x == 0)
                {
                    printf("%-7s%-23s%-6s%-43s%-45s%-28s%s\n", "type","service id", "proto", "origin", "destination", "mapping:", "interface list");
                    printf("------ ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------\n");
                }
            }
        }
    }

    close(fd);
}

void ddos_saddr_map_list()
{
    if (ddos_saddr_fd == -1)
    {
        open_ddos_saddr_map();
    }
    union bpf_attr map;
    uint32_t init_key = 0;
    uint32_t *key = &init_key;
    uint32_t reference_key;
    uint32_t lookup_key;
    bool value;
    bool state;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)ddos_saddr_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&value;
    ddos_saddr_map.value = (uint64_t)&state;
    int lookup = 0;
    int ret = 0;
    int saddr_count = 0;
    ddos_saddr_map.map_fd = ddos_saddr_fd;
    printf("ddos source ip whitelist\n");
    printf("------------------------\n");
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            printf("------------------------\n");
            printf("address count: %d\n", saddr_count);
            break;
        }
        map.key = map.next_key;
        reference_key = *(uint32_t *)map.key;
        lookup_key = *(uint32_t *)map.key;
        ddos_saddr_map.key = (uint64_t)&lookup_key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &ddos_saddr_map, sizeof(ddos_saddr_map));
        if (!lookup)
        {
            char *sprefix = nitoa(ntohl(lookup_key));
            if (sprefix)
            {
                printf("host: %s\n", sprefix);
                free(sprefix);
            }
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&reference_key;
        saddr_count++;
    }
    close(fd);
}

void ddos_dport_map_list()
{
    if (ddos_dport_fd == -1)
    {
        open_ddos_dport_map();
    }
    union bpf_attr map;
    uint16_t init_key = 0;
    uint16_t *key = &init_key;
    uint16_t reference_key;
    uint16_t lookup_key;
    bool value;
    bool state;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)ddos_dport_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&value;
    ddos_dport_map.value = (uint64_t)&state;
    int lookup = 0;
    int ret = 0;
    int dport_count = 0;
    ddos_dport_map.map_fd = ddos_dport_fd;
    printf("ddos destination port list\n");
    printf("-------------------------------\n");
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            printf("-------------------------------\n");
            printf("port count: %d\n", dport_count);
            break;
        }
        map.key = map.next_key;
        reference_key = *(uint16_t *)map.key;
        lookup_key = *(uint16_t *)map.key;
        ddos_dport_map.key = (uint64_t)&lookup_key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &ddos_dport_map, sizeof(ddos_dport_map));
        if (!lookup)
        {
            printf("%d\n", ntohs(lookup_key));
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&reference_key;
        dport_count++;
    }
    close(fd);
}

void dnp3_fcode_map_list()
{
    if (dnp3_fcode_fd == -1)
    {
        open_dnp3_fcode_map();
    }
    union bpf_attr map;
    uint8_t init_key = 0;
    uint8_t *key = &init_key;
    uint8_t reference_key;
    uint8_t lookup_key;
    uint32_t value;
    uint32_t state;
    // Open BPF zt_tproxy_map map
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)dnp3_fcode_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&value;
    dnp3_fcode_map.value = (uint64_t)&state;
    int lookup = 0;
    int ret = 0;
    int fcode_count = 0;
    dnp3_fcode_map.map_fd = dnp3_fcode_fd;
    printf("dnp3 function code allow list\n");
    printf("-------------------------------\n");
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            printf("-------------------------------\n");
            printf("fcode count: %d\n", fcode_count);
            break;
        }
        map.key = map.next_key;
        reference_key = *(uint8_t *)map.key;
        lookup_key = *(uint8_t *)map.key;
        dnp3_fcode_map.key = (uint64_t)&lookup_key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
        if (!lookup)
        {
            printf("%d (0x%x): instantiations: %d\n", lookup_key, lookup_key, state);
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&reference_key;
        fcode_count++;
    }
    close(fd);
}

int get_key_count6()
{
    union bpf_attr count_map;
    memset(&count_map, 0, sizeof(count_map));
    /* set path name with location of map in filesystem */
    if(!egress){
        count_map.pathname = (uint64_t)count6_map_path;
    }else{
        count_map.pathname = (uint64_t)egress_count6_map_path;
    }
    count_map.bpf_fd = 0;
    count_map.file_flags = 0;
    /* make system call to get fd for map */
    int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
    if (count_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    uint32_t count_key = 0;
    uint32_t count_value = 0;
    count_map.map_fd = count_fd;
    count_map.key = (uint64_t)&count_key;
    count_map.value = (uint64_t)&count_value;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
    if (!lookup)
    {
        return count_value;
    }
    close(count_fd);
    return 0;
}

int get_key_count()
{
    union bpf_attr count_map;
    memset(&count_map, 0, sizeof(count_map));
    /* set path name with location of map in filesystem */
    if(!egress){
        count_map.pathname = (uint64_t)count_map_path;
    }else{
        count_map.pathname = (uint64_t)egress_count_map_path;
    }
    count_map.bpf_fd = 0;
    count_map.file_flags = 0;
    /* make system call to get fd for map */
    int count_fd = syscall(__NR_bpf, BPF_OBJ_GET, &count_map, sizeof(count_map));
    if (count_fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    uint32_t count_key = 0;
    uint32_t count_value = 0;
    count_map.map_fd = count_fd;
    count_map.key = (uint64_t)&count_key;
    count_map.value = (uint64_t)&count_value;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &count_map, sizeof(count_map));
    if (!lookup)
    {
        return count_value;
    }
    close(count_fd);
    return 0;
}

void map_list_all6()
{
    union bpf_attr map;
    struct tproxy6_key init_key = {0};
    struct tproxy6_key *key = &init_key;
    struct tproxy6_key current_key;
    struct tproxy_tuple orule;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy6_map_path;
    }else{
        map.pathname = (uint64_t)egress6_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    int ret = 0;
    if(!egress){
        printf("INGRESS FILTERS:\n");
    }else{
        printf("EGRESS FILTERS:\n");
    }
    printf("%-7s%-23s%-6s%-43s%-45s%-28s%s\n", "type","service id", "proto", "origin", "destination", "mapping:", "interface list");
    printf("------ ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------\n");
    int rule_count = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            printf("Rule Count: %d / %d\n", rule_count, BPF_MAX_RANGES);
            printf("prefix_tuple_count: %d / %d\n", get_key_count6(), BPF_MAX_ENTRIES);
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy6_key *)map.key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            print_rule6(&current_key, &orule, &rule_count);
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&current_key;
    }
    close(fd);
}

void map_list_all()
{
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    memset(&map, 0, sizeof(map));
    if(!egress){
        map.pathname = (uint64_t)tproxy_map_path;
    }else{
        map.pathname = (uint64_t)egress_map_path;
    }
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        close_maps(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    int ret = 0;
    if(!egress){
        printf("INGRESS FILTERS:\n");
    }else{
        printf("EGRESS FILTERS:\n");
    }
    printf("%-7s%-22s\t%-3s\t%-20s\t%-32s%-24s\t\t\t\t%-31s\n", "type","service id", "proto", "origin", "destination", "mapping:", "interface list");
    printf("------ ----------------------\t-----\t-----------------\t------------------\t\t-------------------------------------------------------\t-----------------\n");
    int rule_count = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            printf("Rule Count: %d / %d\n", rule_count, BPF_MAX_RANGES);
            printf("prefix_tuple_count: %d / %d\n", get_key_count(), BPF_MAX_ENTRIES);
            break;
        }
        map.key = map.next_key;
        current_key = *(struct tproxy_key *)map.key;
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            print_rule(&current_key, &orule, &rule_count);
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&current_key;
    }
    close(fd);
}

// commandline parser options
static struct argp_option options[] = {
    {"add-user-rules", 'A', NULL, 0, "Add user rules from /opt/openziti/bin/user/user_rules.sh", 0},
    {"bind-saddr-add", 'B', "", 0, "Bind loopback route with scope host", 0},
    {"list-dnp3-fcodes", 'C', NULL, 0, "List/Flush dnp3 fcodes allowed protect from DNP slaves", 0},
    {"delete", 'D', NULL, 0, "Delete map rule", 0},
    {"list-diag", 'E', NULL, 0, "", 0},
    {"flush", 'F', NULL, 0, "Flush all map rules", 0},
    {"list-gc-sessions", 'G', NULL, 0, "List masquerade sessions <optional argument used with -L, --list>", 0},
    {"insert", 'I', NULL, 0, "Insert map rule", 0},
    {"init-tc", 'H', "", 0, "sets ingress and egress tc filters for <interface | all>", 0},
    {"bind-saddr-delete", 'J', "", 0, "Unbind loopback route with scope host", 0},
    {"list", 'L', NULL, 0, "List map rules", 0},
    {"monitor", 'M', "", 0, "Monitor ebpf events for interface", 0},
    {"interface", 'N', "", 0, "Interface <optional insert>", 0},
    {"object-file", 'O', "", 0, "Set object file", 0},
    {"per-interface-rules", 'P', "", 0, "Set interface to per interface rule aware", 0},
    {"disable-ebpf", 'Q', NULL, 0, "Delete tc from all interface and remove all maps", 0},
    {"vrrp-enable", 'R', "", 0, "Enable vrrp passthrough on interface", 0},
    {"ot-filtering", 'S', "", 0, "Manually enable/disable ot advanced filtering on interface", 0},
    {"set-tun-mode", 'T', "", 0, "Set tun mode on interface", 0},
    {"list-ddos-dports", 'U', NULL, 0, "List destination ports to protect from DDOS", 0},
    {"write-log", 'W', "", 0, "Write to monitor output to /var/log/<log file name> <optional for monitor>", 0},
    {"set-tc-filter", 'X', "", 0, "Add/remove TC filter to/from interface", 0},
    {"list-ddos-saddr", 'Y', NULL, 0, "List source IP Addresses currently in DDOS IP whitelist", 0},
    {"init-xdp", 'Z', "", 0, "sets ingress xdp for <interface> (used for setting xdp on zet tun interface)", 0},
    {"ddos-filtering", 'a', "", 0, "Manually enable/disable ddos filtering on interface", 0},
    {"outbound-filtering", 'b', "", 0, "Manually enable/disable ddos filtering on interface", 0},
    {"ipv6-enable", '6', "", 0, "Enable/disable IPv6 packet processing on interface", 0},
    {"dcidr-block", 'c', "", 0, "Set dest ip prefix i.e. 192.168.1.0 <mandatory for insert/delete/list>", 0},
    {"disable", 'd', NULL, 0, "Disable associated diag operation or set rule type to deny", 0},
    {"icmp-echo", 'e', "", 0, "Enable inbound icmp echo to interface", 0},
    {"passthrough", 'f', NULL, 0, "List passthrough rules <optional list>", 0},
    {"high-port", 'h', "", 0, "Set high-port value (1-65535)> <mandatory for insert>", 0},
    {"intercepts", 'i', NULL, 0, "List intercept rules <optional for list>", 0},
    {"bind-flush", 'j', NULL, 0, "flush all bind routes <Requires -F, --flush>", 0},
    {"masquerade", 'k', "", 0, "enable outbound masquerade", 0},
    {"low-port", 'l', "", 0, "Set low-port value (1-65535)> <mandatory insert/delete>", 0},
    {"dprefix-len", 'm', "", 0, "Set dest prefix length (1-32) <mandatory for insert/delete/list >", 0},
    {"oprefix-len", 'n', "", 0, "Set origin prefix length (1-32) <mandatory for insert/delete/list >", 0},
    {"ocidr-block", 'o', "", 0, "Set origin ip prefix i.e. 192.168.1.0 <mandatory for insert/delete/list>", 0},
    {"protocol", 'p', "", 0, "Set protocol (tcp or udp) <mandatory insert/delete>", 0},
    {"pass-non-tuple", 'q', "", 0, "Pass all non-tuple to <interface | all>", 0},
    {"route", 'r', NULL, 0, "Add or Delete static ip/prefix for intercept dest to lo interface <optional insert/delete>", 0},
    {"service-id", 's', "", 0, "set ziti service id", 0},
    {"tproxy-port", 't', "", 0, "Set high-port value (0-65535)> <mandatory for insert>", 0},
    {"ddos-dport-add", 'u', "", 0, "Add destination port to DDOS port list i.e. (1-65535)", 0},
    {"dnp3-fcode-add", 'g', "", 0, "Add fcode to dnp3 fcode list i.e. (0-255)", 0},
    {"verbose", 'v', "", 0, "Enable verbose tracing on interface", 0},
    {"enable-eapol", 'w', "", 0, "enable 802.1X eapol packets inbound on interface", 0},
    {"disable-ssh", 'x', "", 0, "Disable inbound ssh to interface (default enabled)", 0},
    {"ddos-saddr-add", 'y', "", 0, "Add source IP Address to DDOS IP whitelist i.e. 192.168.1.1", 0},
    {"direction", 'z', "", 0, "Set direction", 0},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    program_name = state->name;
    uint32_t idx = 0;
    switch (key)
    {
    case 'A':
        user_rules = true;
        break;
    case 'B':
        bind_saddr = true;
        if (inet_aton(arg, &dcidr))
        {
            cd = true;
        }
        else if (inet_pton(AF_INET6, arg, &dcidr6))
        {
            cd6 = true;
        }
        else
        {
            fprintf(stderr, "Invalid IP Address for arg -B, --bind-saddr-add: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        break;
    case 'C':
        dnp3_fcode_list = true;
        break;
    case 'D':
        delete = true;
        break;
    case 'E':
        list_diag = true;
        all_interface = true;
        break;
    case 'F':
        flush = true;
        break;
    case 'G':
        list_gc = true;
        break;
    case 'H':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -H, --init-tc: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        init_tc = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                tc_interface = check_alt;
            }else{
                tc_interface = arg;
            }
        }
        break;
    case 'I':
        add = true;
        break;
    case 'J':
        unbind_saddr = true;
        if (inet_aton(arg, &dcidr))
        {
            cd = true;
        }
        else if (inet_pton(AF_INET6, arg, &dcidr6))
        {
            cd6 = true;
        }
        else
        {
            fprintf(stderr, "Invalid IP Address for arg -J, --bind-saddr-delete: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        break;
    case 'L':
        list = true;
        break;
    case 'M':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -M, --monitor: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            close_maps(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            close_maps(1);
        }
        monitor = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                monitor_interface = check_alt;
            }else{
                monitor_interface = arg;
            }
        }
        break;
    case 'N':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name required as arg to -N, --interface: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        interface = true;
        idx = if_nametoindex(arg);
        if (!idx)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        if (ifcount < MAX_IF_LIST_ENTRIES)
        {
            if ((idx > 0) && (idx <= UINT32_MAX))
            {
                if_list[ifcount] = idx;
            }
            else
            {
                printf("A rule can be assigned to interfaces with ifindex 1 - %d\n", MAX_IF_ENTRIES - 1);
            }
        }
        else
        {
            printf("A rule can be assigned to a maximum of %d interfaces\n", MAX_IF_LIST_ENTRIES);
            exit(1);
        }
        ifcount++;
        break;
    case 'O':
        if (arg[0] == '-')
        {
            fprintf(stderr, "object file name required as arg to -O, --object-file: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        object = true;
        object_file = arg;
        break;
    case 'P':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -P, --per-interface-rules: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        per_interface = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                prefix_interface = check_alt;
            }else{
                prefix_interface = arg;
            }
        }
        break;
    case 'Q':
        ebpf_disable = true;
        break;
    case 'R':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -R, --vrrp-enable: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        vrrp = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                vrrp_interface = check_alt;
            }else{
                vrrp_interface = arg;
            }
        }
        break;
    case 'S':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -S, --ot-filtering: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        ot_filter = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                ot_interface = check_alt;
            }else{
                ot_interface = arg;
            }
        }
        break;
    case 'T':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -T, --set-tun-mode: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        tun = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                tun_interface = check_alt;
            }else{
                tun_interface = arg;
            }
        }
        break;
    case 'U':
        ddos_dport_list = true;
        break;
    case 'W':
        if (arg[0] == '-')
        {
            fprintf(stderr, "logfile name -W, --write-log: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        logging = true;
        log_file_name = arg;
        break;
    case 'X':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -X, --set-tc-filter: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        tcfilter = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                tc_interface = check_alt;
            }else{
                tc_interface = arg;
            }
        }
        break;
    case 'Y':
        ddos_saddr_list = true;
        break;
    case 'Z':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -Z, --init-xdp: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        init_xdp = true;
        if(if_indextoname(idx, check_alt)){
            xdp_interface = check_alt;
        }else{
            xdp_interface = arg;
        }
        break;
    case 'a':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -a, --ddos-filter: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        ddos = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                ddos_interface = check_alt;
            }else{
                ddos_interface = arg;
            }
        }
        break;
    case 'b':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -b, --outbound-filtering: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        outbound = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                outbound_interface = check_alt;
            }else{
                outbound_interface = arg;
            }
        }
        break;
    case '6':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -6, --ipv6-enable: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        v6 = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                ipv6_interface = check_alt;
            }else{
                ipv6_interface = arg;
            }
        }
        break;
    case 'c':
        if (inet_aton(arg, &dcidr))
        {
            cd = true;
        }
        else if (inet_pton(AF_INET6, arg, &dcidr6))
        {
            cd6 = true;
        }
        else
        {
            fprintf(stderr, "Invalid IP Address for arg -c, --dcidr-block: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        break;
    case 'e':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -e, --icmp-echo: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        echo = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                echo_interface = check_alt;
            }else{
                echo_interface = arg;
            }
        }
        break;
    case 'd':
        disable = true;
        break;
    case 'f':
        passthru = true;
        break;
    case 'g':
        dnp3fc = true;
        dnp3_fcode = arg;
        break;
    case 'h':
        high_port = port2s(arg);
        hpt = true;
        break;
    case 'i':
        intercept = true;
        break;
    case 'j':
        bind_flush = true;
        break;
    case 'k':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -k, --masquerade: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        masquerade = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                masq_interface = check_alt;
            }else{
                masq_interface = arg;
            }
        }
        break;
    case 'l':
        low_port = port2s(arg);
        lpt = true;
        break;
    case 'm':
        dplen = len2u16(arg);
        dl = true;
        break;
    case 'n':
        splen = len2u16(arg);
        sl = true;
        break;
    case 'o':
        if (inet_aton(arg, &scidr))
        {
            cs = true;
        }
        else if (inet_pton(AF_INET6, arg, &scidr6))
        {
            cs6 = true;
        }
        else
        {
            fprintf(stderr, "Invalid IP Address for arg -o, --ocidr-block: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        break;
    case 'p':
        if ((strcmp("tcp", arg) == 0) || (strcmp("TCP", arg) == 0))
        {
            protocol = IPPROTO_TCP;
        }
        else if ((strcmp("udp", arg) == 0) || (strcmp("UDP", arg) == 0))
        {
            protocol = IPPROTO_UDP;
        }
        else
        {
            fprintf(stderr, "Invalid protocol for arg -p,--protocol <tcp|udp>\n");
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        protocol_name = arg;
        prot = true;
        break;
    case 'q':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -q, --pass-non-tuple: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        non_tuple = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                nt_interface = check_alt;
            }else{
                nt_interface = arg;
            }
        }
        break;
    case 'r':
        route = true;
        break;
    case 's':
        if (arg[0] == '-')
        {
            fprintf(stderr, "service id required as arg to -s, --service-id: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        if (strlen(arg) > 22)
        {
            printf("Invalid service ID: ID too long\n");
            exit(1);
        }
        service = true;
        service_string = arg;
        break;
    case 't':
        tproxy_port = port2s(arg);
        tpt = true;
        break;
    case 'u':
        ddport = true;
        ddos_dport = arg;
        break;
    case 'v':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -v, --verbose: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        verbose = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                verbose_interface = check_alt;
            }else{
                verbose_interface = arg;
            }
        }
        break;
    case 'w':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -w, --enable-eapol: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        eapol = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                eapol_interface = check_alt;
            }else{
                eapol_interface = arg;
            }
        }
        break;
    case 'x':
        if (arg[0] == '-')
        {
            fprintf(stderr, "Interface name or all required as arg to -x, --disable-ssh: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        idx = if_nametoindex(arg);
        if (strcmp("all", arg) && idx == 0)
        {
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        ssh_disable = true;
        if (!strcmp("all", arg))
        {
            all_interface = true;
        }
        else
        {
            if(if_indextoname(idx, check_alt)){
                ssh_interface = check_alt;
            }else{
                ssh_interface = arg;
            }
        }
        break;
    case 'y':
        if (!inet_aton(arg, &ddos_scidr))
        {
            fprintf(stderr, "Invalid IP Address for arg -Y, --ddos-saddr-add: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        dsip = true;
        ddos_saddr = arg;
        break;
    case 'z':
        if (strcmp("ingress", arg) && strcmp("egress", arg))
        {
            fprintf(stderr, "direction ingress/egress required as arg to -z, --direction: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        direction = true;
        direction_string = arg;
        if(!strcmp("egress", arg)){
            egress = true;
        }else{
            ingress = true;
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void zfw_init_tc(){
    tcfilter = true;
    char objpath[PATH_MAX];
    char *object_path = getenv("ZFW_OBJECT_PATH");
    if(object_path && strlen(object_path)){
        sprintf(objpath,"%s/%s", object_path, "zfw_tc_ingress.o");
        object_file = objpath;
    }else{
        object_file = "/opt/openziti/bin/zfw_tc_ingress.o";
    }
    ingress = true;
    direction_string = "ingress";
    interface_tc();
    ingress = false;
    if(object_path && strlen(object_path)){
        sprintf(objpath,"%s/%s", object_path, "zfw_tc_outbound_track.o");
        object_file = objpath;
    }else{
        object_file = "/opt/openziti/bin/zfw_tc_outbound_track.o";
    }
    egress = true;
    direction_string = "egress";
    interface_tc();
    close_maps(0);
}

void zfw_init_xdp(){
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "link", "set", xdp_interface, "xdpgeneric", "obj", "/opt/openziti/bin/zfw_xdp_tun_ingress.o", "sec", "xdp_redirect", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn bind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error binding xdp to %s\n", xdp_interface);
    }else{
        int status =0;
        if(!(waitpid(pid, &status, 0) < 0)){
            if(!(WIFEXITED(status) && !WEXITSTATUS(status))){
                printf("waitpid error: xdp not set on dev %s\n", xdp_interface);
            }
        }
    }
}

struct argp argp = {options, parse_opt, 0, doc, 0, 0, 0};

void close_maps(int code)
{
    if (diag_fd != -1)
    {
        close(diag_fd);
    }
    if(bind_saddr_fd != -1){
        close(bind_saddr_fd);
    }
    if (if_fd != -1)
    {
        close(if_fd);
    }
    if (tun_fd != -1)
    {
        close(if_fd);
    }
    if (rb_fd != -1)
    {
        close(rb_fd);
    }
    if (ddos_saddr_fd != -1)
    {
        close(ddos_saddr_fd);
    }
    if (ddos_dport_fd != -1)
    {
        close(ddos_dport_fd);
    }
    if (dnp3_fcode_fd != -1)
    {
        close(dnp3_fcode_fd);
    }
    if (tp_ext_fd != -1)
    {
        close(tp_ext_fd);
    }
    if (if_list_ext_fd != -1)
    {
        close(if_list_ext_fd);
    }
    if (if6_fd != -1)
    {
        close(if6_fd);
    }
    if (range_fd != -1)
    {
        close(range_fd);
    }
    if (egress_range_fd != -1)
    {
        close(egress_range_fd);
    }
    if (egress_if_list_ext_fd != -1)
    {
        close(egress_if_list_ext_fd);
    }
    if (egress_ext_fd != -1)
    {
        close(egress_ext_fd);
    }
    exit(code);
}

char *get_ts(unsigned long long tstamp)
{
    time_t ns;
    time_t s;
    struct timespec spec;
    const char *format = "%b %d %Y %H:%M:%S";
    clock_gettime(CLOCK_REALTIME, &spec);
    s = spec.tv_sec;
    ns = spec.tv_nsec;
    time_t now = s + (ns / 1000000000);
    char ftime[22];
    struct tm local_t;
    struct sysinfo si;
    sysinfo(&si);
    time_t t = (now + tstamp / 1000000000) - (time_t)si.uptime;
    time_t t_ns = tstamp % 1000000000;
    localtime_r(&t, &local_t);
    if (strftime(ftime, sizeof(ftime), format, &local_t) == 0)
    {
        return NULL;
    }
    char *result = malloc(31);
    sprintf(result, "%s.%09ld", ftime, t_ns);
    if (result)
    {
        return result;
    }
    else
    {
        return NULL;
    }
}

void open_ddos_saddr_map()
{
    memset(&ddos_saddr_map, 0, sizeof(ddos_saddr_map));
    ddos_saddr_map.pathname = (uint64_t)ddos_saddr_map_path;
    ddos_saddr_map.bpf_fd = 0;
    ddos_saddr_map.file_flags = 0;
    /* make system call to get fd for map */
    ddos_saddr_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ddos_saddr_map, sizeof(ddos_saddr_map));
    if (ddos_saddr_fd == -1)
    {
        ebpf_usage();
    }
}

void open_bind_saddr_map()
{
    memset(&bind_saddr_map, 0, sizeof(bind_saddr_map));
    bind_saddr_map.pathname = (uint64_t)bind_saddr_map_path;
    bind_saddr_map.bpf_fd = 0;
    bind_saddr_map.file_flags = 0;
    /* make system call to get fd for map */
    bind_saddr_fd = syscall(__NR_bpf, BPF_OBJ_GET, &bind_saddr_map, sizeof(bind_saddr_map));
    if (bind_saddr_fd == -1)
    {
        ebpf_usage();
    }
}

void open_range_map()
{
    memset(&range_map, 0, sizeof(range_map));
    range_map.pathname = (uint64_t)range_map_path;
    range_map.bpf_fd = 0;
    range_map.file_flags = 0;
    /* make system call to get fd for map */
    range_fd = syscall(__NR_bpf, BPF_OBJ_GET, &range_map, sizeof(range_map));
    if (range_fd == -1)
    {
        ebpf_usage();
    }
}

void open_egress_range_map()
{
    memset(&egress_range_map, 0, sizeof(egress_range_map));
    egress_range_map.pathname = (uint64_t)egress_range_map_path;
    egress_range_map.bpf_fd = 0;
    egress_range_map.file_flags = 0;
    /* make system call to get fd for map */
    egress_range_fd = syscall(__NR_bpf, BPF_OBJ_GET, &egress_range_map, sizeof(egress_range_map));
    if (egress_range_fd == -1)
    {
        ebpf_usage();
    }
}

void open_ddos_dport_map()
{
    memset(&ddos_dport_map, 0, sizeof(ddos_dport_map));
    ddos_dport_map.pathname = (uint64_t)ddos_dport_map_path;
    ddos_dport_map.bpf_fd = 0;
    ddos_dport_map.file_flags = 0;
    /* make system call to get fd for map */
    ddos_dport_fd = syscall(__NR_bpf, BPF_OBJ_GET, &ddos_dport_map, sizeof(ddos_dport_map));
    if (ddos_dport_fd == -1)
    {
        ebpf_usage();
    }
}

void open_dnp3_fcode_map()
{
    memset(&dnp3_fcode_map, 0, sizeof(dnp3_fcode_map));
    dnp3_fcode_map.pathname = (uint64_t)dnp3_fcode_map_path;
    dnp3_fcode_map.bpf_fd = 0;
    dnp3_fcode_map.file_flags = 0;
    /* make system call to get fd for map */
    dnp3_fcode_fd = syscall(__NR_bpf, BPF_OBJ_GET, &dnp3_fcode_map, sizeof(dnp3_fcode_map));
    if (dnp3_fcode_fd == -1)
    {
        ebpf_usage();
    }
}

void open_tproxy_ext_map()
{
    memset(&tp_ext_map, 0, sizeof(tp_ext_map));
    /* set path name with location of map in filesystem */
    tp_ext_map.pathname = (uint64_t)tp_ext_map_path;
    tp_ext_map.bpf_fd = 0;
    tp_ext_map.file_flags = 0;
    /* make system call to get fd for map */
    tp_ext_fd = syscall(__NR_bpf, BPF_OBJ_GET, &tp_ext_map, sizeof(tp_ext_map));
    if (tp_ext_fd == -1)
    {
        ebpf_usage();
    }
}

void open_egress_ext_map()
{
    memset(&egress_ext_map, 0, sizeof(egress_ext_map));
    /* set path name with location of map in filesystem */
    egress_ext_map.pathname = (uint64_t)egress_ext_map_path;
    egress_ext_map.bpf_fd = 0;
    egress_ext_map.file_flags = 0;
    /* make system call to get fd for map */
    egress_ext_fd = syscall(__NR_bpf, BPF_OBJ_GET, &egress_ext_map, sizeof(egress_ext_map));
    if (egress_ext_fd == -1)
    {
        ebpf_usage();
    }
}

void open_if_list_ext_map()
{
    memset(&if_list_ext_map, 0, sizeof(if_list_ext_map));
    /* set path name with location of map in filesystem */
    if_list_ext_map.pathname = (uint64_t)if_list_ext_map_path;
    if_list_ext_map.bpf_fd = 0;
    if_list_ext_map.file_flags = 0;
    /* make system call to get fd for map */
    if_list_ext_fd = syscall(__NR_bpf, BPF_OBJ_GET, &if_list_ext_map, sizeof(if_list_ext_map));
    if (if_list_ext_fd == -1)
    {
        ebpf_usage();
    }
}

void open_egress_if_list_ext_map()
{
    memset(&egress_if_list_ext_map, 0, sizeof(egress_if_list_ext_map));
    /* set path name with location of map in filesystem */
    egress_if_list_ext_map.pathname = (uint64_t)egress_if_list_ext_map_path;
    egress_if_list_ext_map.bpf_fd = 0;
    egress_if_list_ext_map.file_flags = 0;
    /* make system call to get fd for map */
    egress_if_list_ext_fd = syscall(__NR_bpf, BPF_OBJ_GET, &egress_if_list_ext_map, sizeof(egress_if_list_ext_map));
    if (egress_if_list_ext_fd == -1)
    {
        ebpf_usage();
    }
}

void open_diag_map()
{
    /*path to pinned ifindex_ip_map*/
    /* open BPF ifindex_ip_map */
    memset(&diag_map, 0, sizeof(diag_map));
    /* set path name with location of map in filesystem */
    diag_map.pathname = (uint64_t)diag_map_path;
    diag_map.bpf_fd = 0;
    diag_map.file_flags = 0;
    /* make system call to get fd for map */
    diag_fd = syscall(__NR_bpf, BPF_OBJ_GET, &diag_map, sizeof(diag_map));
    if (diag_fd == -1)
    {
        ebpf_usage();
    }
}

void open_if_map()
{
    memset(&if_map, 0, sizeof(if_map));
    /* set path name with location of map in filesystem */
    if_map.pathname = (uint64_t)if_map_path;
    if_map.bpf_fd = 0;
    if_map.file_flags = 0;
    /* make system call to get fd for map */
    if_fd = syscall(__NR_bpf, BPF_OBJ_GET, &if_map, sizeof(if_map));
    if (if_fd == -1)
    {
        ebpf_usage();
    }
}

void open_if6_map()
{
    memset(&if6_map, 0, sizeof(if6_map));
    /* set path name with location of map in filesystem */
    if6_map.pathname = (uint64_t)if6_map_path;
    if6_map.bpf_fd = 0;
    if6_map.file_flags = 0;
    /* make system call to get fd for map */
    if6_fd = syscall(__NR_bpf, BPF_OBJ_GET, &if6_map, sizeof(if6_map));
    if (if_fd == -1)
    {
        ebpf_usage();
    }
}

void open_rb_map()
{
    memset(&rb_map, 0, sizeof(rb_map));
    rb_map.pathname = (uint64_t)rb_map_path;
    rb_map.bpf_fd = 0;
    rb_map.file_flags = 0;
    /* make system call to get fd for map */
    rb_fd = syscall(__NR_bpf, BPF_OBJ_GET, &rb_map, sizeof(rb_map));
    if (rb_fd == -1)
    {
        ebpf_usage();
    }
}

void open_tun_map()
{
    memset(&tun_map, 0, sizeof(tun_map));
    tun_map.pathname = (uint64_t)if_tun_map_path;
    tun_map.bpf_fd = 0;
    tun_map.file_flags = 0;
    /* make system call to get fd for map */
    tun_fd = syscall(__NR_bpf, BPF_OBJ_GET, &tun_map, sizeof(tun_map));
    if (tun_fd == -1)
    {
        printf("BPF_OBJ_GET: tun_if_map %s \n", strerror(errno));
        close_maps(1);
    }
}

void egress_usage(){
    printf("No egress maps exist or not running as sudo!\n");
    printf("Ensure at least one interface has an egress filter enabled!\n");
    printf("e.g. sudo zfw -X ens33 -O /opt/openziti/bin/zfw_tc_outbound_track.o -z egress\n");
    close_maps(1);
}

void add_user_rules(){
    pid_t pid;
    char *const parmList[] = {"/opt/openziti/bin/user/user_rules.sh", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn bind");
        close_maps(1);
    }
    else if (pid == 0)
    {
        execv("/opt/openziti/bin/user/user_rules.sh", parmList);
        printf("execv error: unknown error adding user defined rules\n");
        close_maps(1);
    }else{
        int status =0;
        if(!(waitpid(pid, &status, 0) < 0)){
            if(!(WIFEXITED(status) && !WEXITSTATUS(status))){
                printf("waitpid error: adding user defined rules\n");
                close_maps(1);
            }
        }
    }
}

int main(int argc, char **argv)
{
    signal(SIGINT, INThandler);
    signal(SIGTERM, INThandler);
    argp_parse(&argp, argc, argv, 0, 0, 0);

    if(ot_filter){
        if( dnp3_fcode_list || dnp3fc || init_tc || init_xdp || non_tuple ||dsip || echo || ssh_disable || verbose || per_interface || add || delete || eapol || ddos || vrrp || 
            monitor || logging || ddport || masquerade || list || outbound || bind_saddr || unbind_saddr || ddport || init_xdp || tcfilter){
                usage("-S, --ot-filtering cannot be used in non related combination calls");
        }

    }

    if(user_rules){
        if ((access(tproxy_map_path, F_OK) != 0) || (access(tproxy6_map_path, F_OK) != 0))
        {
            ebpf_usage();
        }
        if(non_tuple ||dsip || echo || ssh_disable || verbose || per_interface || add || delete || eapol || ddos || vrrp || 
        monitor || logging || ddport || masquerade || list || outbound || bind_saddr || unbind_saddr || ddport || init_xdp || tcfilter){
            usage("-A, --add-user-rules cannot be used in non related combination calls");
        }
        add_user_rules();
        close_maps(0);
    }

    if(init_tc){
        if(non_tuple ||dsip || echo || ssh_disable || verbose || per_interface || add || delete || eapol || ddos || vrrp || 
        monitor || logging || ddport || masquerade || list || outbound || bind_saddr || unbind_saddr || ddport || init_xdp || tcfilter){
            usage("-H, --init-tc cannot be used in non related combination calls");
        }else{
            zfw_init_tc();
            close_maps(0);
        }
    }

    if(init_xdp){
        if(init_tc || non_tuple ||dsip || echo || ssh_disable || verbose || per_interface || add || delete || eapol || ddos || vrrp || 
        monitor || logging || ddport || masquerade || list || outbound || bind_saddr || unbind_saddr || ddport || tcfilter){
            usage("-Z, --init-xdp cannot be used in non related combination calls");
        }else{
            zfw_init_xdp();
            close_maps(0);
        }
    }

    if(non_tuple && (dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || eapol || ddos || vrrp || 
        monitor || logging || ddport || masquerade || list || outbound || bind_saddr || unbind_saddr || ddport)){
            usage("-j, --bind-flush cannot be used in non related combination calls");
    }

    if(bind_flush){
        if(dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || eapol || ddos || vrrp || 
        monitor || logging || ddport || masquerade || list || outbound || bind_saddr || unbind_saddr|| ddport){
            usage("-j, --bind-flush cannot be used in non related combination calls");
        }else{
            if(flush){
                flush_bind();
            }else{
                usage("-j, --bind-flush requires -F, --flush\n");
            }
        }
        close_maps(0);
    }

    if(bind_saddr){
        if ((dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete
            || flush || eapol) || ddos || vrrp || monitor || logging || ddport || masquerade || list || outbound || 
            unbind_saddr || ddport)
            {
                usage("-B, --bind-saddr-add can not be used in combination call\n");

        }else if(cd && dl){
            if((dplen >= 0) && (dplen <= 32)){
                struct bind_key key = {0};
                key.__in46_u_dest.ip = dcidr.s_addr;
                key.mask = dplen;
                key.type = 4;
                update_bind_saddr_map(&key);
            }else{
                usage("Invalid IPv4 cidr len\n");
            }
        }else if(cd6 && dl){
            if((dplen >= 0) && (dplen <= 128)){
                struct bind_key key = {0};
                memcpy(key.__in46_u_dest.ip6, dcidr6.__in6_u.__u6_addr32, sizeof(key.__in46_u_dest.ip6));
                key.mask = dplen;
                key.type = 6;
                update_bind_saddr_map(&key);
            }else{
                usage("Invalid IPv6 cidr len\n");
            }
        }
        close_maps(0);
    }

    if(unbind_saddr){
        if ((dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete
            || flush || eapol) || ddos || vrrp || monitor || logging || ddport || masquerade || list || outbound || 
            bind_saddr || ddport)
            {
                usage("-J, --bind-saddr-delete can not be used in combination call\n");

        }else if(cd && dl){
            if((dplen >= 0) && (dplen <= 32)){
                struct bind_key key = {0};
                key.__in46_u_dest.ip = dcidr.s_addr;
                key.mask = dplen;
                key.type = 4;
                delete_bind_saddr_map(&key);
            }else{
                printf("Invalid IPv4 cidr len\n");
                close_maps(1);
            }
        }else if(cd6 && dl){
            if((dplen >= 0) && (dplen <= 128)){
                struct bind_key key = {0};
                memcpy(key.__in46_u_dest.ip6, dcidr6.__in6_u.__u6_addr32, sizeof(key.__in46_u_dest.ip6));
                key.mask = dplen;
                key.type =6;
                delete_bind_saddr_map(&key);
            }else{
                printf("Invalid IPv6 cidr len\n");
                close_maps(1);
            }
        }
        close_maps(0);
    }

    if (service && (!add && !delete))
    {
        usage("-s, --service-id requires -I, --insert or -D, --delete");
    }

    if(list && flush){
        usage("-L, --list and -F, --flush not be used in combination call");
    }

    if (tcfilter && !object && !disable)
    {
        usage("-X, --set-tc-filter requires -O, --object-file for add operation");
    }

    if (tcfilter && !direction)
    {
        usage("-X, --set-tc-filter requires -z, --direction for add operation");
    }

    if (masquerade)
    {
        if ((dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || flush || eapol) || ddos || vrrp || monitor || logging || ddport)
        {
            usage("-k, --masquerade can not be used in combination call");
        }
    }

    if (v6)
    {
        if ((dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || flush || eapol) || ddos || vrrp || monitor || logging || ddport)
        {
            usage("-6, --ipv6-enable can not be used in combination call");
        }
    }

    if(v6 && list && !all_interface){
         usage("-6, --ipv6-enable when used in combination with -L --list requires the argument \'all\'");
    }

    if (ddport)
    {
        if (dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || eapol || ddos || vrrp || monitor || logging)
        {
            usage("Y, --ddos-dport-add can not be used in combination call");
        }
    }

    if (dnp3fc)
    {
        if (ddport || masquerade || v6 || tcfilter || bind_saddr || unbind_saddr || bind_flush || non_tuple || user_rules ||  service || 
            dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || eapol || ddos || vrrp || monitor || logging)
        {
            usage("Y, --dnp3-fcode-add can not be used in combination call");
        }
    }

    if (dsip)
    {
        if ((tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || eapol) || ddos || vrrp || monitor || logging)
        {
            usage("Y, --ddos-saddr-add can not be used in combination call");
        }
    }

    if (logging)
    {
        if (tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || eapol || ddos || vrrp || (!monitor))
        {
            usage("W, --write-log can only be used in combination call to -M, --monitor");
        }
    }

    if (ebpf_disable)
    {
        if (ddport || dsip || tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || monitor || eapol || vrrp || ddos || logging)
        {
            usage("Q, --disable-ebpf cannot be used in combination call");
        }
        if (access(diag_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        disable_ebpf();
        close_maps(0);
    }

    if (interface && !(add || delete))
    {
        usage("Missing argument -I, --insert");
    }

    if (ddos_saddr_list && !list)
    {
        usage("-Y, --list-ddos-saddr requires -L --list");
    }

    if (ddos_dport_list && !list)
    {
        usage("-U, --list-ddos-dports requires -L --list");
    }

    if (dnp3_fcode_list && (!list && !flush))
    {
        usage("-C, --list-dnp3-fcodes requires -L --list or -F, --flush");
    }

    if (list_diag && !list)
    {
        usage("-E, --list-diag requires -L --list");
    }

    if (list_gc && !list)
    {
        usage("-G, --list-gc-sessions requires -L --list");
    }

    if ((tun && (echo || ssh_disable || verbose || per_interface || add || delete || list || flush || tcfilter)))
    {
        usage("-T, --set-tun-mode cannot be set as a part of combination call to zfw");
    }

    if ((ddos && (monitor || tun || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || tcfilter || vrrp || eapol)))
    {
        usage("-a, --ddsos-filter cannot be set as a part of combination call to zfw");
    }

    if ((eapol && (monitor || tun || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || tcfilter || vrrp)))
    {
        usage("-M, --enable-eapol cannot be set as a part of combination call to zfw");
    }

    if ((monitor && (tun || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || tcfilter || vrrp)))
    {
        usage("-M, --monitor cannot be set as a part of combination call to zfw");
    }

    if ((vrrp && (tun || echo || ssh_disable || verbose || per_interface || add || delete || list || flush || tcfilter)))
    {
        usage("-R, --vrrp-enable cannot be set as a part of combination call to zfw");
    }

    if ((tcfilter && (echo || ssh_disable || verbose || per_interface || add || delete || list || flush)))
    {
        usage("-X, --set-tc-filter cannot be set as a part of combination call to zfw");
    }

    if ((echo && (ssh_disable || verbose || per_interface || add || delete || list || flush)))
    {
        usage("-e, --icmp-echo cannot be set as a part of combination call to zfw");
    }

    if ((verbose && (ssh_disable || echo || per_interface || add || delete || list || flush)))
    {
        usage("-v, --verbose cannot be set as a part of combination call to zfw");
    }

    if ((per_interface && (ssh_disable || verbose || echo || add || delete || list || flush)))
    {
        usage("-P, --per-interface-rules cannot be set as a part of combination call to zfw");
    }

    if ((ssh_disable && (echo || verbose || per_interface || add || delete || list || flush)))
    {
        usage("-x, --disable-ssh cannot be set as a part of combination call to zfw");
    }

    if ((intercept || passthru) && !list)
    {
        usage("Missing argument -L, --list");
    }

    if (route && (!add && !delete &&!flush))
    {
        usage("Missing argument -r, --route requires -I --insert, -D --delete or -F --flush");
    }

    if (disable && (!ssh_disable && !echo && !verbose && !per_interface && !tcfilter && !tun && !vrrp
     && !eapol && !ddos && !dsip && !ddport && !v6 && !outbound && !add && !delete && !masquerade && !non_tuple && !dnp3fc && !ot_filter))
    {
        usage("Missing argument at least one of -a,-b, -g,-6,-e, -k, -u, -v, -w, -x, -y, or -E, -P, -R, -T, -X");
    }

    if (direction && (!tcfilter && !list && !flush && !delete && !add))
    {
        usage("missing argument -z, --direction requires -X, --set-tc-filter or -D, --delete or --I, --insert or -L, --list or -F, --flush");
    }

    if (object && !tcfilter)
    {
        usage("missing argument -O, --object-file requires -X, --set-tc-filter");
    }

    if (add)
    {
        if(egress && ((access(egress6_map_path, F_OK) != 0) || (access(egress_map_path, F_OK) != 0))){
            egress_usage();
        }
        if ((access(tproxy_map_path, F_OK) != 0) || (access(tproxy6_map_path, F_OK) != 0))
        {
            ebpf_usage();
        }
        if (!cd && !cd6)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!dl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else if (!lpt)
        {
            usage("Missing argument -l, --low-port");
        }
        else if (!hpt)
        {
            usage("Missing argument -h, --high-port");
        }
        else if (!tpt)
        {
            usage("Missing argument -t, --tproxy-port");
        }
        else if (!prot)
        {
            usage("Missing argument -p, --protocol");
        }
        else
        {
            if ((cd && (dplen > 32)) || (cs && (splen > 32)))
            {
                usage("Invalid combination IP4 can't have prefix len greater than 32 bits");
            }
            else if ((cd6 && (dplen > 128)) || (cs6 && (splen > 128)))
            {
                usage("Invalid combination IP6 can't have prefix len greater than 128 bits");
            }
            if (!cs && cd)
            {
                inet_aton("0.0.0.0", &scidr);
                splen = 0;
            }
            else if ((cs || cs6) && !sl)
            {
                usage("Missing argument -n, --sprefix-len");
            }
            else if (cd6 && !cs6)
            {
                inet_pton(AF_INET6, "::", &scidr6);
                splen = 0;
            }
            else if (cd6 && cs)
            {
                usage("Invalid combination can't mix IP4 and IP6 prefixes");
            }
            else if (cd && cs6)
            {
                usage("Invalid combination can't mix IP4 and IP6 prefixes");
            }
            if (cd6 && cs6)
            {
                usage("Source filtering is currently not supported for IP6");
            }
            if (cd6)
            {
                if(egress && (tproxy_port != 0)){
                    usage("-t, tproxy-port 0 is currently the only supported value in egress filters");
                }
                map_insert6();
            }
            else
            {
                if(egress && (tproxy_port != 0)){
                    usage("-t, tproxy-port 0 is currently the only supported value in egress filters");
                }
                map_insert();
            }
        }
    }
    else if (delete)
    {
        if(egress && ((access(egress6_map_path, F_OK) != 0) || (access(egress_map_path, F_OK) != 0))){
            egress_usage();
        }
        if (access(tproxy_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        if ((access(tproxy_map_path, F_OK) != 0) || (access(tproxy6_map_path, F_OK) != 0))
        {
            ebpf_usage();
        }
        if (!cd && !cd6)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!dl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else if (!lpt)
        {
            usage("Missing argument -l, --low-port");
        }
        else if (!prot)
        {
            usage("Missing argument -p, --protocol");
        }
        else
        {
            if ((cd && (dplen > 32)) || (cs && (splen > 32)))
            {
                usage("Invalid combination IP4 can't have prefix len greater than 32 bits");
            }
            else if ((cd6 && (dplen > 128)) || (cs6 && (splen > 128)))
            {
                usage("Invalid combination IP6 can't have prefix len greater than 128 bits");
            }
            if (!cs && cd)
            {
                inet_aton("0.0.0.0", &scidr);
                splen = 0;
            }
            else if ((cs || cs6) && !sl)
            {
                usage("Missing argument -n, --sprefix-len");
            }
            else if (cd6 && !cs6)
            {
                inet_pton(AF_INET6, "::", &scidr6);
                splen = 0;
            }
            else if (cd6 && cs)
            {
                usage("Invalid combination can't mix IP4 and IP6 prefixes");
            }
            else if (cd && cs6)
            {
                usage("Invalid combination can't mix IP4 and IP6 prefixes");
            }
            
            if (cd6)
            {
                map_delete6();
            }
            else
            {
                map_delete();
            }
        }
    }
    else if (flush)
    {
        if(dnp3_fcode_list){
            dnp3_fcode_map_flush();
            close_maps(0);
        }
        if(egress && ((access(egress6_map_path, F_OK) != 0) || (access(egress_map_path, F_OK) != 0))){
            egress_usage();
        }
        if (access(tproxy_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        map_flush();
    }
    else if (list)
    {
        if(egress && ((access(egress6_map_path, F_OK) != 0) || (access(egress_map_path, F_OK) != 0))){
            egress_usage();
        }
        if ((access(tproxy_map_path, F_OK) != 0) || (access(tproxy6_map_path, F_OK) != 0) || (access(diag_map_path, F_OK) != 0))
        {
            ebpf_usage();
        }
        if (list_diag)
        {
            if (cd || dl || cs || sl || prot || ddos_saddr_list)
            {
                usage("-E, --list-diag cannot be combined with cidr list arguments -c,-o, -m, -n, -p, -Y");
            }
            interface_diag();
            close_maps(0);
        }
        if (list_gc)
        {
            if (cd || dl || cs || sl || prot || ddos_saddr_list || list_diag)
            {
                usage("-G, --list-gc-sessions cannot be combined with other list arguments -E,-c,-o, -m, -n, -p, -Y");
            }
            flush_udp_egress();
            flush_tcp_egress();
            close_maps(0);
        }
        if (ddos_saddr_list)
        {
            if (cd || dl || cs || sl || prot || ddos_dport_list)
            {
                usage("-Y, --list-ddos-saddr cannot be combined with cidr list arguments -c,-o, -m, -n, -p, -E, -U");
            }
            ddos_saddr_map_list();
            close_maps(0);
        }
        if (ddos_dport_list)
        {
            if (cd || dl || cs || sl || prot)
            {
                usage("-U, --list-ddos-dports cannot be combined with cidr list arguments -c,-o, -m, -n, -p, -E");
            }
            ddos_dport_map_list();
            close_maps(0);
        }
        if (dnp3_fcode_list)
        {
            if (cd || dl || cs || sl || prot)
            {
                usage("-C, --list-ddos-dports cannot be combined with cidr list arguments -c,-o, -m, -n, -p, -E");
            }
            dnp3_fcode_map_list();
            close_maps(0);
        }
        if (!cd && !dl && !cd6 && v6 && all_interface)
        {
            map_list_all6();
            close_maps(0);
        }
        if (!cd && !dl)
        {
            map_list_all();
        }
        else if (!cd && !cd6)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!dl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else if ((cd && (dplen > 32)) || (cs && (splen > 32)))
        {
            usage("Invalid combination IP4 can't have prefix len greater than 32 bits");
        }
        else if ((cd6 && (dplen > 128)) || (cs6 && (splen > 128)))
        {
            usage("Invalid combination IP6 can't have prefix len greater than 128 bits");
        }
        else
        {
            if (cd && !cs)
            {
                inet_aton("0.0.0.0", &scidr);
                splen = 0;
            }else if(cd6 && !cs6){
                inet_pton(AF_INET6, "::", &scidr6);
                splen = 0;
            }
            else
            {
                if (!sl)
                {
                    usage("Missing argument -n, --sprefix-len");
                }
            }
            if(cd6){
                map_list6();
            }else{
                map_list();
            }
        }
    }
    else if (ot_filter || vrrp || verbose || ssh_disable || echo || per_interface || tun || eapol || ddos || v6 || outbound || masquerade || non_tuple )
    {
        interface_diag();
    }
    else if (tcfilter)
    {
        interface_tc();
    }
    else if (monitor)
    {
        open_rb_map();
        ring_buffer = ring_buffer__new(rb_fd, process_events, NULL, NULL);
        while (true)
        {
            ring_buffer__poll(ring_buffer, 1000);
        }
    }
    else if (dsip)
    {
        if (disable)
        {
            delete_ddos_saddr_map(ddos_saddr);
        }
        else
        {
            update_ddos_saddr_map(ddos_saddr);
        }
    }
    else if (ddport){
        if (disable)
        {
            delete_ddos_dport_map(ddos_dport);
        }
        else
        {
            update_ddos_dport_map(ddos_dport);
        }
    }
    else if (dnp3fc){
        if (disable)
        {
            delete_dnp3_fcode_map(dnp3_fcode);
        }
        else
        {
            update_dnp3_fcode_map(dnp3_fcode);
        }
    }
    else
    {
        usage("No arguments specified");
    }
    close_maps(0);
}
