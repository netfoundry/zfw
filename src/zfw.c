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
#include <linux/if.h>
#include <linux/sockios.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <argp.h>
#include <linux/socket.h>
#include <sys/wait.h>

#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES     100 // MAX # PREFIXES
#endif
#define MAX_INDEX_ENTRIES   100 // MAX port ranges per prefix
#define MAX_TABLE_SIZE      65536  // PORT Mapping table size
#define MAX_IF_LIST_ENTRIES 3
#define MAX_IF_ENTRIES      30

static bool add = false;
static bool delete = false;
static bool list = false;
static bool flush = false;
static bool lpt = false;
static bool hpt = false;
static bool tpt = false;
static bool dl = false;
static bool sl = false;
static bool cd = false;
static bool cs = false;
static bool prot = false;
static bool route = false;
static bool passthru = false;
static bool intercept = false;
static bool echo = false;
static bool verbose = false;
static bool per_interface = false;
static bool interface = false;
static bool disable = false;
static bool all_interface = false;
static bool ssh_disable = false;
static bool tc = false;
static bool tcfilter = false;
static bool direction = false;
static bool object;
static bool ebpf_disable = false;
static bool list_diag = false;
static bool tun = false;
static struct in_addr dcidr;
static struct in_addr scidr;
static unsigned short dplen;
static unsigned short splen;
static unsigned short low_port;
static unsigned short high_port;
static unsigned short tproxy_port;
static char *program_name;
static char *protocol_name;
static unsigned short protocol;
union bpf_attr if_map;
int if_fd = -1;
union bpf_attr diag_map;
int diag_fd = -1;
union bpf_attr tun_map;
int tun_fd = -1;
static const char *tproxy_map_path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
const char *count_map_path = "/sys/fs/bpf/tc/globals/tuple_count_map";
const char *diag_map_path = "/sys/fs/bpf/tc/globals/diag_map";
const char *if_map_path = "/sys/fs/bpf/tc/globals/ifindex_ip_map";
const char *matched_map_path = "/sys/fs/bpf/tc//globals/matched_map";
const char *tcp_map_path = "/sys/fs/bpf/tc/globals/tcp_map";
const char *udp_map_path = "/sys/fs/bpf/tc/globals/udp_map";
const char *tun_map_path = "/sys/fs/bpf/tc/globals/tun_map";
const char *if_tun_map_path = "/sys/fs/bpf/tc/globals/ifindex_tun_map";
const char *transp_map_path = "/sys/fs/bpf/tc/globals/zet_transp_map";
static char doc[] = "zfw -- ebpf firewall configuration tool";
const char *if_map_path;
static char *diag_interface;
static char *echo_interface;
static char *verbose_interface;
static char *ssh_interface;
static char *prefix_interface;
static char *tun_interface;
static char *tc_interface;
static char *object_file;
static char *direction_string;
const char *argp_program_version = "0.4.0";

static __u8 if_list[MAX_IF_LIST_ENTRIES];
int ifcount = 0;
int get_key_count();
void interface_tc();
int add_if_index(uint32_t *idx, in_addr_t ifip, char *ifname);
void open_diag_map();
void open_if_map();
void open_tun_map();
bool interface_map();
void close_maps(int code);


struct ifindex_ip4
{
    uint32_t ipaddr;
    char ifname[IFNAMSIZ];
};

/*value to ifindex_tun_map*/
struct ifindex_tun {
    uint32_t index;
    char ifname[IFNAMSIZ];
    char cidr[16];
    char mask[3];
    bool verbose;
};

struct diag_ip4
{
    bool echo;
    bool verbose;
    bool per_interface;
    bool ssh_disable;
    bool tc_ingress;
    bool tc_egress;
    bool tun_mode;
};

struct tproxy_port_mapping
{
    __u16 low_port;
    __u16 high_port;
    __u16 tproxy_port;
    __u8 if_list[MAX_IF_LIST_ENTRIES];
};

struct tproxy_tuple
{
    __u16 index_len;
    __u16 index_table[MAX_INDEX_ENTRIES];
    struct tproxy_port_mapping port_mapping[MAX_TABLE_SIZE];
};

struct tproxy_key
{
    __u32 dst_ip;
    __u32 src_ip;
    __u16 dprefix_len;
    __u16 sprefix_len;
    __u16 protocol;
    __u16 pad;
};

void ebpf_usage()
{
    if (access(tproxy_map_path, F_OK) != 0)
    {
        printf("Not enough privileges or ebpf not enabled!\n"); 
        printf("Run as \"sudo\" with ingress tc filter [filter -X, --set-tc-filter] set on at least one interface\n");
        close_maps(1);
    }
}

/*function to add loopback binding for intercept IP prefixes that do not
 * currently exist as a subset of an external interface
 * */
void bind_prefix(struct in_addr *address, unsigned short mask)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("binding intercept %s to loopback\n", cidr_block);
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

void unbind_prefix(struct in_addr *address, unsigned short mask)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("unbinding intercept %s from loopback\n", cidr_block);
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
        exit(0);
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
        printf("execv error: unknown error binding");
    }
    else
    {
        int status = 0;
        if (waitpid(pid, &status, 0) > 0)
        {
            if (WIFEXITED(status) && !WEXITSTATUS(status))
            {
                printf("tc parent %s : %s\n", action, tc_interface);
            }
            else
            {
                if (!strcmp("add", action))
                {
                    printf("tc parent already exists : %s\n", tc_interface);
                }
                else
                {
                    printf("tc parent does not exist : %s\n", tc_interface);
                }
            }
        }
    }
}

void set_tc_filter(char *action)
{
    if (access("/usr/sbin/tc", F_OK) != 0)
    {
        printf("tc not installed\n");
        exit(0);
    }
    if (!strcmp("add", action) && access(object_file, F_OK) != 0)
    {
        printf("object file %s not in path\n", object_file);
        exit(1);
    }
    pid_t pid;
    if (!strcmp(action, "add"))
    {
        set_tc(action);
        for(int x = 0; x < 6; x++){
            char prio[10];
            sprintf(prio, "%d", x + 1);
            char section[10];
            if(x ==0){
                sprintf(section, "action");;
            }else{
                if(!strcmp(direction_string,"egress")){
                    break;
                }
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
                printf("execv error: unknown error attaching filter");
            }
            else
            {
                int status = 0;
                if (!(waitpid(pid, &status, 0) > 0))
                {
                    if (WIFEXITED(status) && !WEXITSTATUS(status))
                    {
                        printf("tc %s filter not set : %s\n", direction_string, tc_interface);
                    }
                }
                if(status)
                {
                    printf("tc %s filter action/%d not set : %s\n", direction_string, x,tc_interface);
                    exit(1);
                }
            }
        }
    }
    else
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
}

void disable_ebpf()
{
    all_interface = true;
    disable = true;
    tc = true;
    interface_tc();
    const char *maps[10] = {tproxy_map_path, diag_map_path, if_map_path, count_map_path,
                            udp_map_path, matched_map_path, tcp_map_path, tun_map_path, if_tun_map_path,
                             transp_map_path};
    for (int map_count = 0; map_count < 10; map_count++)
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

/* function to get ifindex by interface name */
int get_index(char *name, uint32_t *idx)
{
    int fd, result;
    struct ifreq irequest;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd == -1){
        return -1;
    }

    strncpy(irequest.ifr_name, name, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &irequest) == -1)
    {
        do
        {
            result = close(fd);
        } while (result == -1 && errno == EINTR);
        return -1;
    }
    
    *idx = irequest.ifr_ifindex;
    close(fd);
    return 0;
}

/* convert string port to unsigned short int */
unsigned short port2s(char *port)
{
    char *endPtr;
    int32_t tmpint = strtol(port, &endPtr, 10);
    if ((tmpint < 0) || (tmpint > 65535) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Port: %s\n", port);
        exit(1);
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
        exit(1);
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
    if ((tmpint < 0) || (tmpint > 32) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Prefix Length: %s\n", len);
        exit(1);
    }
    __u16 u16int = (__u16)tmpint;
    return u16int;
}

/* function to add a UDP or TCP port range to a tproxy mapping */
void add_index(__u16 index, struct tproxy_port_mapping *mapping, struct tproxy_tuple *tuple)
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
    memcpy((void *)&tuple->port_mapping[index], (void *)mapping, sizeof(struct tproxy_port_mapping));
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
        memset((void *)&tuple->port_mapping[index], 0, sizeof(struct tproxy_port_mapping));
        if (tuple->port_mapping[index].low_port == index)
        {
            printf("mapping[%d].low_port = %d\n", index, ntohs(tuple->port_mapping[index].low_port));
        }
        else
        {
            printf("mapping[%d] removed\n", ntohs(index));
        }
    }
    else
    {
        printf("mapping[%d] does not exist\n", ntohs(index));
    }
}

void print_rule(struct tproxy_key *key, struct tproxy_tuple *tuple, int *rule_count)
{
    if(if_fd == -1){
        open_if_map();
    }
    if(tun_fd == -1){
        open_tun_map();
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
        if(o_tunif.index != 0){
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
    for (; x < tuple->index_len; x++)
    {
        sprintf(dpts, "dpts=%d:%d", ntohs(tuple->port_mapping[tuple->index_table[x]].low_port),
                ntohs(tuple->port_mapping[tuple->index_table[x]].high_port));
        if (intercept && !passthru)
        {   bool entry_exists = false;
            if(tun_mode && ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port) == 65535){
                printf("%-11s\t%-3s\t%-20s\t%-32s%-17s\tTUNMODE redirect:%-15s", "TUNMODE", proto, scidr_block, dcidr_block,
                       dpts, o_tunif.ifname);
                entry_exists = true;
                *rule_count += 1;
            }
            else if(ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port) > 0)
            {
                printf("%-11s\t%-3s\t%-20s\t%-32s%-17s\tTPROXY redirect 127.0.0.1:%-6d", "TPROXY", proto, scidr_block, dcidr_block,
                       dpts, ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port));
                entry_exists = true;
                *rule_count += 1;
            }
            char interfaces[IFNAMSIZ * MAX_IF_LIST_ENTRIES + 8] = "";
            for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
            {
                if (tuple->port_mapping[tuple->index_table[x]].if_list[i])
                {
                    if_key = tuple->port_mapping[tuple->index_table[x]].if_list[i];
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
            if (strlen(interfaces))
            {
                printf("%s%.*s%s\n", "[", (int)(strlen(interfaces) - 1), interfaces, "]");
            }
            else if(entry_exists)
            {
                printf("%s\n", "[]");
            }
            
        }
        else if (passthru && !intercept)
        {
            if (ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port) == 0)
            {
                printf("%-11s\t%-3s\t%-20s\t%-32s%-17s\t%s to %-20s", "PASSTHRU", proto, scidr_block, dcidr_block,
                       dpts, "PASSTHRU", dcidr_block);
                char interfaces[IFNAMSIZ * MAX_IF_LIST_ENTRIES + 8] = "";
                for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
                {
                    if (tuple->port_mapping[tuple->index_table[x]].if_list[i])
                    {
                        if_key = tuple->port_mapping[tuple->index_table[x]].if_list[i];
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
            if(tun_mode && ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port) == 65535){
                printf("%-11s\t%-3s\t%-20s\t%-32s%-17s\tTUNMODE redirect:%-15s", "TUNMODE", proto, scidr_block, dcidr_block,
                       dpts, o_tunif.ifname);
            }
            else if(ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port) > 0)
            {
                printf("%-11s\t%-3s\t%-20s\t%-32s%-17s\tTPROXY redirect 127.0.0.1:%-6d", "TPROXY", proto, scidr_block, dcidr_block,
                       dpts, ntohs(tuple->port_mapping[tuple->index_table[x]].tproxy_port));
            }
            else
            {
                printf("%-11s\t%-3s\t%-20s\t%-32s%-17s\t%s to %-20s", "PASSTHRU", proto, scidr_block, dcidr_block,
                       dpts, "PASSTHRU", dcidr_block);
            }
            char interfaces[IFNAMSIZ * MAX_IF_LIST_ENTRIES + 8] = "";
            for (int i = 0; i < MAX_IF_LIST_ENTRIES; i++)
            {
                if (tuple->port_mapping[tuple->index_table[x]].if_list[i])
                {
                    if_key = tuple->port_mapping[tuple->index_table[x]].if_list[i];
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
    fprintf(stderr, "       zfw -V\n");
    fprintf(stderr, "       zfw --help\n");
    exit(1);
}

bool set_tun_diag()
{
    if (access(tun_map_path, F_OK) != 0)
    {
        ebpf_usage();
    }
    if(tun_fd == -1){
        open_tun_map();
    }
    interface_map();
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
            if(strcmp(o_tdiag.ifname,verbose_interface)){
                printf("Invalid tun interface only ZET tun supported\n");
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
            if(strcmp(o_tdiag.ifname,diag_interface)){
                return false;
            }
            printf("%s: %d\n", o_tdiag.ifname, o_tdiag.index);
            printf("--------------------------\n");
            printf("%-24s:%d\n", "verbose", o_tdiag.verbose);
            printf("%-24s:%s\n", "cidr", o_tdiag.cidr);
            printf("%-24s:%s\n", "mask", o_tdiag.mask);
            printf("--------------------------\n\n");
        }
    }
    return true;
}

bool set_diag(uint32_t *idx)
{
    if (access(diag_map_path, F_OK) != 0)
    {
        ebpf_usage();
    }
    diag_map.map_fd = diag_fd;
    struct diag_ip4 o_diag;
    diag_map.key = (uint64_t)idx;
    diag_map.flags = BPF_ANY;
    diag_map.value = (uint64_t)&o_diag;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &diag_map, sizeof(diag_map));
    if (lookup)
    {
        printf("Invalid Index\n");
        return false;
    }
    else
    {
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
            printf("%s: %d\n", diag_interface, *idx);
            printf("--------------------------\n");
            if (*idx != 1)
            {
                printf("%-24s:%d\n", "icmp echo", o_diag.echo);
            }
            else
            {
                printf("%-24s:%d\n", "icmp echo", 1);
            }
            printf("%-24s:%d\n", "verbose", o_diag.verbose);
            printf("%-24s:%d\n", "ssh disable", o_diag.ssh_disable);
            printf("%-24s:%d\n", "per interface", o_diag.per_interface);
            printf("%-24s:%d\n", "tc ingress filter", o_diag.tc_ingress);
            printf("%-24s:%d\n", "tc egress filter", o_diag.tc_egress);
            printf("%-24s:%d\n", "tun mode intercept", o_diag.tun_mode);
            printf("--------------------------\n\n");
        }
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
        exit(1);
    }
    struct ifaddrs *address = addrs;
    uint32_t idx = 0;
    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ip address
     *  as the value
     */
    int lo_count = 0;
    while (address)
    {
        if (address->ifa_addr && (address->ifa_addr->sa_family == AF_INET))
        {
            int index_check = get_index(address->ifa_name, &idx);
            if(index_check){
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if (all_interface)
            {
                tc_interface = address->ifa_name;
            }
            if(!strncmp(address->ifa_name,"tun", 3) || !strncmp(address->ifa_name,"ziti", 4))
            {
                if(!strncmp(tc_interface,"tun", 3) || !strncmp(tc_interface,"ziti", 4)){
                    printf("%s:zfw does not allow tc filters on tun interfaces!\n", address->ifa_name);
                }
                address = address->ifa_next;
                continue;
            }
            if(idx >= MAX_IF_ENTRIES)
            {
                printf("%s:zfw does not allow tc filters interfaces with an ifindex above %d!\n", address->ifa_name, MAX_IF_ENTRIES -1);
                address = address->ifa_next;
                continue;
            }
            if (!strncmp(address->ifa_name, "lo", 2))
            {
                lo_count++;
                if(lo_count > 1){
                    address = address->ifa_next;
                    continue;
                }
            }
            if (tc || tcfilter)
            {
                if (!strcmp(tc_interface, address->ifa_name))
                {
                    if (tc)
                    {
                        if (!disable)
                        {
                            set_tc("add");
                        }
                        else
                        {
                            set_tc("del");
                        }
                    }
                    if (tcfilter)
                    {
                        if (!disable)
                        {
                            set_tc_filter("add");
                            if(diag_fd == -1){
                                open_diag_map();
                            }
                            set_diag(&idx);
                        }
                        else
                        {
                            set_tc_filter("del");
                            if(diag_fd == -1){
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
    if(diag_fd == -1){
        open_diag_map();
    }
    interface_map();
    struct ifaddrs *addrs;

    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        exit(1);
    }
    struct ifaddrs *address = addrs;
    uint32_t idx = 0;
    int lo_count = 0;
    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ip address
     *  as the value
     */
    while (address)
    {
        if (address->ifa_addr && (address->ifa_addr->sa_family == AF_INET))
        {
            int index_check = get_index(address->ifa_name, &idx);
            if(index_check){
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if(idx >= MAX_IF_ENTRIES && strncmp(address->ifa_name,"tun", 3) && strncmp(address->ifa_name,"ziti", 4)){
                printf("%s:zfw does not support interfaces with an ifindex above %d!\n", address->ifa_name, MAX_IF_ENTRIES -1);
                address = address->ifa_next;
                continue;
            }
            if(!strncmp(address->ifa_name, "lo", 2))
            {
                lo_count++;
                if(lo_count > 1){
                    address = address->ifa_next;
                    continue;
                }
            }
            if (all_interface)
            {
                echo_interface = address->ifa_name;
                verbose_interface = address->ifa_name;
                prefix_interface = address->ifa_name;
                ssh_interface = address->ifa_name;
                diag_interface = address->ifa_name;
                tun_interface = address->ifa_name;
            }
            if(!strncmp(address->ifa_name, "tun", 3) && (tun || per_interface || ssh_disable || echo)){
                if(per_interface && !strncmp(prefix_interface, "tun", 3)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                if(tun && !strncmp(tun_interface, "tun", 3)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                if(ssh_disable && !strncmp(ssh_interface, "tun", 3)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                if(echo && !strncmp(echo_interface, "tun", 3)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                address = address->ifa_next;
                continue;
            }
            if(!strncmp(address->ifa_name, "ziti", 4) && (tun || per_interface || ssh_disable || echo)){
                if(per_interface && !strncmp(prefix_interface, "ziti", 4)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                if(tun && !strncmp(tun_interface, "ziti", 4)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                if(ssh_disable && !strncmp(ssh_interface, "ziti", 4)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                if(echo && !strncmp(echo_interface, "ziti", 4)){
                    printf("%s:zfw does not allow setting on tun interfaces!\n", address->ifa_name);
                }
                address = address->ifa_next;
                continue;
            }
            if (echo && strncmp(address->ifa_name,"tun", 3) && strncmp(address->ifa_name,"ziti", 4))
            {
                if (!strcmp(echo_interface, address->ifa_name))
                {
                    set_diag(&idx);
                }
            }

            if (verbose)
            {
                if(!strncmp(address->ifa_name, "tun", 3) && !strncmp(verbose_interface,"tun", 3)){
                    set_tun_diag();
                }
                else if(!strncmp(address->ifa_name, "ziti", 4) && !strncmp(verbose_interface,"ziti", 4)){
                    set_tun_diag();
                }
                else if(!strcmp(verbose_interface, address->ifa_name))
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
                if(!strncmp(address->ifa_name, "tun", 3) && !strncmp(diag_interface,"tun", 3)){
                    set_tun_diag();
                }
                else if(!strncmp(address->ifa_name, "ziti", 4) && !strncmp(verbose_interface,"ziti", 4)){
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

            if (access(diag_map_path, F_OK) != 0)
            {
                ebpf_usage();
            }
        }
        address = address->ifa_next;
    }
    freeifaddrs(addrs);
}

int get_ifindex_map(uint32_t *idx){
    if(if_fd == -1){
        open_if_map();
    }
    uint32_t key = *idx;
    struct ifindex_ip4 orule;
    if_map.map_fd = if_fd;
    if_map.key = (uint64_t)&key;
    if_map.value = (uint64_t)&orule;
    int lookup = 0;
    lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if_map, sizeof(if_map));
    if (!lookup)
    {
        printf("key=%d\n",*idx);
        printf("ifname=%s\n",orule.ifname);
        printf("ifip=%x\n",orule.ipaddr);
    }
    return 0;
}

int add_if_index(uint32_t *idx, in_addr_t ifip, char *ifname)
{
    if(if_fd == -1){
        open_if_map();
    }
    bool change_detected = false;
    if_map.map_fd = if_fd;
    struct ifindex_ip4 o_ifip4;
    if_map.key = (uint64_t)idx;
    if_map.flags = BPF_ANY;
    if_map.value = (uint64_t)&o_ifip4;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &if_map, sizeof(if_map));
    if (lookup)
    {
        printf("Unable to access ArrayMap Index\n");
    }else{
        if(o_ifip4.ipaddr != ifip){
            o_ifip4.ipaddr = ifip;
            change_detected =true;
        }
        if(strcmp(o_ifip4.ifname, ifname)){
            sprintf(o_ifip4.ifname, "%s", ifname);
            change_detected =true;
        }
        if(change_detected){
            int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &if_map, sizeof(if_map));
            if (ret)
            {
                printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                return 1;
            }
            
        }
    }
    return 0;
}

bool interface_map()
{
    if(tun_fd == -1){
        open_tun_map();
    }
    struct ifaddrs *addrs;
    /* call function to get a linked list of interface structs from system */
    if (getifaddrs(&addrs) == -1)
    {
        printf("can't get addrs");
        exit(1);
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
    char tunmask[3] = "10";
    char *tunipstr;
    char *dns_range = "ZITI_DNS_IP_RANGE";
    char *tunif = getenv(dns_range);
    char *tmptun = NULL;
    if(tunif){
        tmptun = strdup(tunif);
    }
    if(tmptun){
        if (tmptun && ((strlen(tmptun) > 8) && (strlen(tmptun) < 19)))
        {
            tunipstr = strsep(&tmptun,"/");
            if(tunipstr){
                if (inet_aton(tunipstr, &tuncidr))
                {
                    tunip = tuncidr.s_addr;
                }
                if(tmptun && (strlen(tmptun) > 0) && (strlen(tmptun) <= 2)){
                    sprintf(tunmask,"%s", tmptun);
                }
            }
        }
    }
    /*
     * traverse linked list of interfaces and for each non-loopback interface
     *  populate the index into the map with ifindex as the key and ip address
     *  as the value
     */
    while (address)
    {
        if (address->ifa_addr && (address->ifa_addr->sa_family == AF_INET))
        {
            int index_check = get_index(address->ifa_name, &idx);
            if(index_check){
                printf("unable to get interface index fd!\n");
                address = address->ifa_next;
                continue;
            }
            if((idx >= MAX_IF_ENTRIES) && strncmp(address->ifa_name,"tun", 3) && strncmp(address->ifa_name,"ziti", 4)){
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
                if(lo_count > 1){
                    address = address->ifa_next;
                    continue;
                }
            }
            if((idx < MAX_IF_ENTRIES) && strncmp(address->ifa_name,"tun", 3) && strncmp(address->ifa_name,"ziti", 4)){
                add_if_index(&idx, ifip, address->ifa_name);
            }

            if((ifip == tunip) && (!strncmp(address->ifa_name,"tun", 3) || !strncmp(address->ifa_name,"ziti", 4)))
            {
                bool change_detected =true;
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
                }else{
                    if(o_iftun.index != idx){
                        o_iftun.index = idx;
                        change_detected =true;
                    }
                    if(strcmp(o_iftun.mask, tunmask)){
                        sprintf(o_iftun.mask, "%s", tunmask);
                        change_detected =true;
                    }
                    if(strcmp(o_iftun.ifname, address->ifa_name)){
                        sprintf(o_iftun.ifname, "%s", address->ifa_name);
                        change_detected =true;
                    }
                    uint32_t tun_net_integer = ntohl(ifip) & bits2Mask(len2u16(tunmask));
                    char *tuncidr_string = nitoa(tun_net_integer);
                    if(tuncidr_string){
                        if(strcmp(o_iftun.cidr, tuncidr_string)){
                            sprintf(o_iftun.cidr, "%s", tuncidr_string);                      
                            change_detected =true;
                        }
                        free(tuncidr_string);
                    }
                    
                    if(change_detected){
                        int ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &tun_map, sizeof(tun_map));
                        if (ret)
                        {
                            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                            return 1;
                        }
                        
                    }
                }
            }
        }
        address = address->ifa_next;
    }
    freeifaddrs(addrs);
    return create_route;
}

void map_insert()
{
    if (get_key_count() == BPF_MAX_ENTRIES)
    {
        printf("INSERT FAILURE -- MAX PREFIX TUPLES REACHED\n");
        exit(1);
    }
    bool route_insert = interface_map();
    union bpf_attr map;
    struct tproxy_key key = {dcidr.s_addr, scidr.s_addr, dplen, splen, protocol, 0};
    struct tproxy_tuple orule; /* struct to hold an existing entry if it exists */
    /* open BPF zt_tproxy_map map */
    memset(&map, 0, sizeof(map));
    /* set path name with location of map in filesystem */
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    /* make system call to get fd for map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    /* make system call to lookup prefix/mask in map */
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(low_port);
    /* pupulate a struct for a port mapping */
    struct tproxy_port_mapping port_mapping = {
        htons(low_port),
        htons(high_port),
        htons(tproxy_port),
        {}};
    if (interface)
    {
        for (int x = 0; x < MAX_IF_LIST_ENTRIES; x++)
        {
            port_mapping.if_list[x] = if_list[x];
        }
    }
    /*
     * Check result of lookup if not 0 then create a new entery
     * else edit an existing entry
     */
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
        close(fd);
        exit(1);
    }
    if (lookup)
    {
        /* create a new tproxy prefix entry and add port range to it */
        struct tproxy_tuple rule = {
            1,
            {index},
            {}};
        memcpy((void *)&rule.port_mapping[index], (void *)&port_mapping, sizeof(struct tproxy_port_mapping));
        map.value = (uint64_t)&rule;
        if (!rule.port_mapping[index].low_port)
        {
            printf("memcpy failed");
            close(fd);
            exit(1);
        }
        else
        {
            union bpf_attr count_map;
            /*path to pinned ifindex_ip_map*/
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
                exit(1);
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
        if (route && route_insert)
        {
            bind_prefix(&dcidr, dplen);
        }
    }
    else
    {
        /* modify existing prefix entry and add or modify existing port mapping entry  */
        printf("lookup success\n");
        add_index(index, &port_mapping, &orule);
        if (!(orule.port_mapping[index].low_port == index))
        {
            printf("Insert failed\n");
            close(fd);
            exit(1);
        }
    }
    map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
        exit(1);
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
    if (route)
    {
        route_delete = interface_map();
    }
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        exit(1);
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

void map_delete()
{
    bool route_delete = interface_map();
    union bpf_attr map;
    struct tproxy_key key = {dcidr.s_addr, scidr.s_addr, dplen, splen, protocol, 0};
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
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = htons(low_port);
    if (lookup)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
        exit(1);
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
            exit(1);
        }
        remove_index(index, &orule);
        if (orule.index_len == 0)
        {
            memset(&map, 0, sizeof(map));
            map.pathname = (uint64_t)tproxy_map_path;
            map.bpf_fd = 0;
            int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                exit(1);
            }
            // delete element with specified key
            map.map_fd = fd;
            map.key = (uint64_t)&key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
                close(fd);
                exit(1);
            }
            else
            {
                union bpf_attr count_map;
                /*path to pinned ifindex_ip_map*/
                const char *count_map_path = "/sys/fs/bpf/tc/globals/tuple_count_map";
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
                    exit(1);
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
                if (route && route_delete)
                {
                    unbind_prefix(&dcidr, dplen);
                }
                exit(0);
            }
        }
        map.value = (uint64_t)&orule;
        map.flags = BPF_ANY;
        /*Flush Map changes to system -- Needed when removing an entry that is not the last range associated
         *with a prefix/protocol pair*/
        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &map, sizeof(map));
        if (result)
        {
            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
            close(fd);
            exit(1);
        }
    }
    close(fd);
}

void map_flush()
{
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
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
        exit(1);
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
    /*path to pinned ifindex_ip_map*/
    const char *count_map_path = "/sys/fs/bpf/tc/globals/tuple_count_map";
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
        exit(1);
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

void map_list()
{
    union bpf_attr map;
    struct tproxy_key key = {dcidr.s_addr, scidr.s_addr, dplen, splen, protocol, 0};
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
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    printf("%-8s\t%-3s\t%-20s\t%-32s%-24s\t\t\t\t%-32s\n", "target", "proto", "origin", "destination", "mapping:", " interface list");
    printf("--------\t-----\t-----------------\t------------------\t\t-------------------------------------------------------\t-----------------\n");
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
                    printf("%-8s\t%-3s\t%-20s\t%-32s%-24s\t\t\t\t%-32s\n", "target", "proto", "origin", "destination", "mapping:", " interface list");
                    printf("--------\t-----\t-----------------\t------------------\t\t-------------------------------------------------------\t-----------------\n");
                }
            }
        }
    }

    close(fd);
}

int get_key_count()
{
    union bpf_attr count_map;
    /*path to pinned ifindex_ip_map*/
    const char *count_map_path = "/sys/fs/bpf/tc/globals/tuple_count_map";
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
        exit(1);
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

void map_list_all()
{
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
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
        exit(1);
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
    int ret = 0;
    printf("%-8s\t%-3s\t%-20s\t%-32s%-24s\t\t\t\t%-32s\n", "target", "proto", "origin", "destination", "mapping:", " interface list");
    printf("--------\t-----\t-----------------\t------------------\t\t-------------------------------------------------------\t-----------------\n");
    int rule_count = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &map, sizeof(map));
        if (ret == -1)
        {
            printf("Rule Count: %d\n", rule_count);
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
    {"insert", 'I', NULL, 0, "Insert map rule", 0},
    {"delete", 'D', NULL, 0, "Delete map rule", 0},
    {"list", 'L', NULL, 0, "List map rules", 0},
    {"flush", 'F', NULL, 0, "Flush all map rules", 0},
    {"set-tun-mode", 'T', "", 0, "set tun mode on interface", 0},
    {"disable-ebpf", 'Q', NULL, 0, "delete tc from all interface and remove all maps", 0},
    {"per-interface-rules", 'P', "", 0, "set interface to per interface rule aware", 0},
    {"disable-ssh", 'x', "", 0, "disable inbound ssh to interface (default enabled)", 0},
    {"dcidr-block", 'c', "", 0, "Set dest ip prefix i.e. 192.168.1.0 <mandatory for insert/delete/list>", 0},
    {"icmp-echo", 'e', "", 0, "enable inbound icmp echo to interface", 0},
    {"verbose", 'v', "", 0, "enable verbose tracing on interface", 0},
    {"disable", 'd', NULL, 0, "disable associated diag operation i.e. -e eth0 -d to disable inbound echo on eth0", 0},
    {"ocidr-block", 'o', "", 0, "Set origin ip prefix i.e. 192.168.1.0 <mandatory for insert/delete/list>", 0},
    {"dprefix-len", 'm', "", 0, "Set dest prefix length (1-32) <mandatory for insert/delete/list >", 0},
    {"oprefix-len", 'n', "", 0, "Set origin prefix length (1-32) <mandatory for insert/delete/list >", 0},
    {"low-port", 'l', "", 0, "Set low-port value (1-65535)> <mandatory insert/delete>", 0},
    {"high-port", 'h', "", 0, "Set high-port value (1-65535)> <mandatory for insert>", 0},
    {"tproxy-port", 't', "", 0, "Set high-port value (0-65535)> <mandatory for insert>", 0},
    {"protocol", 'p', "", 0, "Set protocol (tcp or udp) <mandatory insert/delete>", 0},
    {"route", 'r', NULL, 0, "Add or Delete static ip/prefix for intercept dest to lo interface <optional insert/delete>", 0},
    {"intercepts", 'i', NULL, 0, "list intercept rules <optional for list>", 0},
    {"passthrough", 'f', NULL, 0, "list passthrough rules <optional list>", 0},
    {"interface", 'N', "", 0, "Interface <optional insert>", 0},
    {"list-diag", 'E', NULL, 0, "", 0},
    {"set-tc-filter", 'X', "", 0, "add/remove TC filter to/from interface", 0},
    {"object-file", 'O', "", 0, "set object file", 0},
    {"direction", 'z', "", 0, "set direction", 0},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    program_name = state->name;
    uint32_t idx = 0;
    switch (key)
    {
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
    case 'I':
        add = true;
        break;
    case 'L':
        list = true;
        break;
    case 'N':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name required as arg to -N, --interface: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        interface = true;
        get_index(arg, &idx);
        if(idx == 0){
            printf("Interface not found: %s\n", arg);
            exit(1);
        }
        if (ifcount < MAX_IF_LIST_ENTRIES)
        {
            if ((idx > 0) && (idx < MAX_IF_ENTRIES))
            {
                if_list[ifcount] = idx;
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
        if (!strlen(arg))
        {
            fprintf(stderr, "object file name required as arg to -O, --object-file: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        object = true;
        object_file = arg;
        break;
    case 'P':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -P, --per-interface-rules: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        get_index(arg, &idx);
        if(strcmp("all", arg) && idx == 0){
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
            prefix_interface = arg;
        }
        break;
    case 'Q':
        ebpf_disable = true;
        break;
    case 'T':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -T, --set-tun-mode: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        get_index(arg, &idx);
        if(strcmp("all", arg) && idx == 0){
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
            tun_interface = arg;
        }
        break;
    case 'X':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -X, --set-tc-filter: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        get_index(arg, &idx);
        if(strcmp("all", arg) && idx == 0){
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
            tc_interface = arg;
        }
        break;
    case 'c':
        if (!inet_aton(arg, &dcidr))
        {
            fprintf(stderr, "Invalid IP Address for arg -c, --dcidr-block: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        cd = true;
        break;
    case 'e':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -e, --icmp-echo: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        get_index(arg, &idx);
        if(strcmp("all", arg) && idx == 0){
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
            echo_interface = arg;
        }
        break;
    case 'd':
        disable = true;
        break;
    case 'f':
        passthru = true;
        break;
    case 'h':
        high_port = port2s(arg);
        hpt = true;
        break;
    case 'i':
        intercept = true;
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
        if (!inet_aton(arg, &scidr))
        {
            fprintf(stderr, "Invalid IP Address for arg -o, --ocidr-block: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        cs = true;
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
    case 'r':
        route = true;
        break;
    case 't':
        tproxy_port = port2s(arg);
        tpt = true;
        break;
    case 'v':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -v, --verbose: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        get_index(arg, &idx);
        if(strcmp("all", arg) && idx == 0){
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
            verbose_interface = arg;
        }
        break;
    case 'x':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -x, --disable-ssh: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        get_index(arg, &idx);
        if(strcmp("all", arg) && idx == 0){
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
            ssh_interface = arg;
        }
        break;
    case 'z':
        if (!strlen(arg) || (strcmp("ingress", arg) && strcmp("egress", arg)))
        {
            fprintf(stderr, "direction ingress/egress required as arg to -z, --direction: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        direction = true;
        direction_string = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, 0, doc, 0, 0, 0};

void close_maps(int code){
    if(diag_fd != -1){
        close(diag_fd);
    }
    if(if_fd != -1){
        close(if_fd);
    }
    if(tun_fd != -1){
        close(if_fd);
    } 
    exit(code);
}

void open_diag_map(){
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

void open_if_map(){
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

void open_tun_map(){
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

int main(int argc, char **argv)
{
    argp_parse(&argp, argc, argv, 0, 0, 0);

    if (tcfilter && !object && !disable)
    {
        usage("-X, --set-tc-filter requires -O, --object-file for add operation");
    }

    if (tcfilter && !direction)
    {
        usage("-X, --set-tc-filter requires -z, --direction for add operation");
    }

    if (ebpf_disable)
    {
        if (tcfilter || echo || ssh_disable || verbose || per_interface || add || delete || list || flush)
        {
            usage("Q, --disable-ebpf cannot be used in combination call");
        }
        if (access(diag_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        disable_ebpf();
        exit(0);
    }

    if (interface && !(add || delete))
    {
        usage("Missing argument -I, --insert");
    }

    if (list_diag && !list)
    {
        usage("-E, --list-diag requires -L --list");
    }

    if ((tun && (echo || ssh_disable || verbose || per_interface || add || delete || list || flush || tcfilter)))
    {
        usage("-T, --set-tun-mode cannot be set as a part of combination call to zfw");
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

    if (disable && (!ssh_disable && !echo && !verbose && !per_interface && !tcfilter && !tun))
    {
        usage("Missing argument at least one of -e, -v, -x, or -E, -P, -T, -X");
    }

    if (direction && !tcfilter)
    {
        usage("missing argument -z, --direction requires -X, --set-tc-filter");
    }

    if (object && !tcfilter)
    {
        usage("missing argument -O, --object-file requires -X, --set-tc-filter");
    }

    if (add)
    {
        if (access(tproxy_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        if (!cd)
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
            if (!cs)
            {
                inet_aton("0.0.0.0", &scidr);
                splen = 0;
            }
            else
            {
                if (!sl)
                {
                    usage("Missing argument -n, --sprefix-len");
                }
            }
            map_insert();
        }
    }
    else if (delete)
    {
        if (access(tproxy_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        if (!cd)
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
            if (!cs)
            {
                inet_aton("0.0.0.0", &scidr);
                splen = 0;
            }
            else
            {
                if (!sl)
                {
                    usage("Missing argument -n, --sprefix-len");
                }
            }
            map_delete();
        }
    }
    else if (flush)
    {
        if (access(tproxy_map_path, F_OK) != 0)
        {
            ebpf_usage();
        }
        map_flush();
    }
    else if (list)
    {
        if ((access(tproxy_map_path, F_OK) != 0) || (access(diag_map_path, F_OK) != 0))
        {
            ebpf_usage();
        }
        if (list_diag)
        {
            if (cd || dl || cs || sl || prot)
            {
                printf("-E, --list-diag cannot be combined with cidr list arguments -c,-o, -m, -n, -p");
            }
            interface_diag();
            exit(0);
        }
        if (!cd && !dl)
        {
            map_list_all();
        }
        else if (!cd)
        {
            usage("Missing argument -c, --cider-block");
        }
        else if (!dl)
        {
            usage("Missing argument -m, --prefix-len");
        }
        else
        {
            if (!cs)
            {
                inet_aton("0.0.0.0", &scidr);
                splen = 0;
            }
            else
            {
                if (!sl)
                {
                    usage("Missing argument -n, --sprefix-len");
                }
            }
            map_list();
        }
    }
    else if (verbose || ssh_disable || echo || per_interface || tun)
    {
        interface_diag();
        exit(0);
    }
    else if (tcfilter)
    {
        interface_tc();
        exit(0);
    }
    else
    {
        usage("No arguments specified");
    }
    close_maps(0);
}
