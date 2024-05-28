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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <json-c/json.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/syscall.h>
#include <linux/if.h>
#include <time.h>

#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES   100 //MAX # PREFIXES
#endif
#define MAX_LINE_LENGTH     32766
#define BUFFER_SIZE         512
#define EVENT_BUFFER_SIZE   32768
#define SERVICE_ID_BYTES    32
#define MAX_TRANSP_ROUTES   256
#define MAX_IF_LIST_ENTRIES 3
#define MAX_INDEX_ENTRIES 100 
#define SOCK_NAME "/tmp/ziti-edge-tunnel.sock"
#define EVENT_SOCK_NAME "/tmp/ziti-edge-tunnel-event.sock"
#define DUMP_FILE "/tmp/dumpfile.ziti"

struct tproxy_key
{
    __u32 dst_ip;
    __u32 src_ip;
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

struct tproxy_tuple
{
    __u16 index_len;
    __u16 index_table[MAX_INDEX_ENTRIES];
};

struct range_mapping {
    __u16 high_port;
    __u16 tproxy_port;
};

struct port_extension_key {
    __u32 dst_ip;
    __u32 src_ip;
    __u16 low_port;
    __u8 dprefix_len;
    __u8 sprefix_len;
    __u8 protocol;
    __u8 pad;
};

const char *transp_map_path = "/sys/fs/bpf/tc/globals/zet_transp_map";
const char *if_tun_map_path = "/sys/fs/bpf/tc/globals/ifindex_tun_map";
const char *tp_ext_map_path = "/sys/fs/bpf/tc/globals/tproxy_extension_map";
const char *tproxy_map_path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
const char *range_map_path = "/sys/fs/bpf/tc/globals/range_map";
const char *if_list_ext_map_path = "/sys/fs/bpf/tc/globals/if_list_extension_map";
const char *count_map_path = "/sys/fs/bpf/tc/globals/tuple_count_map";
const char *wildcard_port_map_path = "/sys/fs/bpf/tc/globals/wildcard_port_map";
int ctrl_socket, event_socket;
char tunip_string[16]="";
char tunip_mask_string[10]="";
struct in_addr tun_cidr = {0};
char *tun_ifname;
bool transparent;
bool interface_registered = false;
union bpf_attr transp_map;
int transp_fd = -1;
union bpf_attr tun_map;
int tun_fd = -1;
union bpf_attr range_map;
int range_fd = -1;
union bpf_attr tp_ext_map;
int tp_ext_fd = -1;
union bpf_attr wild_map;
int wild_fd = -1;
typedef unsigned char byte;

struct wildcard_port_key {
    __u16 low_port;
    __u8 protocol;
    __u8 pad;
};

void process_service_updates(char *service_id);
void close_maps(int code);
void open_transp_map();
void open_tun_map();
void open_tproxy_ext_map();
void open_range_map();
void open_wild_map();
void zfw_update(char *ip, char *mask, char *lowport, char *highport, char *protocol, char *service_id, char *action);
void unbind_route_loopback(struct in_addr *address, unsigned short mask);
void INThandler(int sig);
void map_delete_key(char *service_id);
void route_flush();
void process_rules();
bool check_diag();
bool in_service_set(__u16 tproxy_port, unsigned char protocol, char *service_id);
bool rule_exists(uint32_t dst_ip, uint8_t dplen, uint32_t src_ip, uint8_t splen,
 uint16_t low_port, uint16_t high_port, uint8_t protocol);
uint32_t get_resolver_ip(char *ziti_cidr);
int process_bind(json_object *jobj, char *action);
int process_routes(char *service_id);
void if_list_ext_delete_key(struct port_extension_key key);
void range_delete_key(struct port_extension_key key);
void map_delete(struct tproxy_key *key, struct port_extension_key *port_ext_key);
void delete_wild_entry(char *low_port, char *high_port,char *protocol);
void add_wild_entry(char *low_port, char *high_port, char *protocol);
void delete_wild_key(struct wildcard_port_key *key);
void flush_wild();

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

struct tproxy_extension_mapping {
    char service_id[23];
};

struct tproxy_extension_key {
    __u16 tproxy_port;
    __u8 protocol;
    __u8 pad;
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

/*value to ifindex_tun_map*/
struct ifindex_tun {
    uint32_t index;
    char ifname[IFNAMSIZ];
    char cidr[16];
    char mask[3];
    bool verbose;
};

void INThandler(int sig){
    signal(sig, SIG_IGN);
    route_flush();
    flush_wild();
    process_rules();
    close_maps(1);
}

void close_maps(int code){
    if(event_socket != -1){
        close(event_socket);
    }
    if(event_socket != -1){
        close(ctrl_socket);
    }
    if(transp_fd != -1){
        close(transp_fd);
    }
     if(tun_fd != -1){
        close(tun_fd);
    }
    if (tp_ext_fd != -1){
        close(tp_ext_fd);
    }
    if (range_fd != -1){
        close(range_fd);
    }
    if (wild_fd != -1){
        close(wild_fd);
    }
    exit(code);
}

void route_flush()
{
    struct transp_key init_key = {{0}};
    struct transp_key *key = &init_key;
    struct transp_value o_routes;
    struct transp_key current_key;
    transp_map.key = (uint64_t)key;
    transp_map.value = (uint64_t)&o_routes;
    transp_map.map_fd = transp_fd;
    transp_map.flags = BPF_ANY;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &transp_map, sizeof(transp_map));
        if (ret == -1)
        {
            break;
        }
        transp_map.key = transp_map.next_key;
        current_key = *(struct transp_key *)transp_map.key;
        process_routes(current_key.service_id);
    }
}

int process_routes(char *service_id){
    struct transp_key key = {{0}};
    sprintf(key.service_id, "%s", service_id);
    struct transp_value o_routes;
    transp_map.key = (uint64_t)&key;
    transp_map.value = (uint64_t)&o_routes;
    transp_map.map_fd = transp_fd;
    transp_map.flags = BPF_ANY;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &transp_map, sizeof(transp_map));
    bool changed = false;
    if (!lookup)
    {
        for(int x = 0; x <= o_routes.count; x++){
            unbind_route_loopback(&o_routes.tentry[x].saddr, o_routes.tentry[x].prefix_len);
        }
        map_delete_key(service_id);
    }
    return 0;
}

void process_service_updates(char * service_id)
{
    if (range_fd == -1)
    {
        open_range_map();
    }
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));

    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
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
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            struct port_extension_key port_ext_key = {0};
            for(int x = 0; x < orule.index_len; x++){
                struct port_extension_key port_ext_key = {0};
                port_ext_key.dst_ip = current_key.dst_ip;
                port_ext_key.src_ip = current_key.src_ip;
                port_ext_key.low_port = orule.index_table[x];
                port_ext_key.dprefix_len = current_key.dprefix_len;
                port_ext_key.sprefix_len = current_key.sprefix_len;
                port_ext_key.protocol = current_key.protocol,
                port_ext_key.pad = 0;
                range_map.key = (uint64_t)&port_ext_key;
                struct range_mapping range_ports = {0};
                range_map.value = (uint64_t)&range_ports;
                range_map.map_fd = range_fd;
                range_map.flags = BPF_ANY;
                int range_result = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &range_map, sizeof(range_map));
                if(!range_result){
                    if(in_service_set(range_ports.tproxy_port, port_ext_key.protocol, service_id)){
                        map_delete(&current_key, &port_ext_key);
                    }
                }
            }
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&current_key;
    }
    close(fd);
}

bool rule_exists(uint32_t dst_ip, uint8_t dplen, uint32_t src_ip, uint8_t splen,
 uint16_t low_port, uint16_t high_port, uint8_t protocol)
{
    if (range_fd == -1)
    {
        open_range_map();
    }
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return false;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
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
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            struct port_extension_key port_ext_key = {0};
            for(int x = 0; x < orule.index_len; x++){
                struct port_extension_key port_ext_key = {0};
                port_ext_key.dst_ip = current_key.dst_ip;
                port_ext_key.src_ip = current_key.src_ip;
                port_ext_key.low_port = orule.index_table[x];
                port_ext_key.dprefix_len = current_key.dprefix_len;
                port_ext_key.sprefix_len = current_key.sprefix_len;
                port_ext_key.protocol = current_key.protocol,
                port_ext_key.pad = 0;
                range_map.key = (uint64_t)&port_ext_key;
                struct range_mapping range_ports = {0};
                range_map.value = (uint64_t)&range_ports;
                range_map.map_fd = range_fd;
                range_map.flags = BPF_ANY;
                int range_result = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &range_map, sizeof(range_map));
                if(!range_result){
                    if((ntohl(current_key.dst_ip) == dst_ip) && (current_key.src_ip == src_ip) && (current_key.protocol == protocol) &&
                    (current_key.dprefix_len == dplen) && (current_key.sprefix_len == splen) && (ntohs(port_ext_key.low_port) == low_port) &&
                    (ntohs(range_ports.high_port) == high_port)){
                        close(fd);
                        return true;
                    }
                }
            }
        }
        map.key = (uint64_t)&current_key;
    }
    close(fd);
    return false;
}

void process_rules()
{
    if (range_fd == -1)
    {
        open_range_map();
    }
    union bpf_attr map;
    struct tproxy_key init_key = {0};
    struct tproxy_key *key = &init_key;
    struct tproxy_key current_key;
    struct tproxy_tuple orule;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = 0;
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
        lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
        if (!lookup)
        {
            struct port_extension_key port_ext_key = {0};
            for(int x = 0; x < orule.index_len; x++){
                struct port_extension_key port_ext_key = {0};
                port_ext_key.dst_ip = current_key.dst_ip;
                port_ext_key.src_ip = current_key.src_ip;
                port_ext_key.low_port = orule.index_table[x];
                port_ext_key.dprefix_len = current_key.dprefix_len;
                port_ext_key.sprefix_len = current_key.sprefix_len;
                port_ext_key.protocol = current_key.protocol,
                port_ext_key.pad = 0;
                range_map.key = (uint64_t)&port_ext_key;
                struct range_mapping range_ports = {0};
                range_map.value = (uint64_t)&range_ports;
                range_map.map_fd = range_fd;
                range_map.flags = BPF_ANY;
                int range_result = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &range_map, sizeof(range_map));
                if(!range_result){
                    if(ntohs(range_ports.tproxy_port) > 0){
                        map_delete(&current_key, &port_ext_key);
                    }
                }
            }
        }
        else
        {
            printf("Not Found\n");
        }
        map.key = (uint64_t)&current_key;
    }
    close(fd);
}

void if_list_ext_delete_key(struct port_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)if_list_ext_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (!result)
    {
        printf("cleared if_list_ext_map entry\n");
    }
    close(fd);
}

void range_delete_key(struct port_extension_key key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)range_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (!result)
    {
        char *saddr = nitoa(ntohl(key.src_ip));
        char *daddr = nitoa(ntohl(key.dst_ip));
        if(saddr && daddr){
            printf("cleared range_map entry: Range dest=%s/%u, source=%s/%u, protocol=%s, low_port=%u\n", daddr,  key.dprefix_len, saddr,
            key.sprefix_len, key.protocol == 6 ? "tcp" : "udp" , htons(key.low_port));
        }
        if(saddr){
            free(saddr);
        }
        if(daddr){
            free(daddr);
        }
    }
    close(fd);
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

void map_delete(struct tproxy_key *key, struct port_extension_key *port_ext_key)
{
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    struct tproxy_tuple orule = {0}; 
    map.pathname = (uint64_t)tproxy_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return;
    }
    map.map_fd = fd;
    map.key = (uint64_t)key;
    map.value = (uint64_t)&orule;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    unsigned short index = port_ext_key->low_port;
    if (lookup)
    {
        printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
        return;
    }
    else
    {
        printf("lookup success\n");
        if (key->protocol == IPPROTO_UDP)
        {
            printf("Attempting to remove UDP mapping\n");
        }
        else if (key->protocol == IPPROTO_TCP)
        {
            printf("Attempting to remove TCP mapping\n");
        }
        else
        {
            printf("Unsupported Protocol\n");
            close(fd);
            return;
        }
        remove_index(index, &orule);
        if (orule.index_len == 0)
        {
            memset(&map, 0, sizeof(map));
            map.pathname = (uint64_t)tproxy_map_path;
            map.bpf_fd = 0;
            int end_fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
            if (end_fd == -1)
            {
                printf("BPF_OBJ_GET: %s\n", strerror(errno));
                return;
            }
            // delete element with specified key
            map.map_fd = end_fd;
            map.key = (uint64_t)key;
            int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
            if (result)
            {
                printf("MAP_DELETE_ELEM: %s\n", strerror(errno));
                close(end_fd);
                close(fd);
                return;
            }
            else
            {
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
                    close(end_fd);
                    close(fd);
                    return;
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
                range_delete_key(*port_ext_key);
                if_list_ext_delete_key(*port_ext_key);
                return;
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
            return;
        }
    }
    close(fd);
    range_delete_key(*port_ext_key);
    if_list_ext_delete_key(*port_ext_key);
}

void ebpf_usage()
{
    if (access(transp_map_path, F_OK) != 0)
    {
        printf("Not enough privileges or ebpf not enabled!\n"); 
        printf("Run as \"sudo\" with ingress tc filter [filter -X, --set-tc-filter] set on at least one interface\n");
        close_maps(1);
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

void open_wild_map()
{
    memset(&wild_map, 0, sizeof(wild_map));
    /* set path name with location of map in filesystem */
    wild_map.pathname = (uint64_t)wildcard_port_map_path;
    wild_map.bpf_fd = 0;
    wild_map.file_flags = 0;
    /* make system call to get fd for map */
    wild_fd = syscall(__NR_bpf, BPF_OBJ_GET, &wild_map, sizeof(wild_map));
    if (wild_fd == -1)
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

void open_transp_map(){
    memset(&transp_map, 0, sizeof(transp_map));
    /* set path name with location of map in filesystem */
    transp_map.pathname = (uint64_t)transp_map_path;
    transp_map.bpf_fd = 0;
    transp_map.file_flags = 0;
    /* make system call to get fd for map */
    transp_fd = syscall(__NR_bpf, BPF_OBJ_GET, &transp_map, sizeof(transp_map));
    if (transp_fd == -1)
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



void map_delete_key(char *service_id)
{    
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    struct transp_key key = {{0}};
    sprintf(key.service_id, "%s", service_id);
    map.pathname = (uint64_t)transp_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
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
        printf("service id: %s removed from trans_map\n", service_id);
    }
    close(fd);
}

__u16 len2u16(char *len)
{
    char *endPtr;
    int32_t tmpint = strtol(len, &endPtr, 10);
    if ((tmpint < 0) || (tmpint > 32) || (!(*(endPtr) == '\0')))
    {
        printf("Invalid Prefix Length: %s\n", len);
        return 32;
    }
    __u16 u16int = (__u16)tmpint;
    return u16int;
}

void bind_route(struct in_addr *address, unsigned short mask)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("binding local ip route to %s via loopback\n", cidr_block);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "route", "add", "local", cidr_block, "dev", "lo", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn bind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error binding route");
    }
    free(cidr_block);
}

void unbind_route_loopback(struct in_addr *address, unsigned short mask)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("unbinding route to %s via dev %s\n", cidr_block, "lo");
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "route", "del", "local", cidr_block, "dev", "lo", NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn unbind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error unbinding route");
    }
    free(cidr_block);
}

void unbind_route(struct in_addr *address, unsigned short mask, char *dev)
{
    char *prefix = inet_ntoa(*address);
    char *cidr_block = malloc(19);
    sprintf(cidr_block, "%s/%u", prefix, mask);
    printf("unbinding route to %s via dev %s\n", cidr_block, dev);
    pid_t pid;
    char *const parmList[] = {"/usr/sbin/ip", "route", "del", cidr_block, "dev", dev, NULL};
    if ((pid = fork()) == -1)
    {
        perror("fork error: can't spawn unbind");
    }
    else if (pid == 0)
    {
        execv("/usr/sbin/ip", parmList);
        printf("execv error: unknown error unbinding route");
    }
    free(cidr_block);
}

void setpath(char *dirname, char *filename, char * slink)
{
    char buf[PATH_MAX + 1]; 	
    DIR *directory;
    struct dirent *file;
    struct stat statbuf;
    if((directory = opendir(dirname)) == NULL) {
        fprintf(stderr,"cannot open directory: %s\n", dirname);
        return;
    }
    chdir(dirname);
    while((file = readdir(directory)) != NULL) {
        lstat(file->d_name,&statbuf);
        if(S_ISDIR(statbuf.st_mode)) {
            if(strcmp(".",file->d_name) == 0 || strcmp("..",file->d_name) == 0){
                continue;
            }
            setpath(file->d_name, filename, slink);
        }else if((strcmp(filename,file->d_name) == 0)){
	     realpath(file->d_name,buf);
         //printf("buf=%s\n",buf);
	     if(strstr((char *)buf, "/.ziti/")){
		 unlink(slink);
		 symlink(buf,slink);
             }
	    }
    }
    chdir("..");
    closedir(directory);
}


void string2Byte(char* string, byte* bytes)
{
    int si;
    int bi;

    si = 0;
    bi = 0;

    while(string[si] != '\0')
    {
        bytes[bi++] = string[si++];
    }
}

bool in_service_set(__u16 tproxy_port, unsigned char protocol, char *service_id){
    if (tp_ext_fd == -1)
    {
        open_tproxy_ext_map();
    }
    struct tproxy_extension_key key = {0};
    struct tproxy_extension_mapping ext_value = {0};
    tp_ext_map.key = (uint64_t)&key;
    tp_ext_map.value = (uint64_t)&ext_value;
    tp_ext_map.map_fd = tp_ext_fd;
    tp_ext_map.flags = BPF_ANY;
    key.protocol = protocol;
    key.tproxy_port = tproxy_port;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tp_ext_map, sizeof(tp_ext_map));
    if (!lookup)
    {
        if(!strcmp(service_id, ext_value.service_id)){
            return true;
        }
    }
    return false;
}

void zfw_update(char *ip, char *mask, char *lowport, char *highport, char *protocol, char *service_id, char *action){
    if (tp_ext_fd == -1)
    {
        open_tproxy_ext_map();
    }
    __u16 random_port = 0;
    struct tproxy_extension_key key = {0};
    struct tproxy_extension_mapping ext_value = {0};
    tp_ext_map.key = (uint64_t)&key;
    tp_ext_map.value = (uint64_t)&ext_value;
    tp_ext_map.map_fd = tp_ext_fd;
    tp_ext_map.flags = BPF_ANY;
    __u8 count = 0;
    while(true){
        random_port = htons(1024 + rand() % (65535 - 1023));
        key.tproxy_port = random_port;
        if(strcmp("tcp", protocol)==0){
            key.protocol = IPPROTO_TCP; 
        }else{
            key.protocol = IPPROTO_UDP;
        }
        int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tp_ext_map, sizeof(tp_ext_map));
        if (lookup)
        {
            printf("assigning unique tproxy port as label\n");
            break;
        }
        if(count > 20){
            printf("timed out searching for free tproxy port\n");
            return;
        }
        count++;
    }
    char tproxy_port[6];
    sprintf(tproxy_port, "%u", random_port);
    if (access("/usr/sbin/zfw", F_OK) != 0)
    {
        printf("ebpf not running: Cannot find /usr/sbin/zfw\n");
        return;
    }
    pid_t pid;
    char *const parmList[17] = {"/usr/sbin/zfw", action, "-c", ip, "-m", mask, "-l",
     lowport, "-h", highport, "-t", tproxy_port, "-p", protocol, "-s", service_id, NULL};
    if ((pid = fork()) == -1){
        perror("fork error: can't spawn bind");
    }else if (pid == 0) {
       execv("/usr/sbin/zfw", parmList);
       printf("execv error: unknown error binding\n");
    }else{
        int status =0;
        if(!(waitpid(pid, &status, 0) > 0)){
            if(WIFEXITED(status) && !WEXITSTATUS(status)){
                printf("zfw %s action for : %s not set\n", action,  ip);
            }
        }
    }
}

bool check_diag(){
    pid_t pid;
    char *const parmList[4] = {"/usr/sbin/zfw", "-L", "-E", NULL};
    if ((pid = fork()) == -1){
        perror("fork error: can't spawn bind");
    }else if (pid == 0) {
       execv("/usr/sbin/zfw", parmList);
       printf("execv error: unknown error binding\n");
    }else{
        int status =0;
        if(!(waitpid(pid, &status, 0) > 0)){
            if(WIFEXITED(status) && !WEXITSTATUS(status)){
                printf("Diag Interface List Failed!");
                return false;
            }
        }
    }
    return true;
}

int process_bind(json_object *jobj, char *action)
{
    if (transp_fd == -1)
    {
        open_transp_map();
    }
    char service_id[32];
    struct json_object *id_obj = json_object_object_get(jobj, "Id");
    if(id_obj)
    {
        if((strlen(json_object_get_string(id_obj)) + 1 ) <= 32)
        {
            sprintf(service_id, "%s", json_object_get_string(id_obj));
            struct json_object *addresses_obj = json_object_object_get(jobj, "Addresses");
            if(addresses_obj && !strcmp(action,"-I"))
            {
                int addresses_obj_len = json_object_array_length(addresses_obj);
                // enum json_type type;
                struct json_object *allowedSourceAddresses = json_object_object_get(jobj, "AllowedSourceAddresses");
                if (allowedSourceAddresses)
                {
                    int allowedSourceAddresses_len = json_object_array_length(allowedSourceAddresses);
                    printf("allowedSourceAddresses key exists: binding addresses to loopback\n");
                    int j;
                    for (j = 0; j < allowedSourceAddresses_len; j++)
                    {
                        struct json_object *address_obj = json_object_array_get_idx(allowedSourceAddresses, j);
                        if (address_obj)
                        {
                            struct json_object *host_obj = json_object_object_get(address_obj, "IsHost");
                            if(host_obj){
                                bool is_host = json_object_get_boolean(host_obj);
                                char ip[16];
                                char mask[10];
                                if(is_host)
                                {
                                    printf("Invalid: Hostnames not supported for AllowedSourceAddress\n");
                                }else
                                {
                                    struct json_object *ip_obj = json_object_object_get(address_obj, "IP");
                                    printf("\n\nIP intercept:\n");                   
                                    if(ip_obj)
                                    {           
                                        struct json_object *prefix_obj = json_object_object_get(address_obj, "Prefix");
                                        if(prefix_obj){
                                            char ip[strlen(json_object_get_string(ip_obj) + 1)];
                                            sprintf(ip,"%s", json_object_get_string(ip_obj));
                                            int smask = sprintf(mask, "%d", json_object_get_int(prefix_obj));
                                            printf("Service_IP=%s\n", ip);
                                            struct in_addr tuncidr;
                                            if (inet_aton(ip, &tuncidr)){
                                                bind_route(&tuncidr, len2u16(mask));
                                                if (j < MAX_TRANSP_ROUTES)
                                                {
                                                    struct transp_key key = {{0}};
                                                    sprintf(key.service_id, "%s", service_id);
                                                    struct transp_value o_routes;
                                                    transp_map.key = (uint64_t)&key;
                                                    transp_map.value = (uint64_t)&o_routes;
                                                    transp_map.map_fd = transp_fd;
                                                    transp_map.flags = BPF_ANY;
                                                    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &transp_map, sizeof(transp_map));
                                                    bool changed = false;
                                                    if (lookup)
                                                    {
                                                        o_routes.tentry[j].saddr = tuncidr;
                                                        o_routes.tentry[j].prefix_len = len2u16(mask);
                                                        o_routes.count = j;
                                                        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &transp_map, sizeof(transp_map));
                                                        if (result)
                                                        {
                                                            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                                                        }
                                                    }
                                                    else
                                                    {
                                                        o_routes.tentry[j].saddr = tuncidr;
                                                        o_routes.tentry[j].prefix_len = len2u16(mask);
                                                        o_routes.count = j;                                       
                                                        int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &transp_map, sizeof(transp_map));
                                                        if (result)
                                                        {
                                                            printf("MAP_UPDATE_ELEM: %s \n", strerror(errno));
                                                        }
                                                    }
                                                    
                                                }
                                                else
                                                {
                                                    printf("Can't store more than %d transparency routes per service\n", MAX_TRANSP_ROUTES);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }       
            }else{
                process_routes(service_id);
            }
        }
    }
    return 0;
}

 uint32_t get_resolver_ip(char *ziti_cidr){
    uint32_t cidr[4];
        int bits;
        int ret = sscanf(ziti_cidr, "%d.%d.%d.%d", &cidr[0], &cidr[1], &cidr[2], &cidr[3]);
        if (ret != 4) {
            printf(" %s Unable to determine ziti_dns resolver address: Bad CIDR FORMAT\n", ziti_cidr);
            return 0;
        }

        uint32_t address_bytes = 0;
        for (int i = 0; i < 4; i++) {
            address_bytes <<= 8U;
            address_bytes |= (cidr[i] & 0xFFU);
        }
        uint32_t ziti_dns_resolver_ip = 0;
        ziti_dns_resolver_ip = address_bytes + 2;
        return ziti_dns_resolver_ip;
}


void delete_wild_key(struct wildcard_port_key *key){
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    map.pathname = (uint64_t)wildcard_port_map_path;
    map.bpf_fd = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
    }
    // delete element with specified key
    map.map_fd = fd;
    map.key = (uint64_t)key;
    int result = syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &map, sizeof(map));
    if (!result)
    {
        printf("cleared if_list_ext_map entry\n");
    }
    close(fd);
}

void flush_wild(){
    if(wild_fd == -1){
        open_wild_map();
    }
    struct wildcard_port_key init_key = {0};
    struct wildcard_port_key *key = &init_key;
    uint32_t  wcount;
    struct wildcard_port_key current_key;
    wild_map.key = (uint64_t)key;
    wild_map.value = (uint64_t)&wcount;
    wild_map.map_fd = wild_fd;
    wild_map.flags = BPF_ANY;
    int ret = 0;
    while (true)
    {
        ret = syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &wild_map, sizeof(wild_map));
        if (ret == -1)
        {
            break;
        }
        wild_map.key = wild_map.next_key;
        current_key = *(struct wildcard_port_key *)wild_map.key;
        delete_wild_key(&current_key);
    }

}

void update_wild_key(struct wildcard_port_key *key, uint32_t count){
    if (wild_fd == -1)
    {
        open_wild_map();
    }
    wild_map.key = (uint64_t)key;
    wild_map.value = (uint64_t)&count;
    wild_map.map_fd = wild_fd;
    wild_map.flags = BPF_ANY;
    int result = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &wild_map, sizeof(wild_map));
    if (result)
    {
        printf("MAP_UPDATE_ELEM_DATA: %s \n", strerror(errno));
    }
    printf("updated to %u \n", count);
}

void add_wild_entry(char *low_port, char *high_port, char *protocol){
    struct wildcard_port_key key = {0};
    key.low_port = port2s(low_port);
    printf("protocol=%s\n", protocol);
    key.protocol = strcmp("udp", protocol) ? IPPROTO_TCP : IPPROTO_UDP;
    key.pad = 0;
    uint32_t wcount = 0;
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    /* set path name with location of map in filesystem */
    map.pathname = (uint64_t)wildcard_port_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    /* make system call to get fd for map */
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s \n", strerror(errno));
        return;
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value = (uint64_t)&wcount;
    /* make system call to lookup prefix/mask in map */
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    if (lookup){
        wcount = 1;
        zfw_update(tunip_string, tunip_mask_string, low_port, high_port, protocol, "0000000000000000000000", "-I");
    }else{
        wcount += 1;
    }
    update_wild_key(&key, wcount); 
    close(fd);
}



void delete_wild_entry(char *low_port, char *high_port, char *protocol){
    struct wildcard_port_key key = {0};
    key.low_port = port2s(low_port);
    key.protocol = strcmp("udp", protocol) ? IPPROTO_TCP : IPPROTO_UDP;
    key.pad = 0;
    uint32_t wcount = 0;
    union bpf_attr map;
    memset(&map, 0, sizeof(map));
    /* set path name with location of map in filesystem */
    map.pathname = (uint64_t)wildcard_port_map_path;
    map.bpf_fd = 0;
    map.file_flags = 0;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &map, sizeof(map));
    if (fd == -1)
    {
        printf("BPF_OBJ_GET: %s\n", strerror(errno));
        return;
    }
    map.map_fd = fd;
    map.key = (uint64_t)&key;
    map.value  = (uint64_t)&wcount;
    int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &map, sizeof(map));
    if (!lookup){
        if(wcount > 1){
            wcount -= 1;
            update_wild_key(&key, wcount);
        }else{
            printf("DELTETING WILD CARD\n");
            delete_wild_key(&key);
            zfw_update(tunip_string, tunip_mask_string, low_port, high_port, protocol, "0000000000000000000000", "-D");
        }
    }else{
        printf("ENTRY NOT FOUND\n");
    }
    close(fd);
}

int process_dial(json_object *jobj, char *action){
    struct json_object *service_id_obj = json_object_object_get(jobj, "Id");
    char service_id[strlen(json_object_get_string(service_id_obj)) + 1];
    sprintf(service_id, "%s", json_object_get_string(service_id_obj));
    struct json_object *addresses_obj = json_object_object_get(jobj, "Addresses");
    if(addresses_obj)
    {
        int addresses_obj_len = json_object_array_length(addresses_obj);
        //printf("There are %d addresses\n", addresses_len);
        struct json_object *ports_obj = json_object_object_get(jobj, "Ports");
        if(ports_obj){
            int ports_obj_len = json_object_array_length(ports_obj);
            //printf("There are %d portRanges\n", portRanges_len);
            struct json_object *protocols_obj = json_object_object_get(jobj, "Protocols");
            if(protocols_obj){
                int protocols_obj_len = json_object_array_length(protocols_obj);
                //printf("There are %d protocols\n", protocols_len);
                int i;
                int j;
                int k;
                for(i=0; i < protocols_obj_len ; i++){
                    struct json_object *protocol_obj = json_object_array_get_idx(protocols_obj, i);
                    if(protocol_obj){
                        for(j=0; j < addresses_obj_len ; j++){
                            char protocol[4];
                            sprintf(protocol, "%s", json_object_get_string(protocol_obj));
                            struct json_object *address_obj = json_object_array_get_idx(addresses_obj, j);
                            if(address_obj){
                                //printf("Add: %s\n",json_object_get_string(addressobj));
                                for(k=0; k < ports_obj_len ; k++){
                                    struct json_object *port_obj = json_object_array_get_idx(ports_obj, k);
                                    if(port_obj){
                                        struct json_object *range_low_obj = json_object_object_get(port_obj, "Low");
                                        struct json_object *range_high_obj = json_object_object_get(port_obj, "High");
                                        char lowport[7];
                                        char highport[7];
                                        sprintf(lowport,"%d", json_object_get_int(range_low_obj));
                                        sprintf(highport,"%d", json_object_get_int(range_high_obj));
                                        struct json_object *host_obj = json_object_object_get(address_obj, "IsHost");
                                        if(host_obj){  
                                            bool is_host = json_object_get_boolean(host_obj);
                                            char ip[16];
                                            char mask[10];
                                            if(is_host)
                                            {
                                                uint32_t resolver = get_resolver_ip(tunip_string);
                                                if(!rule_exists(resolver, 32, 0, 0, 53, 53, IPPROTO_UDP)){
                                                    if(resolver){
                                                        char *resolver_ip = nitoa(resolver);
                                                        if(resolver_ip){
                                                            zfw_update(resolver_ip, "32", "53", "53", "udp", "0000000000000000000000",action);
                                                            free(resolver_ip);
                                                            printf("-----------------Resolver Rule Entered -------------------\n");
                                                        }
                                                    }
                                                }else{
                                                    printf("-----------------Resolver Rule Exists -------------------\n");
                                                }
                                                struct json_object *hostname_obj = json_object_object_get(address_obj, "HostName");
                                                printf("\n\nHost intercept: Skipping ebpf\n");       
                                                if(hostname_obj){
                                                    char hostname[strlen(json_object_get_string(address_obj)) + 1];
                                                    sprintf(hostname, "%s", json_object_get_string(hostname_obj));
                                                    if(strncmp(hostname,"*.", 2)){
                                                        struct addrinfo hints_1, *res_1;
                                                        memset(&hints_1, '\0', sizeof(hints_1));

                                                        int err = getaddrinfo( hostname, lowport, &hints_1, &res_1);
                                                        if(err){
                                                            printf("Unable to resolve: %s\n", hostname);
                                                            continue;
                                                        }
                                                    
                                                        inet_ntop(AF_INET, &res_1->ai_addr->sa_data[2], ip, sizeof(ip));
                                                        printf("Hostname=%s\n", hostname);
                                                        printf ("Resolved_IP=%s\n", ip);
                                                        printf("Protocol=%s\n", protocol);
                                                        printf("Low=%s\n", lowport); 
                                                        printf("High=%s\n\n", highport);
                                                        if(!strcmp("-I", action)){
                                                            if(strlen(ip) > 7 && strlen(ip) < 16){
                                                                zfw_update(ip, "32", lowport, highport, protocol, service_id,action); 
                                                            }
                                                        }
                                                    }else{
                                                        printf("Wild Card Hostname=%s\n", hostname);
                                                        printf("Protocol=%s\n", protocol);
                                                        printf("Low=%s\n", lowport); 
                                                        printf("High=%s\n\n", highport);
                                                        if(!strcmp("-I", action)){
                                                            printf("ADDING ENTRY\n");
                                                            add_wild_entry(lowport, highport, protocol); 
                                                        }else{
                                                            printf("REMOVING ENTRY\n");
                                                            delete_wild_entry(lowport, highport, protocol);
                                                        }
                                                        
                                                    }
                                                } 
                                            }
                                            else{ 
                                                struct json_object *ip_obj = json_object_object_get(address_obj, "IP");
                                                printf("\n\nIP intercept:\n");                   
                                                if(ip_obj)
                                                {           
                                                    struct json_object *prefix_obj = json_object_object_get(address_obj, "Prefix");
                                                    char ip[strlen(json_object_get_string(ip_obj) + 1)];
                                                    sprintf(ip,"%s", json_object_get_string(ip_obj));
                                                    int smask = sprintf(mask, "%d", json_object_get_int(prefix_obj));
                                                    printf("Service_IP=%s\n", ip);
                                                    printf("Protocol=%s\n", protocol);
                                                    printf("Low=%s\n", lowport); 
                                                    printf("high=%s\n\n", highport);
                                                    struct in_addr tuncidr;
                                                    char *transp_mode = "TRANSPARENT_MODE";
                                                    char *mode = getenv(transp_mode);
                                                    if(mode){
                                                        if(!strcmp(mode,"true")){
                                                            if (inet_aton(ip, &tuncidr) && tun_ifname){
                                                                unbind_route(&tuncidr, len2u16(mask), tun_ifname);
                                                            }  
                                                        }
                                                    }
                                                    if(!strcmp("-I", action)){
                                                        zfw_update(ip, mask, lowport, highport, protocol, service_id, action);
                                                    }
                                                }  
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if(strcmp("-I", action)){
            process_service_updates(service_id);
        }
    }
    return 0;
}

void enumerate_service(struct json_object *services_obj, char *action){
    if(!interface_registered){
        interface_registered = check_diag();
    }
    int services_obj_len = json_object_array_length(services_obj);
    for(int s = 0; s < services_obj_len; s++){
        struct json_object *service_obj = json_object_array_get_idx(services_obj, s);
        struct json_object *service_id_obj = json_object_object_get(service_obj, "Id");
        char service_id[strlen(json_object_get_string(service_id_obj)) + 1];
        sprintf(service_id, "%s", json_object_get_string(service_id_obj));
        printf("\n\n###########################################\n");
        printf("Service Id=%s\n", service_id);
        struct json_object *service_permissions_obj = json_object_object_get(service_obj, "Permissions");
        if(service_permissions_obj){
            struct json_object *service_bind_obj = json_object_object_get(service_permissions_obj, "Bind");
            struct json_object *service_dial_obj = json_object_object_get(service_permissions_obj, "Dial");
            bool dial = json_object_get_boolean(service_dial_obj);
            bool bind = json_object_get_boolean(service_bind_obj);
            if(dial){
                printf("Service policy is Dial\n");
                process_dial(service_obj, action);
            }
            if(bind){
                if(transp_fd == -1){
                    open_transp_map();
                }
                printf("Service policy is Bind\n");
                process_bind(service_obj, action);
            }
        }
    }
}

void get_string(char source[4096], char dest[2048]){
    int count = 0;
    while((source[count] != '\n') && (count < 1023)){
        dest[count] = source[count];
        count++;
    }
    dest[count]='\n';
    dest[count + 1] = '\0';
}

int run(){
    signal(SIGINT, INThandler);
    system("clear");
    setpath("/tmp/", "ziti-edge-tunnel.sock",SOCK_NAME);
    setpath("/tmp/", "ziti-edge-tunnel-event.sock",EVENT_SOCK_NAME);
    struct sockaddr_un ctrl_addr;
    struct sockaddr_un event_addr;	
    int new_count = 0;
    int old_count =0;
    char* command = "{\"Command\":\"ZitiDump\",\"Data\":{\"DumpPath\": \"/tmp/.ziti\"}}";
    int command_len = strlen(command);	    
    byte cmdbytes[command_len];
    string2Byte(command, cmdbytes);
    char *val_type_str, *str;
    int val_type;
    int ret;

    
    char event_buffer[EVENT_BUFFER_SIZE];
     //open Unix client ctrl socket 
    event_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctrl_socket == -1) {
        perror("socket");
        printf("%s\n", strerror(errno));
        return 1;
    }
    //open Unix client ctrl socket 
    ctrl_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctrl_socket == -1) {
        perror("socket");
        printf("%s\n", strerror(errno));
        return 1;
    }
    //zero sockaddr_un for compatibility
    memset(&event_addr, 0, sizeof(struct sockaddr_un));
    memset(&ctrl_addr, 0, sizeof(struct sockaddr_un));
    ctrl_addr.sun_family = AF_UNIX;
    event_addr.sun_family = AF_UNIX;
    //copy string path of symbolic link to Sun Paths
    strncpy(event_addr.sun_path, EVENT_SOCK_NAME, sizeof(event_addr.sun_path) - 1);
    strncpy(ctrl_addr.sun_path, SOCK_NAME, sizeof(ctrl_addr.sun_path) - 1);
    //connect to ziti-edge-tunnel unix sockets
    ret = connect(event_socket, (const struct sockaddr *) &event_addr,sizeof(struct sockaddr_un));
    if (ret == -1) {
        fprintf(stderr, "The ziti-edge-tunnel-event sock is down.\n");
        printf("%s\n", strerror(errno));
        return -1;
    } 
    ret = connect (ctrl_socket, (const struct sockaddr *) &ctrl_addr,sizeof(struct sockaddr_un));
    if (ret == -1) {
        fprintf(stderr, "The ziti-edge-tunnel sock is down.\n");
        printf("%s\n", strerror(errno));
        return -1;
    }   
    while(true)
    {
        if(tun_fd == -1){
            open_tun_map();
        }
        if(!strcmp(tunip_string,"")){
            printf("registering ziti dns cidr block\n");
            uint32_t key = 0;
            struct ifindex_tun o_tunif;
            tun_map.key = (uint64_t)&key;
            tun_map.value = (uint64_t)&o_tunif;
            tun_map.map_fd = tun_fd;
            int lookup = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &tun_map, sizeof(tun_map));
            if (!lookup)
            {   
                if((sizeof(o_tunif.cidr) > 0) && (sizeof(o_tunif.mask) >0)){
                    sprintf(tunip_string, "%s" , o_tunif.cidr);
                    sprintf(tunip_mask_string, "%s", o_tunif.mask);
                    if (!inet_aton(tunip_string, &tun_cidr)){
                        printf("Invalid ziti tunnel IP\n");
                    }
                    tun_ifname = o_tunif.ifname;
                }
            }
        }
        memset(&event_buffer, 0, EVENT_BUFFER_SIZE);
        char ch[1];
        int count = 0;
        while((read(event_socket, ch, 1 ) != 0) && count < MAX_LINE_LENGTH){
            if(ch[0] != '\n'){
                //printf("%c", ch[0]);
                event_buffer[count] = ch[0];
            }else{
                //printf("%c\n", ch[0]);
                event_buffer[count + 1] = '\0';
                break;
            }
            count++;
        }
        
        /* Ensure buffer is 0-terminated. */
        event_buffer[EVENT_BUFFER_SIZE - 1] = '\0';
        char *event_jString = (char*)event_buffer;
        if(strlen(event_jString))
        {
            struct json_object *event_jobj = json_tokener_parse(event_jString);
            struct json_object *op_obj = json_object_object_get(event_jobj, "Op");
            if(op_obj){
                char operation[strlen(json_object_get_string(op_obj)) + 1];
                sprintf(operation, "%s", json_object_get_string(op_obj));
                if(strcmp(operation, "metrics")){
                    printf("%s\n\n",json_object_to_json_string_ext(event_jobj,JSON_C_TO_STRING_PLAIN));
                }
                if(!strcmp("status", operation)){
                    struct json_object *status_obj = json_object_object_get(event_jobj, "Status");
                    
                    if(status_obj){
                        struct json_object *identities_obj = json_object_object_get(status_obj, "Identities");
                        if(identities_obj){
                            int identities_len = json_object_array_length(identities_obj);
                            if(identities_len){
                                for(int i = 0; i < identities_len; i++){
                                    struct json_object *ident_obj = json_object_array_get_idx(identities_obj, i);
                                    if(ident_obj){
                                        struct json_object *services_obj = json_object_object_get(ident_obj, "Services");
                                        if(services_obj){
                                            enumerate_service(services_obj, "-I");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else if(!strcmp("bulkservice", operation)){
                    struct json_object *services_obj = json_object_object_get(event_jobj, "RemovedServices");
                    if(services_obj){
                        enumerate_service(services_obj, "-D");
                    }
                    services_obj = json_object_object_get(event_jobj, "AddedServices");
                    if(services_obj){
                        enumerate_service(services_obj, "-I");
                    }
                }
                else if(!strcmp("identity", operation)){
                    struct json_object *action_obj = json_object_object_get(event_jobj, "Action");
                    if(action_obj){
                        char action_string[strlen(json_object_get_string(action_obj)) + 1];
                        sprintf(action_string, "%s", json_object_get_string(action_obj));
                        if(!strcmp("updated", action_string)){
                            struct json_object *ident_obj = json_object_object_get(event_jobj, "Id");
                            if(ident_obj){
                                struct json_object *ident_services_obj = json_object_object_get(ident_obj, "Services");
                                if(ident_services_obj){
                                    //enumerate_service(ident_services_obj, "-I");
                                    printf("IGNORED\n");
                                }
                            }
                        }
                    }
                    }

            }
            json_object_put(event_jobj);
        }
        sleep(1);
    }
    return 0;    
}

int main(int argc, char *argv[]) {
    signal(SIGINT, INThandler);
    signal(SIGTERM, INThandler);
    //system("clear");
    system("clear");
    srand(time(0));
    while(true){
        if(transp_fd == -1){
            open_transp_map();
        }
        if(tun_fd == -1){
            open_tun_map();
        }
        run();
        if(event_socket != -1){
            close(event_socket);
        }
        if(event_socket != -1){
            close(ctrl_socket);
        }
        sleep(1);
    }
    return 0;
}
