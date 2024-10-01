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

bool logging = false;
bool monitor = false;
bool all_interface = false;
char *monitor_interface;
char *program_name;
char *log_file_name;
char check_alt[IF_NAMESIZE];
char doc[] = "zfw_monitor -- ebpf firewall monitor tool";
const char *rb_map_path = "/sys/fs/bpf/tc/globals/rb_map";
const char *tproxy_map_path = "/sys/fs/bpf/tc/globals/zt_tproxy_map";
const char *argp_program_version = "0.9.1";
union bpf_attr rb_map;
int rb_fd = -1;

int write_log(char *dest, char *source);
void open_rb_map();
void ebpf_usage();
void close_maps(int code);
void usage(char *message);
void INThandler(int sig);
char *nitoa(uint32_t address);
static int process_events(void *ctx, void *data, size_t len);
char *get_ts(unsigned long long tstamp);
struct ring_buffer *ring_buffer;
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

void close_maps(int code)
{
    if (rb_fd != -1)
    {
        close(rb_fd);
    }
    exit(code);
}

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

char *get_ts(unsigned long long tstamp)
{
    time_t ns;
    time_t s;
    struct timespec spec;
    const char *format = "%b %d %Y %H:%M:%S";
    ;
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

void usage(char *message)
{
    fprintf(stderr, "%s : %s\n", program_name, message);
    fprintf(stderr, "Usage:  zfw_monitor -i <ifname | all> [-W <filename>]\n");
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

// commandline parser options
static struct argp_option options[] = {
  
    {"interface", 'i', "", 0, "Monitor ebpf events for interface", 0},
    {"write-log", 'W', "", 0, "Write to monitor output to /var/log/<log file name> <optional for monitor>", 0},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    program_name = state->name;
    uint32_t idx = 0;
    switch (key)
    {
    case 'i':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "Interface name or all required as arg to -i, --interface: %s\n", arg);
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
    case 'W':
        if (!strlen(arg) || (strchr(arg, '-') != NULL))
        {
            fprintf(stderr, "logfile name -W, --write-log: %s\n", arg);
            fprintf(stderr, "%s --help for more info\n", program_name);
            exit(1);
        }
        logging = true;
        log_file_name = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {options, parse_opt, 0, doc, 0, 0, 0};

int main(int argc, char **argv)
{
    signal(SIGINT, INThandler);
    signal(SIGTERM, INThandler);
    argp_parse(&argp, argc, argv, 0, 0, 0);

    if (monitor)
    {
        open_rb_map();
        ring_buffer = ring_buffer__new(rb_fd, process_events, NULL, NULL);
        while (true)
        {
            ring_buffer__poll(ring_buffer, 1000);
        }
    }else{
        usage("No arguments specified");
    }
}