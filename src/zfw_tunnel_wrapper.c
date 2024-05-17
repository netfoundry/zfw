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

#ifndef BPF_MAX_ENTRIES
#define BPF_MAX_ENTRIES   100 //MAX # PREFIXES
#endif
#define MAX_LINE_LENGTH     32766
#define BUFFER_SIZE         512
#define EVENT_BUFFER_SIZE   32768
#define SERVICE_ID_BYTES    32
#define MAX_TRANSP_ROUTES   256
#define SOCK_NAME "/tmp/ziti-edge-tunnel.sock"
#define EVENT_SOCK_NAME "/tmp/ziti-edge-tunnel-event.sock"
#define DUMP_FILE "/tmp/dumpfile.ziti"
const char *transp_map_path = "/sys/fs/bpf/tc/globals/zet_transp_map";
const char *if_tun_map_path = "/sys/fs/bpf/tc/globals/ifindex_tun_map";
int ctrl_socket, event_socket;
char tunip_string[16]="";
char tunip_mask_string[10]="";
char *tun_ifname;
bool transparent;
union bpf_attr transp_map;
int transp_fd = -1;
union bpf_attr tun_map;
int tun_fd = -1;
typedef unsigned char byte;
void close_maps(int code);
void open_transp_map();
void open_tun_map();
void zfw_update(char *ip, char *mask, char *lowport, char *highport, char *protocol, char *action);
void unbind_route_loopback(struct in_addr *address, unsigned short mask);
void INThandler(int sig);
void map_delete_key(char *service_id);
void route_flush();
int process_bind(json_object *jobj, char *action);
int process_routes(char *service_id);

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
    exit(code);
}

void route_flush()
{
    struct transp_key init_key = {{0}};
    struct transp_key *key = &init_key;
    struct transp_value o_routes;
    struct transp_key current_key;
    transp_map.key = (uint64_t)&key;
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
        //map_delete_key(current_key.service_id);
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


void ebpf_usage()
{
    if (access(transp_map_path, F_OK) != 0)
    {
        printf("Not enough privileges or ebpf not enabled!\n"); 
        printf("Run as \"sudo\" with ingress tc filter [filter -X, --set-tc-filter] set on at least one interface\n");
        close_maps(1);
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
        exit(1);
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

void zfw_update(char *ip, char *mask, char *lowport, char *highport, char *protocol, char *action){
    if (access("/usr/sbin/zfw", F_OK) != 0)
    {
        printf("ebpf not running: Cannot find /usr/sbin/zfw\n");
        return;
    }
    pid_t pid;
    //("%s, %s\n", action ,rules_temp->parmList[3]);
    char *const parmList[15] = {"/usr/sbin/zfw", action, "-c", ip, "-m", mask, "-l",
     lowport, "-h", highport, "-t", "65535", "-p", protocol, NULL};
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

int process_dial(json_object *jobj, char *action){
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
                                                struct json_object *hostname_obj = json_object_object_get(address_obj, "HostName");
                                                printf("\n\nHost intercept: Skipping ebpf\n");       
                                                if(hostname_obj){
                                                    char hostname[strlen(json_object_get_string(address_obj)) + 1];
                                                    sprintf(hostname, "%s", json_object_get_string(hostname_obj));
                                                    if(!strcmp("-I", action)){
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
                                                        
                                                        /*if(strlen(ip) > 7 && strlen(ip) < 16){
                                                            zfw_update(ip, mask, lowport, highport, protocol, action); 
                                                        }*/
                                                    }else{
                                                        printf("Hostname=%s\n", hostname);
                                                        printf("Can't Resolve on Delete Service since resolver is removed\n\n");
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
                                                    zfw_update(ip, mask, lowport, highport, protocol, action);
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
    return 0;
}

void enumerate_service(struct json_object *services_obj, char *action){
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
                        if(tun_fd == -1){
                            open_tun_map();
                        }
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
                                zfw_update(tunip_string, tunip_mask_string, "1", "65535", "tcp", "-I");
                                zfw_update(tunip_string, tunip_mask_string, "1", "65535", "udp", "-I");
                                tun_ifname = o_tunif.ifname;
                            }
                        }
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
                                    enumerate_service(ident_services_obj, "-I");
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
