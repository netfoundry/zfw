# Introduction

--- 
This firewall application utilizes both tc-ebpf and xdp to provide stateful firewalling
for an [OpenZiti](https://docs.openziti.io/) ziti-edge-tunnel installation and is meant as a replacement for ufw for packet
filtering.  It can be used in conjunction with ufw's masquerade feature on a Wan facing interface if
the zfw_outbound_track.o is activated in the egress direction. It can also be used in conjunction with OpenZiti
edge-routers deb package.


## Build

[To build / install zfw from source. Click here!](./BUILD.md)

## Ziti-Edge-Tunnel Deployment 

The program is designed to be deployed as systemd services if deployed via .deb package with
an existing ziti-edge-tunnel(v21.0 +) installation on Ubuntu 22.04(amd64/arm64)service installation. If you don't currently
have ziti-edge-tunnel installed and an operational OpenZiti network built, follow these 
[instructions](https://docs.openziti.io/docs/guides/Local_Gateway/EdgeTunnel).


- Install
  ubuntu 22.04 only (binary deb package)
```
sudo dpkg -i zfw-tunnel_<ver>_<arch>.deb
```
Install from source ubuntu 22.04+ / Debian 12
[build / install zfw from source](./BUILD.md)

## Ziti-Router Deployment

The program is designed to integrated into an existing Openziti ziti-router installation if ziti router has been deployed via ziti_auto_enroll
 [instructions](https://docs.openziti.io/docs/guides/Local_Gateway/EdgeRouter). 

- Install
  ubuntu 22.04 only (binary deb package)
```
sudo dpkg -i zfw-router_<ver>_<arch>.deb
```
Install from source ubuntu 22.04+ / Debian 12
[build / install zfw from source](./BUILD.md)

**The following instructions pertain to both zfw-tunnel and zfw-router. Platform specific functions will be noted explicitly**

Packages files will be installed in the following directories.
```
/etc/systemd/system <systemd service files>  
/usr/sbin <symbolic link to zfw executable>
/opt/openziti/etc : <config files> 
/opt/openziti/bin : <binary executables, executable scripts, binary object files>
/opt/openziti/bin/user/: <user configured rules>
```
Configure:
- Edit interfaces (zfw-tunnel) note: ziti-router will automatically add lanIf: from config.yml
```
sudo cp /opt/openziti/etc/ebpf_config.json.sample /opt/openziti/etc/ebpf_config.json
sudo vi /opt/openziti/etc/ebpf_config.json
```
- Adding interfaces
  Replace ens33 in line with:{"InternalInterfaces":[{"Name":"ens33" ,"OutboundPassThroughTrack": false, "PerInterfaceRules": false}], "ExternalInterfaces":[]}
  Replace with interface that you want to enable for ingress firewalling / openziti interception and 
  optionally ExternalInterfaces if running containers or other subtending devices (Described in more detail
  later in this README.md).
```
i.e. ens33
    {"InternalInterfaces":[{"Name":"ens33"}], "ExternalInterfaces":[]}
Note if you want to add more than one add to list
    {"InternalInterfaces":[{"Name":"ens33"}, {"Name":"ens37"}], "ExternalInterfaces":[]}
```

- Add user configured rules:
```
sudo cp /opt/openziti/bin/user/user_rules.sh.sample /opt/openziti/bin/user/user_rules.sh
sudo vi /opt/openziti/bin/user/user_rules.sh
```   

- Enable services:(zfw-tunnel)
```  
sudo systemctl enable ziti-fw-init.service
sudo systemctl enable ziti-wrapper.service 
sudo systemctl restart ziti-edge-tunnel.service 
```

- Enable services:(zfw-router)
```  
sudo /opt/openziti/bin/start_ebpf_router.py 
```

The Service/Scripts will automatically configure ufw (if enabled) to hand off to ebpf on configured interface(s).  Exception is icmp
which must be manually enabled if it's been disabled in ufw.  

/etc/ufw/before.rules:
```
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
```

Also to allow icmp echos to reach the ip of attached interface you would need to
set icmp to enabled in the /opt/openziti/bin/user/user_rules.sh file i.e. 
```
sudo zfw -e ens33 
sudo systemctl restart ziti-wrapper.service 
```


Verify running: (zfw-tunnel)
```
sudo zfw -L
```
If running:
```
Assuming you are using the default address range for ziti-edge-tunnel should see output like:

target  	proto	origin              destination             mapping:                				                interface list                 
--------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
TUNMODE    	tcp	    0.0.0.0/0           100.64.0.0/10           dpts=1:65535     	TUNMODE redirect:tun0               []
TUNMODE    	udp	    0.0.0.0/0           100.64.0.0/10           dpts=1:65535     	TUNMODE redirect:tun0               []
```

Verify running: (zfw-router)
```
sudo zfw -L
```
If running:
```
Assuming no services configured yet:

target  	proto	origin              	destination                     mapping:                				 interface list                 
--------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
Rule Count: 0
prefix_tuple_count: 0 / 100000

```

If not running:
```
Not enough privileges or ebpf not enabled!
Run as "sudo" with ingress tc filter [filter -X, --set-tc-filter] set on at least one interface

```
Verify running on the configured interface i.e.
```
sudo tc filter show dev ens33 ingress
```   
If running on interface:
```
filter protocol all pref 1 bpf chain 0 
filter protocol all pref 1 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action] direct-action not_in_hw id 26 tag e8986d00fc5c5f5a 
filter protocol all pref 2 bpf chain 0 
filter protocol all pref 2 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/1] direct-action not_in_hw id 31 tag ae5f218d80f4f200 
filter protocol all pref 3 bpf chain 0 
filter protocol all pref 3 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/2] direct-action not_in_hw id 36 tag 751abd4726b3131a 
filter protocol all pref 4 bpf chain 0 
filter protocol all pref 4 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/3] direct-action not_in_hw id 41 tag 63aad9fa64a9e4d2 
filter protocol all pref 5 bpf chain 0 
filter protocol all pref 5 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/4] direct-action not_in_hw id 46 tag 6c63760ceaa339b7 
filter protocol all pref 6 bpf chain 0 
filter protocol all pref 6 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/5] direct-action not_in_hw id 51 tag b7573c4cb901a5da
```    

Services configured via the openziti controller for ingress on the running ziti-edge-tunnel/ziti-router identity will auto populate into
the firewall's inbound rule list.

Also note for zfw-tunnel xdp is enabled on the tunX interface that ziti-edge tunnel is attached to support functions like bi-directional 
ip transparency which would otherwise not be possible without this firewall/wrapper.

You can verify this as follows:
```
sudo ip link show tun0
```
expected output:
```
9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500
    link/none 
    prog/xdp id 249 tag 06c4719358c6de42 jited  <This line will be there if exp forwarder is running>
```

### Outbound External passthrough traffic

The firewall can support subtending devices for two interface scenarios i.e.
external and trusted.

external inet <----> (ens33)[ebpf-router](ens37) <----> trusted client(s)

with zfw_tc_ingress.o applied ingress on ens33 and zfw_tc_oubound_track.o applied egress on ens33 the router will
statefully track outbound udp and tcp connections on ens33 and allow the associated inbound traffic.  While
running in this mode it does not make sense to add ziti tproxy rules and is meant for running as a traditional fw.
As be for you can also create passthrough FW rules (set -t --tproxy-port to 0) which would also make sense in the mode for
specific internet-initiated traffic you might want to allow in.

TCP:
    If the tcp connections close gracefully then the entries will remove upon connection closure. 
    if not, then there is a 60-minute timeout that will remove the in active state if no traffic seen
    in either direction.

UDP:
    State will remain active as long as packets tuples matching SRCIP/SPORT/DSTIP/DPORT are seen in
    either direction within 30 seconds.  If no packets seen in either direction the state will expire.
    If an external packet enters the interface after expiring the entry will be deleted.  if an egress
    packet fined a matching expired state it will return the state to active.

In order to support this per interface rule awareness was added which allows each port range within a prefix
to match a list of connected interfaces.  On a per interface basis you can decide to honor that list or not via
a per-prefix-rules setting in the following manner via the zfw utility


#### Two Interface config with ens33 facing internet and ens37 facing local lan

```
sudo vi /opt/openziti/etc/ebpf_config.json
```
```
{"InternalInterfaces":[{"Name":"ens37","OutboundPassThroughTrack": false, PerInterfaceRules: false}],
 "ExternalInterfaces":[{"Name":"ens33", OutboundPassThroughTrack: true, PerInterfaceRules: true}]}
```
The above JSON sets up ens33 to be an internal interface (No outbound tracking) and ens33 as an external interface
with outbound tracking (Default for External Interface).  It also automatically adds runs the sudo zfw -P ens33 so ens33
(default for ExternalInterfaces) which requires -N to add inbound rules to it and will ignore rules where it is not in the interface list.
Keys "OutboundPassThroughTrack" and "PerInterfaceRules" are shown with their default values, you only need to add them if you
want change the default operation for the interface type.

#### Single Interface config with ens33 facing lan local lan
```
sudo vi /opt/openziti/etc/ebpf_config.json
```
```
{"InternalInterfaces":[{"Name":"ens37","OutboundPassthroughTrack": true, PerInterfaceRules: false}],
 "ExternalInterfaces":[]}
```
**Double check that your json formatting is correct since mistakes could render the firewall inoperable.**

After editing disable zfw and restart ziti-edge-wrapper service
 
(zfw-tunnel)
```
sudo zfw -Q
sudo /opt/openziti/bin/start_ebpf_tunnel.py
sudo systemctl restart ziti-edge-wrapper.service 

```

(zfw-router)
```
sudo zfw -Q
sudo systemctl restart ziti-router.service

```

### Ziti Edge Tunnel Bidirectional Transparency (zfw-tunnel only)

In order to allow internal tunneler connections over ziti the default operation has been set to not delete any tunX link routes. This will disable the ability to support transparency on some architectures i.e. arm64.  There is now an environmental variable ```TRANSPARENT_MODE='true'``` that can be set in the ```/opt/openziti/etc/ziti-edge-tunnel.env``` file to enable deletion of tunX routes if bi-directional transparency is required at the expense of disabling internal tunneler interception.

### Supporting Internal Containers / VMs

Traffic from containers like docker appears just like passthrough traffic to ZFW so you configure it the same as described above for 
normal external pass-through traffic.

### Upgrading zfw-tunnel
```
sudo systemctl stop ziti-wrapper.service
sudo dpkg -i <zfw-tunnel_<ver>_<arch>.deb
```
After updating reboot the system 
```
sudo reboot
```

### Upgrading zfw-router
```
sudo dpkg -i <zfw-router_<ver>_<arch>.deb
```
After updating reboot the system 
```
sudo reboot
```

## Ebpf Map User Space Management
---
### User space manual configuration
ziti-edge-tunnel/ziti-router will automatically populate rules for configured ziti services so the following is if
you want to configure additional rules outside of the automated ones. zfw-tunnel will also auto-populate /opt/openziti/bin/user/user_rules.sh
with listening ports in the config.yml.

**Note the ```zfw-router_<version>_<arch>.deb``` will install an un-enabled service ```fw-init.service```. If you install the zfw-router package without an OpenZiti ziti-router installation and enable this service it will start the ebpf fw after reboot and load the commands from /opt/openziti/bin/user/user_rules.sh.  If you later decide to install ziti-router this service should be disabled and you should run ```/opt/openziti/bin/start_ebpf_router.py``` you will also need to manually copy the /opt/openziti/etc/ebpf_config.json.sample to ebpf_config.json and edit interface name**

**(All commands listed in this section need to be put in /opt/openziti/bin/user/user_rules.shin order to survive reboot)**

### ssh default operation
By default ssh is enabled to pass through to the ip address of the attached interface from any source.
If secondary addresses exist on the interface this will only work for the first 10.  After that you would need
to add manual entries via ```zfw -I```. 

The following command will disable default ssh action to pass to the IP addresses of the local interface and will
fall through to rule check instead where a more specific rule could be applied.  This is a per
interface setting and can be set for all interfaces except loopback.  This would need to be put in
 /opt/openziti/bin/user/user_rules.sh to survive reboot.

- Disable
```
sudo zfw -x <ens33 | all>
```

- Enable
```
sudo zfw -x <ens33 | all> -d
```

### vrrp passthrough
- Enable
```
sudo zfw --vrrp-enable <ens33 | all>
```

- Disable
``` 
sudo zfw --vrrp-enable <ens33 | all> -d
```


### Inserting / Deleting rules
    
The -t, --tproxy-port is has a dual purpose one it to signify the tproxy port used by openziti routers in tproxy mode and the other is to identify either local passthrough with value of 0 and the other is tunnel redirect mode with value of 65535.

- Example Insert
If you disable default ssh handling with a device interface ip of 172.16.240.1 and you want to insert a user rule with source 
filtering that only allows source ip 10.1.1.1/32 to reach 172.16.240.1:22. 

Particularly notice -t 0 which means that matched packets will pass to the local OS stack and are not redirected to tproxy ports or tunnel interface.
```
sudo zfw -I -c 172.16.240.1 -m 32 -o 10.1.1.1 -n 32  -p tcp -l 22 -h 22 -t 0
```
    
- Example Delete
    
```
sudo zfw -D -c 172.16.240.1 -m 32 -o 10.1.1.1 -n 32  -p tcp -l 22
```

- Example: Remove all rule entries from FW

```
sudo zfw -F
```

### Debugging

Example: Monitor ebpf trace messages

```
sudo zfw -M <ifname>|all

```
  
```
Jul 26 2023 01:42:24.108913490 : ens33 : TCP :172.16.240.139:51166[0:c:29:6a:d1:61] > 192.168.1.1:5201[0:c:29:bb:24:a1] redirect ---> ziti0
Jul 26 2023 01:42:24.108964534 : ziti0 : TCP :192.168.1.1:0[0:c:29:bb:24:a1] > 172.16.240.139:0[0:c:29:6a:d1:61] redirect ---> ens33
Jul 26 2023 01:42:24.109011595 : ziti0 : TCP :192.168.1.1:0[0:c:29:bb:24:a1] > 172.16.240.139:0[0:c:29:6a:d1:61] redirect ---> ens33
Jul 26 2023 01:42:24.109036999 : ziti0 : TCP :192.168.1.1:0[0:c:29:bb:24:a1] > 172.16.240.139:0[0:c:29:6a:d1:61] redirect ---> ens33
Jul 26 2023 01:42:24.108913490 : ens33 : TCP :172.16.240.139:51166[0:c:29:6a:d1:61] > 192.168.1.1:5201[0:c:29:bb:24:a1] redirect ---> ziti0
Jul 26 2023 01:42:24.108964534 : ziti0 : TCP :192.168.1.1:0[0:c:29:bb:24:a1] > 172.16.240.139:0[0:c:29:6a:d1:61] redirect ---> ens33
Jul 26 2023 01:42:24.109011595 : ziti0 : TCP :192.168.1.1:0[0:c:29:bb:24:a1] > 172.16.240.139:0[0:c:29:6a:d1:61] redirect ---> ens33
```

Example: List all rules in Firewall

```
sudo zfw -L
```
```
target     proto    origin              destination               mapping:                                                   interface list
------     -----    ---------------     ------------------        --------------------------------------------------------- ----------------
TPROXY     tcp      0.0.0.0/0           10.0.0.16/28              dpts=22:22                TPROXY redirect 127.0.0.1:33381  [ens33,lo]
TPROXY     tcp      0.0.0.0/0           10.0.0.16/28              dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
TPROXY     udp      0.0.0.0/0           172.20.1.0/24             dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
TPROXY     tcp      0.0.0.0/0           172.16.1.0/24             dpts=22:22                TPROXY redirect 127.0.0.1:33381  []
TPROXY     tcp      0.0.0.0/0           172.16.1.0/24             dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
PASSTHRU   udp      0.0.0.0/0           192.168.3.0/24            dpts=5:7                  PASSTHRU to 192.168.3.0/24       []
PASSTHRU   udp      10.1.1.1/32         192.168.100.100/32        dpts=50000:60000          PASSTHRU to 192.168.100.100/32   []
PASSTHRU   tcp      10.230.40.1/32      192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
TPROXY     udp      0.0.0.0/0           192.168.0.3/32            dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
PASSTHRU   tcp      0.0.0.0/0           192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
TUNMODE    udp	    0.0.0.0/0           100.64.0.0/10             dpts=1:65535     	        TUNMODE redirect:tun0            []
```
    
- Example: List rules in firewall for a given prefix and protocol.  If source specific you must include the o 
  <origin address or prefix> -n <origin prefix len>

```  
sudo zfw -L -c 192.168.100.100 -m 32 -p udp
```
```  
target     proto    origin           destination              mapping:                                                  interface list
------     -----    --------         ------------------       --------------------------------------------------------- ------------------    
PASSTHRU   udp      0.0.0.0/0        192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32     []
```

- Example: List rules in firewall for a given prefix
Usage: zfw -L -c <ip dest address or prefix> -m <prefix len> -p <protocol>
```
sudo zfw -L -c 192.168.100.100 -m 32
```
```
target     proto    origin           destination              mapping:                                                  interface list
------     -----    --------         ------------------       --------------------------------------------------------- -------------------
PASSTHRU   udp      0.0.0.0/0        192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32     []
PASSTHRU   tcp      0.0.0.0/0        192.168.100.100/32       dpts=60000:65535	      PASSTHRU to 192.168.100.100/32     []
```
- Example: List all interface settings

```
sudo zfw -L -E
```
```
lo: 1
--------------------------
icmp echo               :1
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :0
tc egress filter        :0
tun mode intercept      :0
vrrp enable             :0
--------------------------

ens33: 2
--------------------------
icmp echo               :0
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :1
tc egress filter        :1
tun mode intercept      :1
vrrp enable             :1
--------------------------

ens37: 3
--------------------------
icmp echo               :0
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :0
tc egress filter        :0
tun mode intercept      :0
vrrp enable             :0
--------------------------

tun0: 18
--------------------------
verbose                 :0
cidr                    :100.64.0.0
mask                    :10
--------------------------
```

- Example Detaching bpf from interface:

```
sudo zfw --set-tc-filter <interface name>  --direction <ingress | egress> --disable
```

Example: Remove all tc-ebpf on router

```
sudo zfw --disable-ebpf
```
```
tc parent del : lo
tc parent del : ens33
tc parent del : ens37
removing /sys/fs/bpf/tc/globals/zt_tproxy_map
removing /sys/fs/bpf/tc/globals/diag_map
removing /sys/fs/bpf/tc/globals/ifindex_ip_map
removing /sys/fs/bpf/tc/globals/tuple_count_map
removing /sys/fs/bpf/tc/globals/prog_map
removing /sys/fs/bpf/tc/globals/udp_map
removing /sys/fs/bpf/tc//globals/matched_map
removing /sys/fs/bpf/tc/globals/tcp_map
```


