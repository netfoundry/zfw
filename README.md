# Introduction

--- 
This firewall application utilizes both tc-ebpf and xdp to provide stateful firewalling
for an [OpenZiti](https://docs.openziti.io/) ziti-edge-tunnel installation and is meant as a replacement for packet
filtering.  It can also be used in conjunction with OpenZiti edge-routers or as a standalone fw. It now has built in
EBPF based masquerade capability for both IPv4/IPv6. 

  
## Build

[To build / install zfw from source. Click here!](./BUILD.md)

## Standalone FW Deployment

 Install
  binary deb or rpm package (refer to workflow for detail pkg contents)

Debian 12/ Ubuntu 22.04+
```
sudo dpkg -i zfw-router_<ver>_<arch>.deb
```

RedHat 9.4
```
sudo yum install zfw-router-<ver>.<arch>.rpm
```
Note if running firewalld you will need to at a minimum set each interface you enable tc ebpf on to the trusted zone or equivalent. e.g. ```firewall-cmd --permanent --zone=trusted --add-interface=ens33``` or firewalld will drop traffic before it reaches the zfw filters.

Install from source ubuntu 22.04+ / Debian 12+ / Redhat 9.4
[build / install zfw from source](./BUILD.md)

After installing:
```
sudo su - 
cd /opt/openziti/etc
cp ebpf_config.json.sample ebpf_config.json
```
Follow the README.md section ```Two Interface config with ens33 facing internet and ens37 facing local lan``` on how to edit ebpf_config.json based on your interface configuration.
if you only have one interface then set it as InternalInterfaces and leave ExternalInterfaces as an empty list [].  With a single interface if you want to block outbound traffic you will need to add egress rules as described in the section ```Outbound Filtering```.

example ebpf_config.json:
```
{"InternalInterfaces":[{"Name":"eth0"}],
 "ExternalInterfaces":[{"Name":"eth1"}]}
```

To start the firewall just run 

 sudo /opt/openziti/bin/start_ebpf_router.py

you will see output like 

```
Unable to retrieve LanIf!
ziti-router not installed, skipping ebpf router configuration!
Attempting to add ebpf ingress to:  eth0
Attempting to add ebpf egress to:  eth1
Ebpf not running no  maps to clear
tc parent add : eth0
Set tc filter enable to 1 for ingress on eth0
Attached /opt/openziti/bin/zfw_tc_ingress.o to eth0
Skipping adding existing rule
Skipping adding existing rule (v6)
tc parent add : eth1
Set tc filter enable to 1 for ingress on eth1
Attached /opt/openziti/bin/zfw_tc_ingress.o to eth1
Rules updated
Rules updated (v6)
Set per_interface rule aware to 1 for eth1
Error: Exclusivity flag on, cannot modify.
tc parent already exists : eth1
Set tc filter enable to 1 for egress on eth1
Attached /opt/openziti/bin/zfw_tc_outbound_track.o to eth1
```

the important lines from above to verify its worked:
```
Set tc filter enable to 1 for ingress on eth0
Attached /opt/openziti/bin/zfw_tc_ingress.o to eth0

Set tc filter enable to 1 for ingress on eth1
Attached /opt/openziti/bin/zfw_tc_ingress.o to eth1

Set tc filter enable to 1 for egress on eth1
Attached /opt/openziti/bin/zfw_tc_outbound_track.o to eth1
```

In order to ensure the FW starts on boot you need to enable the fw-init.service.
```
sudo systemctl enable fw-init.service
```

Since you will not be using ziti to populate rules all your rules would be with respect to the local OS then any rules will need to be set 

to drop to the host system as mentioned in the README this is done by setting the ```tproxy-port to 0``` in your rules. i.e.

``` 
sudo /usr/sbin/zfw -I -c 192.168.1.108 -m 32 -l 8000 -h 8000 -t 0 -p tcp
```

Note:
The ExternalInterface is set to what is called ```per interface rules``` which means it only follows
rules where its name is set in the rule, whereas the InternalInterface follows all rules by default. i.e. to allow the above rule in on the External interface you need
```-N, --interface <ifname>``` in the rule i.e.
```
sudo /usr/sbin/zfw -I -c 192.168.1.108 -m 32 -l 8000 -h 8000 -t 0 -p tcp -N eth1
```
## Ziti-Edge-Tunnel Deployment 

The program is designed to be deployed as systemd services if deployed via .deb package with
an existing ziti-edge-tunnel(v22.5 +) installation on Ubuntu 22.04(amd64/arm64)service installation. If you don't currently
have ziti-edge-tunnel installed and an operational OpenZiti network built, follow these 
[instructions](https://docs.openziti.io/docs/guides/Local_Gateway/EdgeTunnel).


- Install
  binary deb or rpm package (refer to workflow for detail pkg contents)

Debian 12/ Ubuntu 22.04+
```
sudo dpkg -i zfw-tunnel_<ver>_<arch>.deb
```

RedHat 9.4
```
sudo yum install zfw-tunnel-<ver>.<arch>.rpm
```
Note if running firewalld you will need to at a minimum set each interface you enable tc ebpf on to the trusted zone or equivalent. e.g. ```firewall-cmd --permanent --zone=trusted --add-interface=ens33``` or firewalld will drop traffic before it reaches the zfw filters.

Install from source ubuntu 22.04+ / Debian 12+ / Redhat 9.4
[build / install zfw from source](./BUILD.md)

## Ziti-Router Deployment

The program is designed to integrated into an existing Openziti ziti-router installation if ziti router has been deployed via ziti_auto_enroll
 [instructions](https://docs.openziti.io/docs/guides/Local_Gateway/EdgeRouter). 

- Install
  binary deb package (refer to workflow for detail pkg contents)
```
sudo dpkg -i zfw-router_<ver>_<arch>.deb
```
Install from source ubuntu 22.04+ / Debian 12 / Redhat 9.4
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
- Edit interfaces (zfw-tunnel) note: zfw for ziti-router will automatically add lanIf: from config.yml when
 ```/opt/openziti/bin/start_ebpf_router.py``` is run the first time and OpenZiti router is installed and
 configured.
```
sudo cp /opt/openziti/etc/ebpf_config.json.sample /opt/openziti/etc/ebpf_config.json
sudo vi /opt/openziti/etc/ebpf_config.json
```
- Adding interfaces
  Replace ens33 in line with:{"InternalInterfaces":[{"Name":"ens33"}], "ExternalInterfaces":[]}
  Replace with interface that you want to enable for ingress firewalling / openziti interception and 
  optionally ExternalInterfaces if you want per interface rules -N <ifname> with -I.
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

Verify running: (zfw-router)
```
sudo zfw -L
```
If running:
```
Assuming no services configured yet:

type   service id              proto    origin              destination               mapping:                                                   interface list
------ ----------------------  -----    ---------------     ------------------        --------------------------------------------------------- ----------------
Rule Count: 0 / 250000
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
If running ingress filters on interface:
```
filter protocol all pref 1 bpf chain 0 
filter protocol all pref 1 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action] direct-action not_in_hw id 18287 tag 7924b3b7066e6c20 jited 
filter protocol all pref 2 bpf chain 0 
filter protocol all pref 2 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/1] direct-action not_in_hw id 18293 tag aa2d601900a4bb11 jited 
filter protocol all pref 3 bpf chain 0 
filter protocol all pref 3 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/2] direct-action not_in_hw id 18299 tag b2a4d46c249aec22 jited 
filter protocol all pref 4 bpf chain 0 
filter protocol all pref 4 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/3] direct-action not_in_hw id 18305 tag ed0a156d6e90d4ab jited 
filter protocol all pref 5 bpf chain 0 
filter protocol all pref 5 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/4] direct-action not_in_hw id 18311 tag 7b65254c0f4ce589 jited 
filter protocol all pref 6 bpf chain 0 
filter protocol all pref 6 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/5] direct-action not_in_hw id 18317 tag f4d6609cc4eb2da3 jited 
filter protocol all pref 7 bpf chain 0 
filter protocol all pref 7 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action/6] direct-action not_in_hw id 18323 tag a3c047d2327de858 jited 
```    

Verify running egress filters on the configured interface i.e.
```
sudo tc filter show dev ens33 egress
```   
If running egress on interface:
```
filter protocol all pref 1 bpf chain 0 
filter protocol all pref 1 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action] direct-action not_in_hw id 18329 tag 4d66fa6f69670aad jited 
filter protocol all pref 2 bpf chain 0 
filter protocol all pref 2 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action/1] direct-action not_in_hw id 18335 tag e55132e45dc4a711 jited 
filter protocol all pref 3 bpf chain 0 
filter protocol all pref 3 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action/2] direct-action not_in_hw id 18341 tag 9ec5f3c00f9ef356 jited 
filter protocol all pref 4 bpf chain 0 
filter protocol all pref 4 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action/3] direct-action not_in_hw id 18347 tag 9af99a7218e0be3d jited 
filter protocol all pref 5 bpf chain 0 
filter protocol all pref 5 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action/4] direct-action not_in_hw id 18353 tag d1a536ae48efe657 jited 
filter protocol all pref 6 bpf chain 0 
filter protocol all pref 6 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action/5] direct-action not_in_hw id 18359 tag 7da52c707c308700 jited 
filter protocol all pref 7 bpf chain 0 
filter protocol all pref 7 bpf chain 0 handle 0x1 zfw_tc_outbound_track.o:[action/6] direct-action not_in_hw id 18365 tag bd21505cf7e27536 jited 
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

In order to enable outbound tracking you need to add an egress tc filter to the interface where traffic will be egressing.
This is performaed with the following cli command: ```sudo zfw -X <ifname> -O <egress tc object file> -z, --direction egress```.
e.g.
```
sudo zfw -X ens33 -O /opt/openziti/bin/zfw_tc_outbound_track.o --direction egress
```


#### Two Interface config with ens33 facing internet and ens37 facing local lan

```
sudo vi /opt/openziti/etc/ebpf_config.json
```
```
{"InternalInterfaces":[{"Name":"ens37","OutboundPassThroughTrack": true, PerInterfaceRules: false}],
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

### Ziti Edge Tunnel L2tp Tunnel over ziti (zfw-tunnel only)

To support L2tpV3 over ziti with l2tp tunnel terminating on the same vm as ziti-edge-tunnel.
In order to support this a unique ZITI_DNS_IP_RANGE must be set on both vms terminating l2tpv3.  The
source of the L2tpv3 tunnel on each zet host needs to be set to the ip address assigned to the ziti0
interface which will be the first host address in the ZITI_DNS_IP_RANGE. In addition you will need to enable
ebpf outbound tracking on the loopback interface.  This can be setup vi /opt/openziti/etc/ebpf_config.json i.e.
```
{"InternalInterfaces":[{"Name":"eth0"}, {"Name":"lo", "OutboundPassThroughTrack": true}],"ExternalInterfaces":[]}
```

### Ziti Edge Tunnel Bidirectional Transparency (zfw-tunnel only)

In order to allow internal tunneler connections over ziti the default operation has been set to not delete any tunX link routes. This will disable the ability to support transparency.  There is an environmental variable ```TRANSPARENT_MODE='true'``` that can be set in the ```/opt/openziti/etc/ziti-edge-tunnel.env``` file to enable deletion of tunX routes if bi-directional transparency is required at the expense of disabling internal tunneler interception.

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
sudo dpkg -i zfw-router_<ver>_<arch>.deb
```
After updating reboot the system 
```
sudo reboot
```

### URL based services
  Summary rules below will no longer be inserted and will be replaced with explicit host rules:
  ```
  (removed)
  accept 0000000000000000000000	tcp	0.0.0.0/0           	100.64.0.0/10                   dpts=1:65535     	TUNMODE redirect:ziti0          []
  accept 0000000000000000000000	tcp	0.0.0.0/0           	100.64.0.0/10                   dpts=1:65535     	TUNMODE redirect:ziti0          []
  
  (example new dynamic rule)
  5XzC8mf1RrFO2vmfHGG5GL	tcp	0.0.0.0/0           	100.64.0.5/32                   dpts=5201:5201   	TUNMODE redirect:ziti0          []
  ```
  A rule will also be entered for the ziti resolver ip upon the first configured hostname based service i.e.
  ```
  accept 0000000000000000000000	udp	0.0.0.0/0           	100.64.0.2/32                   dpts=53:53       	TUNMODE redirect:ziti0          []
  
  This entry will remain unless ziti-edge-tunnel is stopped and will again be reentered upon reading the first hostname based service entry
  ```

  If wild card hostnames are used i.e. *.test.ziti then zfw will enter summary rules for the entire ziti DNS range for the specific ports defined for the service i.e.
  ```
  accept 0000000000000000000000	tcp	0.0.0.0/0           	100.64.0.0/10                   dpts=5201:5201   	TUNMODE redirect:ziti0          []
  accept 0000000000000000000000	udp	0.0.0.0/0           	100.64.0.0/10                   dpts=5201:5201   	TUNMODE redirect:ziti0          []

  IMPORTANT: These entries will remain until as long as there is at least one wildcard in a service using the port/port range via cli and will not be removed by ziti service deletion. It is recommended to use single ports with wild card since the low port acts as a key and thus the first service that gets entered will dictate the range for the ports and there is only one prefix. 
  ``` 

## Ebpf Map User Space Management
---
### User space manual configuration
ziti-edge-tunnel/ziti-router will automatically populate rules for configured ziti services so the following is if
you want to configure additional rules outside of the automated ones. zfw-tunnel will also auto-populate /opt/openziti/bin/user/user_rules.sh
with listening ports in the config.yml. 

**(All commands listed in this section need to be put in /opt/openziti/bin/user/user_rules.sh in order to survive reboot)**

### ssh default operation
By default ssh is enabled to pass through to the ip address of the attached interface from any source.
If secondary addresses exist on the interface this will only work for the first 10.  After that you would need
to add manual entries via ```zfw -I```.  

NOTE: **For environments where the IP will change zfw should detect the change with in 1 minute. It is highly recommended that a manual ssh rule is entered in /opt/openziti/bin/user_rules.sh with an entry for the entire subnet as backup unless you have either a manual static address or reserved DHCP address. e.g if subnet is 192.168.1.0/24.** 
```
#!/bin/bash
sudo /opt/openziti/bin/zfw -I -c 192.168.1.0 -m 24 -l 22 -h 22 -t 0 -p tcp
```
  
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

### Non tuple passthrough
**Caution:**
This allows all non udp/tcp traffic to passthrough to the OS and should only be enabled if you are using zfw for tcp/udp redirection and are
using **another firewall** to filter traffic. This setting will also disable icmp masquerade if enabled. **THIS SETTING IS DISABLED BY DEFAULT**.
- Enable
```
sudo zfw -q, --pass-non-tuple <ifname | all>
```

- Disable 
```
sudo zfw -q, --pass-non-tuple <ifname | all> -d
```

### Inserting / Deleting Ingress rules
    
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

- Example: Remove all rule entries from FW both ingress and egress

```
sudo zfw -F
```

- Example: Remove all ingress rules from FW

```
sudo zfw -F -z ingress
```

- Example: Remove all egress rules from FW

```
sudo zfw -F -z egress
```

### Debugging

Example: Monitor ebpf trace messages

```
sudo zfw -M <ifname>|all

```

### Load rules from /opt/openziti/bin/user/user_rules.sh

```sudo zfw -A, --add-user-rules```

### Enable both TC ingress and Egress filters on an interface

```sudo zfw -H, --init-tc <ifname | all>```

### Native EBPF based IPv4 and IPv6 Masquerade support

zfw can now provide native IPv4/IPv6 masquerade operation for outbound pass through connections which can be enabled on a WAN facing interface:

```sudo zfw -k, --masquerade <ifname>```

This function requires that both ingress and egress TC filters are enabled on outbound interface. For IPv4 this is now using Dynamic PAT and IPv6 is using 
static PAT.  Note: When running on later kernels i.e. 6+ some older network hardware may not work with ebpf Dynamic PAT. We have also seen some incompatibility with 2.5Gb interfaces on 5.x+ kernels. 

In release v0.8.19 masquerade session gc was added to /etc/cron.d/zfw_refresh via ```/opt/openziti/bin/zfw -L -G > /dev/null``` and runs once per minute.  Stale udp sessions will be 
removed if over 30s and stale tcp sessions will be removed if over 3600 seconds(1hr). 

### Explicit Deny Rules
This feature adds the ability to enter explicit deny rules by appending ```-d, --disable``` to the ```-I, --insert rule``` to either ingress or egress rules.  Rule precedence is based on longest match prefix.  If the prefix is the same then the precedence follows the order entry of the rules, which when listed will go from top to bottom for ports with in the same prefix e.g.  

If you wanted to allow all tcp 443 traffic outbound except to 10.1.0.0/16 you would enter the following egress rules:

```
sudo zfw -I -c 10.1.0.0 -m 16 -l 443 -h 443 -t 0 -p tcp -z egress -d
sudo zfw -I -c 0.0.0.0 -m 0 -l 443 -h 443 -t 0 -p tcp -z egress
``` 
Listing the above with ```sudo zfw -L -z egress``` you would see:
```
EGRESS FILTERS:
type   service id            	proto	origin              	destination                     mapping:                				interface list                 
------ ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
accept 0000000000000000000000	tcp	0.0.0.0/0           	0.0.0.0/0                       dpts=443:443     	PASSTHRU to 0.0.0.0/0           []
deny   0000000000000000000000	tcp	0.0.0.0/0           	10.1.0.0/16                     dpts=443:443     	PASSTHRU to 10.1.0.0/16         []
Rule Count: 2 / 250000
prefix_tuple_count: 2 / 100000
```

The following illustrates the precedence with rules matching the same prefix:

Assume you want to block port 22 to address 172.16.240.137 and enter rules the following rules:
```
sudo zfw -I -c 172.16.240.139 -m 32 -l 1 -h 65535 -t 0 -p tcp -z egress
sudo zfw -I -c 172.16.240.139 -m 32 -l 22 -h 22 -t 0 -p tcp -z egress -d
```
```
sudo zfw -L -z egress
EGRESS FILTERS:
type   service id            	proto	origin              	destination                     mapping:                				interface list                 
------ ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
accept 0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=1:65535     	PASSTHRU to 172.16.240.139/32   []
deny   0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=22:22       	PASSTHRU to 172.16.240.139/32   []
Rule Count: 2 / 250000
```
The rule listing shows the accept port range 1-65535 listed first and then the deny port 22 after.  This would result in port 22 being allowed outbound because traffic would match the accept rule and never reach the deny rule.

The correct rule order entry would be:
```
sudo zfw -I -c 172.16.240.139 -m 32 -l 22 -h 22 -t 0 -p tcp -z egress -d
sudo zfw -I -c 172.16.240.139 -m 32 -l 1 -h 65535 -t 0 -p tcp -z egress
```
```
sudo zfw -L -z egress
EGRESS FILTERS:
type   service id            	proto	origin              	destination                     mapping:                				interface list                 
------ ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
deny   0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=22:22       	PASSTHRU to 172.16.240.139/32   []
accept 0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=1:65535     	PASSTHRU to 172.16.240.139/32   []
Rule Count: 2 / 250000
prefix_tuple_count: 1 / 100000
```
This will result in traffic to port 22 matching the first rule and correctly being dropped as intended.

### DNP3 Function Code filtering

- Added support for dnp3 slave function code filtering.  If ot filtering is enabled on the interface inbound tcp packets with source port of 20000 and   
  have DNP3 datalink start bytes: 0x0564 and contain application layer header will be droppoed unless the function code value is in the allowed fcode list and the direction bit is unset.

  Enable/Disable at interface level with ```sudo zfw --ot-filtering <iface> [-d]```

  Allowed codes added via ```sudo zfw --dnp3-fcode-add <decimal fcode>```

  List allowed fcodes ```sudo zfw -L --list-dnp3-fcodes```
  ```
  dnp3 function code allow list
  -------------------------------
  129 (0x81)
  -------------------------------
  ```
fcode count: 1
### Outbound filtering 
- This new feature is currently meant to be used in stand alone FW mode (No OpenZiti). It can be run with OpenZiti
  on intercepted inbound connections but locally hosted services will require manually entered egress rules. 
  See note in section ```User space manual configuration``` which briefly describes installing
  zfw without OpenZiti.

  The feature allows for both IPv4 and IPv6 ingress/egress filters on a single external interface. i.e.
  This mode maintains state for outbound traffic associated with traffic allowed by ingress filters so 
  there is no need to statically configure high port ranges for return traffic.  The assumption is
  If you enable inbound ports you want to allow the stateful reply packets for udp and tcp.

An egress filter must be attached to the interface , ```-b, --outbound-filter <ifname>``` needs to be set ,and at least one interface needs to have had an ingress filter applied.

From cli:

```
sudo zfw --init-tc ens33
sudo /opt/openziti/bin/zfw --outbound-filter ens33
```

The above should result in all outbound traffic except for arp and icmp to be dropped on ens33 (icmp echo-reply
will also be dropped unless  ```sudo zfw -e ens33 is set```). ssh return traffic will also be allowed outbound
unless ```ssh -x ens33 is set```.

If per interface rules is not false then the egress rules would
need explicit -N <interface name added> for each rule in the same manner as ingress rules. 

i.e. set ```/opt/openziti/etc/ebpf_config.json``` as below changing interface name only

  ```{"InternalInterfaces":[], "ExternalInterfaces":[{"Name":"ens33", "PerInterfaceRules": false}]}```

  or equivalent InternalInterfaces config:

```{"InternalInterfaces":[{"Name":"ens33"}],"ExternalInterfaces":[]}```

Then in executable script file ```/opt/openziti/bin/user/user_rules.sh```
```
#!/bin/bash

# enable outbound filtering (Can be set before or after egress rule entry)
# If set before DNS rules some systems command response might be slow till 
# a DNS egress rule is entered

sudo /opt/openziti/bin/zfw --outbound-filter ens33

#example outbound rules set by adding -z, --direction egress
#ipv4
sudo /opt/openziti/bin/zfw -I -c 0.0.0.0 -m 0 -l 53 -h 53 -t 0 -p udp --direction egress
sudo /opt/openziti/bin/zfw -I -c 172.16.240.139 -m 32 -l 5201 -h 5201 -t 0 -p tcp -z egress
sudo /opt/openziti/bin/zfw -I -c 172.16.240.139 -m 32 -l 5201 -h 5201 -t 0 -p udp --direction egress

#ipv6
sudo /opt/openziti/bin/zfw -6 ens33 #enables ipv6
sudo /opt/openziti/bin/zfw -I -c 2001:db8::2 -m 32 -l 5201 -h 5201 -t 0 -p tcp -z egress
sudo /opt/openziti/bin/zfw -I -c 2001:db8::2 -m 32 -l 5201 -h 5201 -t 0 -p udp --direction egress

#inbound rules
sudo /opt/openziti/bin/zfw -I -c 172.16.240.0 -m 24 -l 22 -h 22 -t 0 -p tcp```
```
- To view all IPv4 egress rules: ```sudo zfw -L -z egress```

```
EGRESS FILTERS:
type   service id            	proto	origin              	destination                     mapping:                				        interface list                 
------ ----------------------	-----	-----------------	------------------		-------------------------------------------------------	    -----------------
accept 0000000000000000000000	udp	0.0.0.0/0           	172.16.240.139/32               dpts=5201:5201   	PASSTHRU to 172.16.240.139/32   []
accept 0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=5201:5201   	PASSTHRU to 172.16.240.139/32   []

```
- To view all IPv6 egress rules: ```sudo zfw -L -6 all -z egress```

```
EGRESS FILTERS:
type   service id             proto origin                                     destination                                  mapping:                    interface list
------ ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------
accept 0000000000000000000000|tcp  |::/0                                      |2001:db8::2/32                             | dpts=5201:5201   PASSTHRU | []
accept 0000000000000000000000|udp  |::/0                                      |2001:db8::2/32                             | dpts=5201:5201   PASSTHRU | []
```
- to view egress rules for a single IPv4 CIDR ```sudo zfw -L -c 172.16.240.139 -m 32 -z egress```
``` 
EGRESS FILTERS:
type   service id            	proto	origin              destination             mapping:                				                    interface list                 
------ ----------------------	-----	-----------------	------------------		-------------------------------------------------------	    -----------------
accept 0000000000000000000000	udp	0.0.0.0/0               172.16.240.139/32               dpts=5201:5201   	PASSTHRU to 172.16.240.139/32       []
Rule Count: 1
type   service id            	proto	origin              destination             mapping:                				                    interface list                 
------ ----------------------	-----	-----------------	------------------		-------------------------------------------------------	    -----------------
accept 0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=5201:5201   	PASSTHRU to 172.16.240.139/32       []
accept 0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=22:22       	PASSTHRU to 172.16.240.139/32       []
Rule Count: 2
```
  
- to view tcp egress rules for a single IPv6 CIDR ```$sudo zfw -L -c 2001:db8:: -m 64 -z egress -p tcp```

```
EGRESS FILTERS:
type   service id             proto origin                                     destination                                  mapping:                    interface list
------ ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------
accept|0000000000000000000000|tcp  |::/0                                      |2001:db8::/64                              | dpts=5201:5201   PASSTHRU | []
Rule Count: 1
```

### Support for ipv6
- *Enabled via ```sudo zfw -6 <ifname | all>``` 
   Note: Router discovery / DHCPv6 are always enabled even if ipv6 is disabled in order to ensure the ifindex_ip6_map gets populated.
- Supports ipv6 neighbor discovery (redirects not supported)
- *Supports inbound ipv6 echo (disabled by default can be enabled via zfw -e)/ echo reply 
- *Supports inbound ssh (Can be disabled via ```sudo zfw -x <ifname | all>```) (Care should be taken as this affects IPv4 as well)
- Supports outbound stateful host connections (Inbound only if outbound initiated)
- Supports outbound passthrough tracking.  Sessions initiated from non-ebpf enabled and ebpf enabled  internal interfaces out 
  through interface(s) defined as ExternalInterface (requires -N <ifname> with -I unless "PerInterfaceRules": false) or InternalInterface in /opt/openziti/etc/ebpf_config.json
  or manually applied with sudo ```zfw -X <ifname> -O /opt/openziti/zfw_outbound_track.o -z egress``` 
  will allow stateful udp and tcp session traffic back in.
- Support for inbound IPv6 filter destination rules. Currently only destination filtering is allowed.
  e.g. 
  ```
    sudo zfw -I -c 2001:db9:: -m 64 -l 443 -h 443 -t 0 -p tcp
  ```
- All IPv6 ingress Rules can be listed with the following command:
  ```
    sudo zfw -L -6 all
  ```
- individual IPv6 ingress rules can be listed with 
  ```
  sudo zfw -L -c <IPv6 CIDR> -m <CIDR LEN 0 - 128> 
  ```
- IPv6 rules can be individually deleted or flushed 
  e.g.
```
sudo zfw -F
sudo zfw -D -c 2001:db9:: -m 64 -l 443 -h 443 -p tcp
```
- Monitor connection state via ```sudo zfw -M, --monitor <ifname | all>```  optionally ```sudo zfw -v verbose <ifname | all> ```
  alternatively you can use the dedicated monitor binary ```sudo zfw_monitor -i <ifname | all> ``` 
*These setting need to be in /opt/openziti/bin/user_rules.sh to be persistent across reboots.

Note: Some of the above IPv6 features are not fully supported with OpenZiti yet. Features like
tproxy and ziti0 forwarding will not work completely till updates are released in OpenZiti.
OpenZiti routers do support IPv6 fabric connections using DNS names in the config with corresponding
AAAA records defined.  ziti-edge-tunnel supports ipv6 interception but the IPC events channel does
not include the intercept IPv6 addresses, so currently IPv6 services would require manual zfw rule
entry. Similarly to IPv4, IPv6 rules can be used to forward packets to the host OS by setting 
```-t, --tproxy-port 0``` in the insert command.
  
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
type   service id              proto    origin              destination               mapping:                                                   interface list
------ ----------------------  -----    ---------------     ------------------        --------------------------------------------------------- ----------------
accept 5XzC8mf1RrFO2vmfHGG5GL  tcp      0.0.0.0/0           10.0.0.16/28              dpts=22:22                TPROXY redirect 127.0.0.1:33381  [ens33,lo]
accept 5XzC8mf1RrFO2vmfHGG5GL  tcp      0.0.0.0/0           10.0.0.16/28              dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
accept 0000000000000000000000  udp      0.0.0.0/0           172.20.1.0/24             dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
accept 5XzC8mf1RrFO2vmfHGG5GL  tcp      0.0.0.0/0           172.16.1.0/24             dpts=22:22                TPROXY redirect 127.0.0.1:33381  []
accept 5XzC8mf1RrFO2vmfHGG5GL  tcp      0.0.0.0/0           172.16.1.0/24             dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
accept 0000000000000000000000  udp      0.0.0.0/0           192.168.3.0/24            dpts=5:7                  PASSTHRU to 192.168.3.0/24       []
accept 0000000000000000000000  udp      10.1.1.1/32         192.168.100.100/32        dpts=50000:60000          PASSTHRU to 192.168.100.100/32   []
accept 0000000000000000000000  tcp      10.230.40.1/32      192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
accept FO2vmfHGG5GLvmfHGG5GLU  udp      0.0.0.0/0           192.168.0.3/32            dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
accept 0000000000000000000000  tcp      0.0.0.0/0           192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
accept FO2vmfHGG5GLvmfHGG5GLU  udp      0.0.0.0/0           100.64.0.5/10             dpts=5000:10000           TUNMODE redirect:tun0            []
accept 0000000000000000000000  udp      0.0.0.0/0           100.64.0.2/32             dpts=53:53                TUNMODE redirect:ziti0           []
```
    
- Example: List rules in firewall for a given prefix and protocol.  If source specific you must include the o 
  <origin address or prefix> -n <origin prefix len>

```  
sudo zfw -L -c 192.168.100.100 -m 32 -p udp
```
```  
type   service id              proto    origin           destination                  mapping:                                                  interface list
------ ----------              -----    --------         ------------------           --------------------------------------------------------- ------------------
accept 0000000000000000000000  udp      0.0.0.0/0        192.168.100.100/32           dpts=50000:60000          PASSTHRU to 192.168.100.100/32  []
```

- Example: List rules in firewall for a given prefix
Usage: zfw -L -c <ip dest address or prefix> -m <prefix len> -p <protocol>
```
sudo zfw -L -c 192.168.100.100 -m 32
```
```
type   service id              proto    origin           destination                  mapping:                                                  interface list
------ ----------              -----    --------         ------------------           --------------------------------------------------------- ------------------
accept 0000000000000000000000  udp      0.0.0.0/0        192.168.100.100/32           dpts=50000:60000          PASSTHRU to 192.168.100.100/32  []
accept 0000000000000000000000  tcp      0.0.0.0/0        192.168.100.100/32           dpts=60000:65535          PASSTHRU to 192.168.100.100/32  []
```
- Example: List all interface settings

```
sudo zfw -L -E
```
```
lo: 1
--------------------------
icmp echo               :1
pass non tuple          :1
ipv6 enable             :1
verbose                 :0
ssh disable             :0
outbound_filter         :0
per interface           :0
tc ingress filter       :0
tc egress filter        :0
tun mode intercept      :0
vrrp enable             :0
eapol enable            :0
ddos filtering          :0
masquerade              :0
--------------------------

ens33: 2
--------------------------
icmp echo               :0
pass non tuple          :0
ipv6 enable             :0
verbose                 :0
ssh disable             :0
outbound_filter         :0
per interface           :0
tc ingress filter       :1
tc egress filter        :1
tun mode intercept      :0
vrrp enable             :0
eapol enable            :0
ddos filtering          :0
masquerade              :0
--------------------------

ens37: 3
--------------------------
icmp echo               :0
pass non tuple          :0
ipv6 enable             :0
verbose                 :0
ssh disable             :0
outbound_filter         :0
per interface           :0
tc ingress filter       :0
tc egress filter        :0
tun mode intercept      :0
vrrp enable             :0
eapol enable            :0
ddos filtering          :0
masquerade              :0
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
removing /sys/fs/bpf/tc/globals/zt_tproxy_map
removing /sys/fs/bpf/tc/globals/diag_map
removing /sys/fs/bpf/tc/globals/ifindex_ip_map
removing /sys/fs/bpf/tc/globals/tuple_count_map
removing /sys/fs/bpf/tc/globals/udp_map
removing /sys/fs/bpf/tc//globals/matched_map
removing /sys/fs/bpf/tc/globals/tcp_map
removing /sys/fs/bpf/tc/globals/tun_map
removing /sys/fs/bpf/tc/globals/ifindex_tun_map
removing /sys/fs/bpf/tc/globals/zet_transp_map
removing /sys/fs/bpf/tc/globals/rb_map
removing /sys/fs/bpf/tc/globals/ddos_saddr_map
removing /sys/fs/bpf/tc/globals/ddos_dport_map
removing /sys/fs/bpf/tc/globals/syn_count_map
removing /sys/fs/bpf/tc/globals/tproxy_extension_map
removing /sys/fs/bpf/tc/globals/if_list_extension_map
removing /sys/fs/bpf/tc/globals/range_map
removing /sys/fs/bpf/tc/globals/wildcard_port_map
removing /sys/fs/bpf/tc/globals/zt_tproxy6_map
removing /sys/fs/bpf/tc/globals/ifindex_ip6_map
removing /sys/fs/bpf/tc/globals/tuple6_count_map
removing /sys/fs/bpf/tc/globals/matched6_map
removing /sys/fs/bpf/tc/globals/egress_range_map
removing /sys/fs/bpf/tc/globals/egress_if_list_extension_map
removing /sys/fs/bpf/tc/globals/egress_extension_map
removing /sys/fs/bpf/tc/globals/zt_egress_map
removing /sys/fs/bpf/tc/globals/zt_egress6_map
removing /sys/fs/bpf/tc/globals/egress_count_map
removing /sys/fs/bpf/tc/globals/egress6_count_map
removing /sys/fs/bpf/tc/globals/egress_matched6_map
removing /sys/fs/bpf/tc//globals/egress_matched_map
removing /sys/fs/bpf/tc/globals/udp_ingress_map
removing /sys/fs/bpf/tc/globals/tcp_ingress_map
removing /sys/fs/bpf/tc/globals/masquerade_map
removing /sys/fs/bpf/tc/globals/icmp_masquerade_map
removing /sys/fs/bpf/tc/globals/icmp_echo_map
removing /sys/fs/bpf/tc/globals/masquerade_reverse_map
removing /sys/fs/bpf/tc/globals/bind_saddr_map
```


