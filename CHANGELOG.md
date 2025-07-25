# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
###

# [0.9.21] - 2025-7-18

- Refactored port_extension_key.pad to  port_extension_key.type to differentiate ipv4 from ipv6
  range/interface maps so that they are not ambiguous in the case of all zeros prefix/len with 
  matching ifindex/lowport values.
- Fixed issue in zfw_tunnel_wrapper.c that could cause a rule cleanup issue on exit.
- Refactored pr.yml due to changes in the regression test pattern.

###

# [0.9.20] - 2025-7-18

- Refactored cli sanitization to only block '-' at start of argument and removed 
  redundant check for no argument.
- Added workflow_dispatch to pr.yml

# [0.9.19] - 2025-6-1
###

- Fixed issue where in masquerade mode if sending at a high rate user space could not keep up with timestamps.
- Additions to tcp tracking to work with varying tcp stack FIN acknowledgement handling.

###

# [0.9.18] - 2025-5-28
###

- Fixed issue where outbound tcp passthrough tracking will stop packet ingress forwarding prematurely when
  fin received from client and server.

- Fixed format error in zfw_xdp_ingress.c where several statements had double ; termination.

# [0.9.17] - 2025-5-1

- Refactored GENEVE inbound termination to continue to filter processing as non GENEVE if the GENEVE version and
  header length are not the expected values vs the current explicit drop action.
  
- Removed port 6081(GENEVE) from the IPv4 masquerade PAT random dynamic udp source port pool
  
###

# [0.9.16] - 2025-4-25

- Refactored openziti tunnel mode forwarding to optimize forwarding performance.  On ingress
  a check is made to see if there is an existing tunnel state for the source ip, dest ip, src port,
  dest port and protocol.  If it exists and is not expired (State expires in 30 seconds if no traffic seen
  in either direction) traffic is fast redirected to the ziti0 interface. Tunnel mode should only be enabled on
  interfaces which you wish to intercept traffic when running in conjunction with ziti-edge-tunnel.  

- Updated README.md 

###

# [0.9.15] - 2025-4-23

- Refactoring udp state engine for outbound filtering in order to optimize throughput.
  The most notable change is in SEC("action") of zfw_tc_outbound_track.c which now looks up
  existing cached udp sessions in the udp_map to determine if the flow should be fast switched
  to the os.  This has some implications as follows if the outbound rule is removed and will act
  differently if masquerade is also enabled on the outbound interface.

  If masquerade is disabled and the outbound rule is removed and the flow is active it will timeout
  in 30 seconds regardless if outbound udp traffic is sent that matches the rule tuple.  Note the
  tuple includes both source and destination ports so new sessions that only match the outbound destination 
  ip/port and not source port will immediately be blocked when the outbound rule is removed.

  if masquerade is enabled and the outbound rule is removed and the flow is active it will not timeout
  till outbound traffic that matches the tuple ceases for at least 30 seconds. Similarly to non-masquerade the
  tuple includes both source and destination ports so new sessions that only match the outbound destination 
  ip/port and not source port will immediately be blocked when the outbound rule is removed.

  In both cases inbound matching udp traffic will continue to maintain states unless it ceases for at 
  least 30 seconds.
  
###

# [0.9.14] - 2025-4-19

- Additional changes made to ingress filter to ensure masquerade collisions are avoided for
  host initiated client sessions.

###

# [0.9.13] - 2025-4-17

- Refactored masquerade to ensure that firewall internally generated outbound client sessions are also
  processed through masquerade dynamic PAT to ensure there are no source port 
  collisions with passthrough sessions.  Note with this change when an interface is in masquerade mode 
  you will not be able to connect inbound to udp listening ports on the firewall.

- Fixed an issue where if tc fails to attach a filter and zfw reports a waitpid error but still partially
  applies some of the filers and reports the filter is in place in ```zfw -L -E```.   

###

# [0.9.12] - 2025-4-5

- Updated DNP3 fcode map to change value to an unsigned int to count the number of times the 
  same fcode insertion was requested to track queued service fcode requests so that the fcode
  will only be removed when all instantiations have been decremented.  Output of ```zfw -L -C```
  now list the current instantiations per fcode i.e
  ```
  dnp3 function code allow list
  -------------------------------
  129 (0xa0): instantiations: 1
  130 (0x82): instantiations: 2
  -------------------------------
  fcode count: 3
  ```
  Also added ```sudo zfw -F -C``` which will flush all dnp3 fcodes from the map.
  The above functionality allows for more advanced interaction with external programs such as openziti
  to facilitate automated fcode insertion / removal with services.

###

# [0.9.11] - 2025-3-14

- Updated DNP3 fcode map to limit size to 256 entries and changed to standard hashmap.  Also added DNP3 ring buffer event logging. 
- Added IPv4 modbus attack protection when ot filtering is enabled on the inbound interface.  zfw actively monitors the slave responses to
  ensure valid transaction id, unit id, function codes in response to requests from the master. Note a logical AND operation is performed on
  response functions codes with 0x7f to allow for error responses.
  
###

# [0.9.10] - 2025-3-7

- Added IPv4 support for dnp3 slave function code filtering.
    
  Enable/Disable at interface level with ```sudo zfw --ot-filtering <iface> [-d]```

  Allowed codes added via ```sudo zfw --dnp3-fcode-add <decimal fcode>```

  List allowed fcodes ```sudo zfw -L --list-dnp3-fcodes```

- Fixed some command help usage syntax errors
- Fixed incorrect brackets on ddos port add/remove conditional in zfw.c.
- Updated README.md
  
###

# [0.9.9] - 2025-2-19

- Modified start_ebpf_controller.py so it does not restart the controller when configuring services.

  
###

# [0.9.8] - 2025-2-4

- Modified start_ebpf_router.py and start_ebpf_controller.py scripts so that if the user_rules.sh file
  exists it can override the default port settings set based on the respective config file.
  
###

# [0.9.7] - 2024-12-16

- added debug option to the pr worklow for checking version tested

###

# [0.9.6] - 2024-12-09

- Updated zfw.c to redirect system call output to /dev/null for set_tc_filter() 
  
###

# [0.9.5] - 2024-11-29

- updated the release workflow to upload zfw-router deb package to jfrog repo

###

# [0.9.4] - 2024-11-20

- added zfw_xdp_tun_ingress.o to router package for installations where ziti-edge-tunnel is not run as a service
  
###

# [0.9.3] - 2024-11-12

- Removed unused variables from zfw.c
- refactored start_ebpf_controller.py to enable/modify external ddos protection services
###

# [0.9.2] - 2024-10-01

- adding environmental path option for the ```sudo zfw -H, --init-tc <ifname|all>```.  if ZFW_OBJECT_PATH=<PATH> is populated then this command will
  follow <PATH> otherwise it will follow the default path ```/opt/openziti/bin```. 
- Fixed help menu formatting issue.

###

# [0.9.1] - 2024-10-01

- Added code to test if masquerade dst ip and src_port/dst_port/protocol combination is free before allocating new random   
  source port to ensure no collisions will occur.

###

# [0.9.0] - 2024-09-24
- Added several new Arguments to zfw to allow for direct system call integrations with 
  ziti-edge-tunnel ```-A --add-user-rules```, ```-H --init-tc <iface>```, ```-Z, --init-xdp <iface>```, ```-B, bind-saddr-add <cidr>```,
  ```-J, bind-saddr-delete <cidr>```, ```-F -j, bind-flush```
  - Added new interface setting to ```-q, pass-non-tuple``` (off by default) pass all non tuple (tcp/udp) traffic to the os for
    applications requiring only redirection (Not recommended for stand alone fw use)
  - Updated README.md 


# [0.8.19] - 2024-09-08
- Add masquerade/reverse_masquerade map garbage collection to ```zfw.c -L -G, --list-gc-sessions``` which is now added to
  /etc/cron.d/zfw_refresh as well so it will run once every 60 seconds unless modified.
- Fixed issue where icmp unreachable were not working for ipv4 masqueraded tcp/udp sessions that was introduced when dynamic PAT was added. 

###
# [0.8.18] - 2024-09-07
- Add removal of udp state upon receipt of DNS reply from server for passthrough tracking / Masquerade
  
###
# [0.8.17] - 2024-09-06
- Refactor of L4 csum ipv4 
  
###
# [0.8.16] - 2024-09-02
- Fixed incorrect waitpid success/failure conditional checks in zfw.c and zfw_tunnel_wrapper.c.  This did not cause an operational issue but would not
  report correctly in case system call failures.
- Refactored csum calc for both ipv4 tcp / udp. 
- Updated README with latest ```zfw -Q``` printout. 
  
###
# [0.8.15] - 2024-08-26
- Refactored all startup scripts to default InternalInterfaces to have outbound tracking enabled
- Refactored IPv4 masquerade to use dynamic PAT vs static PAT and added RB logging
- Fixed issue where if IPv4 udp checksum was 0 masquerade erroneously attempted to recalculate the checksum
  
  

###
# [0.8.14] - 2024-08-16
- Fixed issue where icmp type 3 tcp only accepting inbound for ports associated with local listening ports
- Added support for stateful IPv4 icmp unreachable support both in the case of masquerade and non masquerade, for udp
  and tcp outgoing initiated connections only.

###
# [0.8.13] - 2024-08-12
- Added Outbound tracking for IPv4 and IPv6 ICMP Echo
- Added Masquerade for passthrough icmp echos.
- Fixed an issue where both the packages and Makefile were limiting egress rule entries to 100 instead of 100000.
- Fixed issue where incorrect count check was being performed on insert for ipv6 rules to verify if they had reached
  BPF_MAX_ENTRIES.
  
###
# [0.8.12] - 2024-08-07
- Change ci workflow display name and to trigger on push to branches other than main.
- Refactored install.sh, start_ebpf_controller.py and revert_ebpf_controller.py to work with controller not running as root.

###
# [0.8.11] - 2024-08-03

- Edit Readme updated ```zfw -L -E ``` outputs
- Added cron script ```/etc/crond.d/zfw_refresh``` to run ```/opt/openziti/zfw -L -E``` once per minute to refresh the ifindex to ip mappings. This was done
  to enable detection of new interfaces and to refresh ip for any interface that might have changed dynamically or otherwise. 
  
###
# [0.8.10] - 2024-07-29

- Updated start_ebpf_controller.py to only clear ingress filters on restart and also removed ```-r, --route``` from the flush.
- Added native masquerade for IPv4/IPv6 passthrough connections.
  
###
# [0.8.9] - 2024-07-28

- Removed arm64 rpm package build for RH from workflows
- updated BUILD.md with info on x86_64 RH build prerequisites
- Fixed issue with -F, --flush introduced when adding flush for all, ingress and egress
- Updated start_ebpf_router.py and start_ebpf_tunnel.py to only clear ingress filters on restart.

###
# [0.8.8] - 2024-07-24

- Updated workflows to support rpm packages for ReH 9
- Updated workflows to remove deprecated actions
- Updated README to describe RH deployment
  
###
# [0.8.7] - 2024-07-23

###

- Added separate zfw_monitor binary as a dedicated logging tool for zfw and to be called on from zfw-logging.service rather 
  than calling the main zfw binary.  The main zfw binary will retain support for -M, --monitor.
- Updated github workflows and Make scripts to compile/package/install new zfw_monitor.
- Updated README with more info and example of explicit deny rules precedence.


# [0.8.6] - 2024-07-20

###

- Added support for explicit deny rules.  Appending an ```-I, --insert``` entry with ```-d, --disable``` will now enter an explicit deny
  rule.  This works for both ```ingress``` and ```egress``` ```IPv4``` and ```IPv6``` rules. Note the default operation is to deny all so this will only be useful if you want to deny a specific host or subnet of an existing allowed cidr.  e.g if you wanted to deny 172.16.240.139 out of the allowed range of 172.16.240.0/24 you would enter:
  ```
  sudo zfw -I -c 172.16.240.139 -m 32 -l 443 -h 443 -t 0 -p tcp  -z egress -d
  sudo zfw -I -c 172.16.240.0 -m 24 -l 443 -h 443 -t 0 -p tcp  -z egress
  ``` 

  listing will now show type e.g.
  ```sudo zfw -L```
  ```  
  type   service id            	proto	origin              	destination                     mapping:                				    interface list                 
  ------  ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
  Accept 0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.0/24         dpts=443:443   	        PASSTHRU to 172.16.240.0/24     []
  deny   0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.137/32       dpts=443:443            PASSTHRU to 172.16.240.137/32   []
   ```

- README syntax cleanup
- README update sample ```zfw -L -E, --list-diag``` to reflect latest code updates
- Fixed issue where zfw allowed inserting/deleting a rule with a mask value outside the 
  range for the address type.
- Fixed the print formatting for listing individual IPv6 cidr in zfw.c
- Fixed the print formatting for listing individual IPv4 cidr in zfw.c

# [0.8.5] - 2024-07-17

###

- Added code to check if tc qdisc clsact is already enabled on an interface so it there will no longer be 
  exclusivity errors printed on adding additional filters or re-adding.
- Added code to block entering -b, --outbound_filter if egress tc filter is not applied to the interface first.
- Added code to block duplicate tc ingress / egress filters
- Added code to set outbound filter setting to off for an interface when its tc egress filter is removed.
- Changed operation of -F --flush.  Now -F with no additional arguments will remove all entries ingress and egress.
  -F -z ingress will remove all ingress filters. -F -z egress will remove all egress filters.


# [0.8.4] - 2024-07-13

###

- Added the ability to lookup individual ipv6 and egress rules by CIDR/LEN or CIDR/LEN/PROTOCOL combination e.g.
  ```
  $sudo zfw -L -c 172.16.240.139 -m 32 -z egress

  EGRESS FILTERS:
  service id            	proto	origin              	destination                     mapping:                				 interface list                 
  ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
  0000000000000000000000	udp	0.0.0.0/0           	172.16.240.139/32               dpts=5201:5201   	PASSTHRU to 172.16.240.139/32   []
  Rule Count: 1
  service id            	proto	origin              	destination                     mapping:                				 interface list                 
  ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
  0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=5201:5201   	PASSTHRU to 172.16.240.139/32   []
  0000000000000000000000	tcp	0.0.0.0/0           	172.16.240.139/32               dpts=22:22       	PASSTHRU to 172.16.240.139/32   []
  Rule Count: 2
  
  $sudo zfw -L -c 2001:db8:: -m 64 -z egress -p tcp

  EGRESS FILTERS:
  service id             proto origin                                     destination                                  mapping:                    interface list
  ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------
  0000000000000000000000|tcp  |::/0                                      |2001:db8::/64                              | dpts=5201:5201   PASSTHRU | []
  Rule Count: 1

  $sudo zfw -L -c 2001:db9:: -m 64

  INGRESS FILTERS:
  service id             proto origin                                     destination                                  mapping:                    interface list
  ---------------------- ----- ------------------------------------------ ------------------------------------------   -------------------------   --------------
  0000000000000000000000|udp  |::/0                                      |2001:db9::/64                              | dpts=5000:5000   PASSTHRU | []
  0000000000000000000000|udp  |::/0                                      |2001:db9::/64                              | dpts=5201:5201   PASSTHRU | []
  0000000000000000000000|udp  |::/0                                      |2001:db9::/64                              | dpts=400:400     TP:323   | []
  Rule Count: 3
  service id            	proto	origin              	destination                     mapping:                				 interface list                 
  ----------------------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
  0000000000000000000000|tcp  |::/0                                      |2001:db9::/64                              | dpts=22:22       PASSTHRU | []
  0000000000000000000000|tcp  |::/0                                      |2001:db9::/64                              | dpts=443:443     PASSTHRU | []
  0000000000000000000000|tcp  |::/0                                      |2001:db9::/64                              | dpts=8000:8000   PASSTHRU | []
  0000000000000000000000|tcp  |::/0                                      |2001:db9::/64                              | dpts=5000:5000   PASSTHRU | []
  0000000000000000000000|tcp  |::/0                                      |2001:db9::/64                              | dpts=5201:5201   PASSTHRU | []
  0000000000000000000000|tcp  |::/0                                      |2001:db9::/64                              | dpts=400:400     TP:631   | []
  Rule Count: 6
  ```
- zfw.c is now statically compiled with the latest version libbpf available at time of the deb package build, refer to workflow files for details.
- Added LICENSE, CHANGELOG.md and README.md files to bin directory of deb packages
- Cleaned up README.md syntax errors / clarifications
- Updated license comments in source code to include SPDIX-License-Identifier.
  
# [0.8.3] - 2024-07-04

###

- Added ability to apply outbound IPv4 and IPv6 filters to an interface.  The default is set to no 
  filtering but outbound tracking of passthrough client traffic when afw_tc_outbound_track.o is applied.
  Outbound filtering is enabled by ```sudo zfw -b, --outbound_filter <iface name | all>```
  
- Fixed issue where if ingress filtering enabled on loopback 
  interface IPv6 was not enabled by default

- Fixed an issue where udp inbound initiated connections were disconnected for some ipv4 sockets 
  when passing through to the local OS.

- Hardened zfw_tunnel_wrapper.c around the currently incorrect ipv6 event channel IP info.
  Also fixed invalid strlen() calc. 

- Fixed issue where alt interface names could not be used. 

# [0.8.2] - 2024-07-01

###

- Added support for ipv6 inbound filtering rules. Currently only destination filtering is allowed.
  Rules are entered exactly the same as IPv4 rules and zfw will detect whether the address is ipv4 
  or ipv6 based on the addresses. This now allows for trusted filtered IPv6 traffic to be forwarded 
  to an External Interface with outbound tracking.
  e.g. sudo zfw -I -c 2001:db9:: -m 64 -l 443 -h 443 -t 0 -p tcp

# [0.8.1] - 2024-06-23

###

- Fixed issue in start_ebpf_router.py and start_ebpf_tunnel.py where if an ExternalInterface does not exist but is configured it causes zfw to disable ebpf on the system
  for all interfaces preventing the FW from starting.  Note this only could occur on initial start of ebpf and did not occur if the start scripts were run after ebpf was already 
  running on other interfaces.

# [0.8.0] - 2024-06-13

###

- Initial support for IPv6. Added basic neighbor discovery, inbound ipv6 echo (disabled by default)/ echo reply, Inbound ssh,  Outbound 
  stateful tracking. IPv6 is disabled by default except for inbound ipv6 router advertisments so that the ipv6 auto-configuration(SLAAC) can occur before zfw enumerates ipv6 interfaces 
  to ensure the ipv6 interface address is included in the ifindex_ip6_map.'
- Removed unused tuple_key struct from zfw_xdp_tun_ingress.c

# [0.7.8] - 2024-06-13

###

- Fixed issue where zombie processes were generated by zfw_tc_ingress.c when adding or deleting
  routes via ip system calls.
  
# [0.7.7] - 2024-06-11

###

- Fixed fw-init.service changed after= to After=
- Cleanup in zfw_tunnel_wrapper.c removed various unused variables
  
# [0.7.6] - 2024-06-04

###

- Fixed issues in zfw_tunnel_wrapper where incorrect reference was made to zet ctrl socket where needed to check status of event socket.  Removed all
  references to unused zet ctrl socket.

# [0.7.5] - 2024-06-04

###

- Fixed issue where allowed source addresses where not being updated on service modification without restart of
  ziti-edge-tunnel.

# [0.7.4] - 2024-06-03

###

- Fixed issue where ziti-fw-init.service and ziti-wrapper.service run in parallel the insert duplicate tc entries on
  some ebpf enable interfaces. This was remedied by placing an ExecStartPre statement requiring ziti-fw-init.service is not running
  before start of ziti-wrapper.service.

# [0.7.3] - 2024-05-30

###

-- Added support for L2tpV3 over ziti with l2tp tunnel terminating on the same vm as ziti-edge-tunnel.
   In order to support this a unique ZITI_DNS_IP_RANGE must be set on both vms terminating l2tpv3.  The
   source of the L2tpv3 tunnel on each zet host needs to be set to the ip address assigned to the ziti0
   interface which will be the first host address in the ZITI_DNS_IP_RANGE. In addition you will need to enable
   ebpf outbound tracking on the loopback interface.  This can be setup vi /opt/openziti/etc/ebpf_config.json i.e.
   ```
   {"InternalInterfaces":[{"Name":"eth0", "OutboundPassThroughTrack": false, "PerInterfaceRules": false}, {"Name":"lo", "OutboundPassThroughTrack": true}],"ExternalInterfaces":[]}
   ```
-- Fixed Readme.md formatting issue introduced in 0.7.2

# [0.7.2] - 2024-05-28

###

- Refactored to include resolver ip in ifindex_tun struct
  ```
  struct ifindex_tun {
    uint32_t index;
    char ifname[IF_NAMESIZE];
    char cidr[16];
    uint32_t resolver;
    char mask[3];
    bool verbose;
  };
  ```
  - Fixed issue: incorrect setting in ziti-fw-init.service.  after=network.target should have been 
    After=network.target
  
# [0.7.1] - 2024-05-28

###

- Fixed issue where if ziti-edge-tunnel is stopped and wildcard entries exist they will re-populate on start unless rebooted or ebpf disabled and re-enabled.  

# [0.7.0] - 2024-05-26

###

- Fixed issue found with Ubuntu 24.04 on Raspberry Pi where the ebpf interface was not
  discovering its IP address due to some timing issue at boot.  Added diag check when adding a service for
  the first time via zfw_tunnel_wrapper.c to ensure IP is up when ebpf enumerates the interface.  
- Fixed potential memory leak in zfw.c ringbuff monitoring
- Refactored to support add and removal of individual url based services.
  Summary rules below will no longer be inserted and will be replaced with explicit host rules:
  ```
  (removed)
  0000000000000000000000	tcp	0.0.0.0/0           	100.64.0.0/10                   dpts=1:65535     	TUNMODE redirect:ziti0          []
  0000000000000000000000	tcp	0.0.0.0/0           	100.64.0.0/10                   dpts=1:65535     	TUNMODE redirect:ziti0          []
  
  (example new dynamic rule)
  5XzC8mf1RrFO2vmfHGG5GL	tcp	0.0.0.0/0           	100.64.0.5/32                   dpts=5201:5201   	TUNMODE redirect:ziti0          []
  ```
  A rule will also be entered for the ziti resolver ip upon the first configured hostname based service i.e.
  ```
  0000000000000000000000	udp	0.0.0.0/0           	100.64.0.2/32                   dpts=53:53       	TUNMODE redirect:ziti0          []

  This entry will remain unless ziti-edge-tunnel is stopped and will again be reentered upon reading the first hostname based service entry
  ```

  If wild card hostnames are used i.e. *.test.ziti then zfw will enter summary rules for the entire ziti DNS range for the specific ports defined for the service i.e.
  ```
  0000000000000000000000	tcp	0.0.0.0/0           	100.64.0.0/10                   dpts=5201:5201   	TUNMODE redirect:ziti0          []
  0000000000000000000000	udp	0.0.0.0/0           	100.64.0.0/10                   dpts=5201:5201   	TUNMODE redirect:ziti0          []

  IMPORTANT: These entries will remain until as long as there is at least one wildcard in a service using the port/port range via cli and will not be removed by ziti service deletion. It is recommended to use single ports with wild card since the low port acts as a key and thus the first service that gets entered will dictate the range for the ports and there is only one prefix. 
  ```


# [0.6.5] - 2024-05-24

###

- For ZET added ziti generated rule removal upon shutdown via zfw_tunnel_wrapper.  Wrapper will also remove any statically entered rules with tproxy_port > 0.
- Refactored to expressly deny ssh to local interface interface if "diag ssh disable set to true" even if ebpf does not know its ip address yet.  Note this can be overridden 
  if an explicit ssh rule exists"

# [0.6.4] - 2024-05-21

###

- Refactoring for further memory optimization. Removed struct tproxy_port_mapping. 
- Refactored ziti-wrapper.service with high water mark 80% memory.
- Fixed rule listing format issue where if the service id was less than 22 characters the entire rule was left shifted
- Fixed issue for listing output with ziti-edge-tunnel where passthrough rules were listed as tunnel redirect rules    
  
# [0.6.3] - 2024-05-17

###

- Added back per-interface-rule support for dynamic index interfaces with reduced memory footprint.
- Added back service_id logging with reduced memory footprint.
    
# [0.6.2] - 2024-05-16

###

- Reverted to only support per-interface rules if an interface ifindex is < 255.  This was done to
  reduce per rule memory load which can greatly increase memory requirements when dealing with 1000s or rules.
- Reverted addition of service_id as well since it also greatly increased memory requirements 

# [0.6.1] - 2024-05-14

###

- Added support for ziti service id tracking.  Will need to update ziti-router via pr.
- Fixed issue where passthrough rules would not generate log data when in verbose mode.
- Fixed release workflow where if a non merged pull request was closed it would trigger a release
  build action. 

# [0.5.18] - 2024-05-08

###

- Refactored to support per-interface-rules for interfaces with indexes greater than 255
   i.e. tun/tap interfaces.
   
- Fixed issue where if MAX_ADDRESSES # of interfaces exist with out IPs but with another AF Family that iterates before AF_INET then
  the ifindex_ip_map does not populate since the index failed the conditional.  Added a specific ip_index_count and moved the old
  index_count to all_index_count.

# [0.5.16] - 2024-04-26

###

-- Refactored interface_map() in zfw.c to mitigate a potential memory leak in corner case where a user
   manually enables zfw with ziti-edge-tunnel and non default cidr.

###
# [0.5.15] - 2024-04-12

###

- Added map to track tcp syn count for packets sent to the firewall ip address on port 443.
- Ddos protection is meant for the FW host accept/deny logic was moved to first bpf program. 
- ddos dport map was created to specify ports to be protected when an interface is in 
  ddos_protect mode.
- ddos saddr map was created to specify whitelisted IP addresses to be allowed to reach protected ports
  when an interface is in ddos_protect mode.
  
# [0.5.14] - 2024-04-02

###

- Fixed Added su directive to /etc/logrotate.d
   
# [0.5.13] - 2024-03-28

###

- Changed ddos_protect_map to type BPF_MAP_TYPE_LRU_HASH to allow cycling of entries
- Added controller startup script
- Added optional logging systemd service with log rotation support
- Updated make install.sh for controller install and logging service files
- Removed -p from cp commands in make install.sh so files are installed as owned by root user   
- Added fw-init-router.service for standalone firewall deployment in make install.sh
- Updated workflows to add new / updated files

# [0.5.12] - 2024-03-14

###

- Added ddos_protect diag mode
- Added icmp unrecheable ttl logging. Inner and outer.
- Fixed BUILD.md incorrect reference to parent repo

# [0.5.11] - 2024-02-27

###

- Added ip protocol to matched map key and fixed typo in comment

# [0.5.10] - 2024-02-20

###

- Fixed a possible issue where in high performance compute environments there could be more than one packet being processed by the TC filters there could be a 
  mismatched rule where if a new packet matches a rule it could cause other packets in flight to be processed by the same rule.

# [0.5.9] - 2024-02-09

###

- Fixed an issue where if an ingress tc filter is applied to the loopback interface traffic is dropped if it does not specifically 
  match a rule.  The correct action is to pass all traffic to the loopback unless there is a rule explicitly redirecting.
  the traffic to either a tproxy port or ziti(tun) interface.

# [0.5.8] - 2024-01-28

###

-- Modified start_ebpf_router to include a conditional when adding the rules for the ziti-router resolver. 
   If the ip address of the ziti-router's resolver in the config.yml is set to 100.127.255.254 which is the 
   ip that NetFoundry uses when setting up AWS Gateway load balancing the -r option is now added in order to 
   automatically assign the address back to the loopback.  This change was required due to the addition of the -r flag in the zfw -F -r command used to ensure all ziti zfw rules/routes are deleted before restarting ziti-router.service. 


# [0.5.7] - 2024-01-21

###

-- Modified the "zfw -F" system call in start_ebpf_py.py to "zfw -F -r" to ensure that any ziti created loopback routes are also
   cleared when restarting ziti-router.  
-- Removed deprecated sed entries in start_ebpf_router.py that are no longer required
-- Fixed inaccurate string parse check in start_ebpf_router.py set_local_rules()
-- Original changes were merged directly into v0.5.6 so this entry is to allow new release merge.

# [0.5.6] - 2024-01-19

###

-- Fixed issue in outbound tracking for passthrough tcp connections where packets with rst set from
   server were only accepted if connection was already in established state.  Changed to allow rst during
   tcp handshake which occurs when server refuses a connection.

# [0.5.5] - 2024-01-05

###

-- Changed ICMP Unreachable logging to default level
-- Added -L, --write-log option to -M, --monitor output to a specified log file 
-- Removed redundant check on ifname in process_events
-- Refactored ring_buffer to report only errors and ICMP Unreachables by default and
   require verbose for all valid traffic monitoring. 
-- Added new error code ICMP_INNER_IP_HEADER_TOO_BIG
-- Code consolidation in zfw_tc_ingress.c

# [0.5.4] - 2023-12-24

###

-- Added support for stateful stateful icmp unreachable inbound support in order to support
   pmtud and unreachable metric collection.
-- Fixed added ring_buffer__free() to INThandler in zfw.c to properly de-allocate memory 
   allocated by ring_buffer__new in main() if -M argument was supplied and SIGINT or SIGTERM
   is received.

# [0.5.3] - 2023-12-19

###

- Fixed issue causing valgrind memory error due to non-initialized struct in add_if_index() in zfw.c.

# [0.5.2] - 2023-11-27

###

- Changed ifindex_ip_map to a hashmap and added code to prune stale keys due to 
  index changes for dynamic interfaces.
- cleanup removed redefinitions of global count_map_path in multiple functions 

# [0.5.1] - 2023-08-22

###

- Fixed outbound tracking broken due to missed addition of eapol to diag_map values.

# [0.5.0] - 2023-08-18

###

- Added make to pre-compile binary package installs listed in BUILD.md
- Changed bind service lookup from dumpfile to event channel.  0.5.0 will only work with
  ZET 0.22.4 or above
- Added passthrough support for eapol (802.1X) frames

# [0.4.6] - 2023-08-13

###

- Fixed potential race condition if upstream DHCP server is not functioning when FW inits ebpf.
  Changed address family match to ethernet when applying TC Filters/Diag settings.
  
# [0.4.5] - 2023-08-03

###

- Fixed ring buffer events for tunnel interface not sending correct source/destination ports.  Also changed default
  xdp RB events to only send if verbose mode is enabled for the tun/ziti interface.  

# [0.4.4] - 2023-08-01

###

- Added Makefile and install.sh in src folder to allow 
  build via make.

- Fixed issue where start_ebpf_router.py was not   
  properly updating the ziti-router.service file.

# [0.4.3] - 2023-07-25
 
###

-- Refactored monitoring to use ring buffer and removed all bpf_printk() helper calls
-- Added ring buffer monitoring to zfw via -M, --monitor <interface | all> flags 
-- General Code cleanup in zfw.c  

# [0.4.2] - 2023-07-15

###

- Added support for secondary ip addresses with the auto ssh inbound support function on the incoming interface.
  Number of total addresses if defined in by MACRO MAX_ADDRESSES.  In package deployments this will be set to 10.

# [0.4.1] - 2023-06-30

###

- Added support for inbound vrrp on a per port basis.
  
# [0.4.0] - 2023-06-29

###

- Added support for upcoming ziti-edge-tunnel interface name change from tunX to zitiX.
  
# [0.3.10] - 2023-06-28

###

- Added checks to catch exceptions in config.yml 
   
# [0.3.9] - 2023-06-27

###

- Refactored start_ebpf_router.py and revert_ebpf_router.py to read / update config.yml
  using pyyaml python module.

# [0.3.8] - 2023-06-26

###

- Fixed missing terminating bold in README.md.
- Refactored start_ebpf_router.py to suppress some output messages.
   
# [0.3.7] - 2023-06-16

###

- Fixed CHANGELOG Duplicate 0.3.5 entry and set to 0.3.6
- Added check to make sure each ebpf program loads into tc filter before proceeding and if failure occurs
  exit(1) and print the filter# where the failure ocurred.
- Removed unknown import shutil from start_ebpf_router.py


# [0.3.6] - 2023-06-15

###

- Refactored auto-load of ziti-router config.yml port rules to dynamically enter rules when ziti-router.service is restarted or
  the start_ebpf_router.py is executed.  Also refactored deb packages to install all scripts, zfw and zfw_tunnwrapper as only 
  root executable.
  
# [0.3.5] - 2023-06-15

###

- Changed zfw-router auto ziti-router config.yml port/rule insertion to limit destination IP to config.yml lanIf 
  
# [0.3.4] - 2023-06-14

###

- Fixed bug in start_ebpf_router.py where lan IP mask was set to /24 instead of /32
   
# [0.3.3] - 2023-06-14

###

- Refactored to start_ebpf_router.py to add ziti-router listen ports as passthrough zfw rules on in /user/openziti/bin/user/user_rules.sh for both CloudZiti and
  OpenZiti deployed ziti-routers. 
- Refactored start_ebpf_router.py and revert_ebpf_router.py scripts ziti-router.service auto-edits to key on only the router service for entry 
  for both start and revert respectfully.

# [0.3.2] - 2023-06-13

###

- initial integration of ziti-router.  Changed package name for ziti-tunnel to zfw-tunnel. Added new package zfw-router.  Previous installs with
  zfw package should remove package first then install new package i.e. sudo dpkg -P zfw && sudo dpkg -i zfw-tunnel_<ver>_<arch>.deb

# [0.2.5] - 2023-06-05

###

- Refactored zfw.c to include <linux/if.h> vs <net/if.h> for consistency.
- Refactored zfw_tc_ingress.c and zfw_tc_ingress.c added final seq/ack tracking to more accurately determine
  tcp session termination.
- Updated README with link to build openziti network and install ziti-edge-tunnel

# [0.2.4] - 2023-06-02

###

- Fixed fd leak in zfw.c get_index()
- Interface function refactor / clean

# [0.2.2] - 2023-05-31

###

- Fixed missing verbose check for bpf_printk statement in action/5.
- Fixed logic in action/5 for tproxy based forwarding decision (Needed for ziti-router integration).
- Minor README formatting change.

# [0.2.1] - 2023-05-29

###

- Changed in operation of transparency route unbinding.  In order to allow internal tunneler connections
  over ziti the default operation has been set to not delete any tunX link routes. This will disable the ability to support transparency on some architectures.  There is now an environmental variable TRANSPARENT_MODE='true' that can be set in the /opt/openziti/etc/ziti-edge-tunnel.env file to enable deletion of tun routes if bi-directional transparency is required at the expense of disabling internal tunneler interception.

# [0.2.0] - 2023-05-29

###

- Changed ebpf program chaining method from tail calls to tc filter chaining.  This 
  change should allow for installation on newer linux releases that do not support
  legacy ELF maps. 
- Fixed issue where if the loopback was set to disable ssh via zfw -x, --disable-ssh 
  the diag setting incorrectly set it to disabled and would not allow the disable to
  be removed without clearing the ebpf diag map manually.

# [0.1.19] - 2023-05-25

###

- Removed unused/unsupported 'id' field from all BTF Maps
  
# [0.1.18] - 2023-05-25

###

- Switched deb compression algorithm to gzip
   
# [0.1.17] - 2023-05-25

###

- Fixed BUILD.md pointing to deprecated repo.
  
# [0.1.16] - 2023-05-23

###

- Increased event buffer size / max line size to support single services with large #s
  of prefixes.

# [0.1.15] - 2023-05-23

###

- Added local route cleanup on SIGTERM/SIGINT.

# [0.1.14] - 2023-05-23

###

- Major operational change.  Fixed issue where ziti-edge-tunnel would not bind to egress allows source 
  ip unless there was an exact /32 match.  Now binding is possible with a subnet level match.  This is
  a significant improvement as now allowed sources do not have to be host level entries. In order to 
  achieve this the link scoped route to tuX created by ZET for interception is deleted by the wrapper and a
  local ip route is added to lo in its place.  This is made possible by the tc-ebpf-redirect which negates
  the need for the link scoped route. **After update a system reboot should be performed** 

- General code cleanup 

# [0.1.13] - 2023-05-21

###

- Fixed incorrect spelling of privileges in ebpf not enabled output messages.

# [0.1.12] - 2023-05-21

###

- Changed interface ebpf settings assignment which may require alteration of existing config if setup for exteral
  outbound tracking.   

  Added keys to /opt/openziti/etc/ebpf_config.json
   - PerInterfaceRules - sets state of per interface rules awareness.
     -  InternalInterfaces default: false
     -  ExternalInterfaces default: true
   - OutboundPassThroughTrack
      -  InternalInterfaces default: false
      -  ExternalInterfaces default: true

- Added empty ExternalInterfaces key to ebpf_config.json.sample and new keys described above with default values in
  the InternalInterfaces object.  These can be excluded since they are default and provided only for example purposes.
- /opt/openziti/start_ebpf.py updated to parse new keys and implement new interface deployment logic.

- Edited debug output in ingress/egress tc to better reflect data captured

# [0.1.11] - 2023-05-17

###

- Fixed Usage: output inconsistencies
- Added hyperlink to https://docs.openziti.io/
- Added debug output in both ingress and egress for traffic that matches
  host initiated connections
- standardized on debug output messaging and corrected spelling errors.

# [0.1.10] - 2023-05-17

###

- Reverted ci/release.yml to include 'Pre-Depends: linux-image-generic (>= 5.15.0)'
- Fixed README Missing comma in json sample


# [0.1.9] - 2023-05-17

- Changed ci/release.yml to include 'Pre-Depends: linux-image-generic (>= 5.15.0)'
- Fixed ci/release.yml ${{ env.MAINTAINER }} missing prepended $
- Added additional src/dest debug info in outbound tracking for udp
- Fixed inconsistency in usage:

###

- Fixed --help output changed "ssh echo" to ssh

# [0.1.8] - 2023-05-17

###

- Added input validation to all interface related commands.  If non existent name is given "Interface not 
  found: <ifname> will be output.
- Fixed output of zfw -L -i
- Added README.md section for containers, fixed some inconsistencies  

# [0.1.7] - 2023-05-17

###

- Fixed input validation to reject any tc filter commands with out -z, --direction specified
- Added enhanced output for outbound tracking 
- Modified tcp state map to have separate fin state for client and server to more accurately
  identify tcp session close.
- Edits to readme removed ./ and repeated sudo

# [0.1.6] - 2023-05-17

###

-Fixed start_ebpf.py syntax error printf() and should have been print() and removed sys.exit(1) on zfw -Q fail.
-Fixed README.md inconsistencies/errors.
-Fixed zfw -Q not displaying sudo permissions requirement when operated as a non privileged user.
-Modified Maximums entries for multiple maps, this included a changed for MAX_BPF_ENTRIES which
 is settable at compile time and reflected in release.yml/ci.yml workload.
 
# [0.1.5] - 2023-05-16

###

- Fixed some README.md inconsistencies and reduced some instructions to list only the most optimal methods.
- Changed Depends: ziti-edge-tunnel to Pre-Depends: ziti-edge-tunnel '(>= 0.21.0)' in release.yml key to .deb 
  control to prevent installation if ziti-edge-tunnel is not already installed.

# [0.1.4] - 2023-05-16

###

- Refactored release.yml to replace deprecated actions.

# [0.1.3] - 2023-05-15

###

- Added ability to override automated settings in start_ebpf.sh by moving user_rules.sh read to last item in script

## [0.1.2] - 2023-05-15

###

- Refactored release.yml deploy_packages_(arch) jobs to a single deploy_packages job with iteration through ${{ matrix.goarch }}

## [0.1.1] - 2023-05-15

###

- Added initial code. 
- Added README.md
- Added BUILD.md
- Modified json object in files/json/ebpf_config.json and modified files/scripts/start_ebpf.py to parse it for new key "ExternalInterfaces" which
  gives the ability to assign an outbound tracking object and set per interface rules on a wan interface as described in README.md
- Fixed memory leak caused b y not calling json_object_put() on the root json objects created by calls to json _token_parse(). 

## [0.1.0] - 2023-05-12

###

- Added initial code.

