# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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

