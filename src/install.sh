#!/bin/bash
if [ $# -lt 1 ]; then
   echo ""
   echo "Usage:"
   echo "     $0 <router|tunnel>"
   exit
fi
if [ $1 == "router" ]
then
   if [ ! -d "/opt/openziti/bin" ]
   then
       mkdir -p /opt/openziti/bin/user
   fi
   if [ ! -d "/opt/openziti/etc" ]
   then
       mkdir -p /opt/openziti/etc
   fi
   cp -p zfw /opt/openziti/bin
   cp -p zfw_tc_ingress.o /opt/openziti/bin
   cp -p zfw_tc_outbound_track.o /opt/openziti/bin
   cp -p ../files/scripts/start_ebpf_router.py /opt/openziti/bin
   cp -p ../files/scripts/revert_ebpf_router.py /opt/openziti/bin
   cp -p ../files/scripts/revert_ebpf_router.py /opt/openziti/bin
   cp -p ../files/scripts/user_rules.sh.sample /opt/openziti/bin/user
   cp -p ../files/json/ebpf_config.json.sample /opt/openziti/etc
   chmod 744 /opt/openziti/bin/start_ebpf_router.py
   chmod 744 /opt/openziti/bin/revert_ebpf_router.py
   chmod 744 /opt/openziti/bin/user/user_rules.sh.sample
   chmod 744 /opt/openziti/bin/zfw
   if [ ! -L "/usr/sbin/zfw" ]
      then
          ln -s /opt/openziti/bin/zfw /usr/sbin/zfw
   fi
elif [ $1 == "tunnel" ]
then
   if [ -d "/opt/openziti/bin" ] && [ -d "/opt/openziti/etc" ]
   then
      if [ ! -d "/opt/openziti/bin/user" ]
      then
         mkdir -p /opt/openziti/bin/user
      fi
      cp -p zfw /opt/openziti/bin
      cp -p zfw_tc_ingress.o /opt/openziti/bin
      cp -p zfw_tc_outbound_track.o /opt/openziti/bin
      cp -p zfw_xdp_tun_ingress.o /opt/openziti/bin
      cp -p  zfw_tunnwrapper /opt/openziti/bin
      cp -p ../files/scripts/start_ebpf_tunnel.py /opt/openziti/bin
      cp -p ../files/scripts/set_xdp_redirect.py /opt/openziti/bin
      cp -p ../files/scripts/user_rules.sh.sample /opt/openziti/bin/user
      cp -p ../files/json/ebpf_config.json.sample /opt/openziti/etc
      cp -p ../files/services/ziti-wrapper.service /etc/systemd/system
      cp -p ../files/services/ziti-fw-init.service /etc/systemd/system
      chmod 744 /opt/openziti/bin/start_ebpf_tunnel.py
      chmod 744 /opt/openziti/bin/set_xdp_redirect.py
      chmod 744 /opt/openziti/bin/user/user_rules.sh.sample
      chmod 744 /opt/openziti/bin/zfw_tunnwrapper
      chmod 744 /opt/openziti/bin/zfw

      if [ ! -L "/usr/sbin/zfw" ]
      then
          ln -s /opt/openziti/bin/zfw /usr/sbin/zfw
      fi
   else
      echo "ziti-edge-tunnel not installed!"
      exit 1
   fi
fi
exit 0
