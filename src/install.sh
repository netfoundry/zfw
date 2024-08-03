#!/bin/bash
if [ $# -lt 1 ]; then
   echo ""
   echo "Usage:"
   echo "     $0 <router|tunnel>"
   exit
fi
if [ $1 == "router" ]
then
   if [ ! -d "/opt/openziti/bin/user" ]
   then
       mkdir -p /opt/openziti/bin/user
   fi
   if [ ! -d "/opt/openziti/etc" ]
   then
       mkdir -p /opt/openziti/etc
   fi
   cp zfw /opt/openziti/bin
   cp zfw_monitor /opt/openziti/bin
   cp zfw_tc_ingress.o /opt/openziti/bin
   cp zfw_tc_outbound_track.o /opt/openziti/bin
   cp ../files/scripts/start_ebpf_router.py /opt/openziti/bin
   cp ../files/scripts/zfw_refresh /etc/cron.d
   cp ../files/scripts/revert_ebpf_router.py /opt/openziti/bin
   cp ../files/scripts/revert_ebpf_router.py /opt/openziti/bin
   cp ../files/scripts/zfwlogs /etc/logrotate.d
   cp ../files/scripts/user_rules.sh.sample /opt/openziti/bin/user
   cp ../files/json/ebpf_config.json.sample /opt/openziti/etc
   cp ../files/services/zfw-logging.service /etc/systemd/system
   cp ../files/services/fw-init.service /etc/systemd/system
   chmod 744 /opt/openziti/bin/start_ebpf_router.py
   chmod 744 /opt/openziti/bin/revert_ebpf_router.py
   chmod 744 /opt/openziti/bin/user/user_rules.sh.sample
   chmod 744 /opt/openziti/bin/zfw
   chmod 644 /etc/cron.d/zfw_refresh
   if [ ! -L "/usr/sbin/zfw" ]
      then
          ln -s /opt/openziti/bin/zfw /usr/sbin/zfw
   fi
   chmod 744 /opt/openziti/bin/zfw_monitor
   if [ ! -L "/usr/sbin/zfw_monitor" ]
      then
          ln -s /opt/openziti/bin/zfw_monitor /usr/sbin/zfw_monitor
   fi
elif [ $1 == "tunnel" ]
then
   if [ -d "/opt/openziti/bin" ] && [ -d "/opt/openziti/etc" ]
   then
      if [ ! -d "/opt/openziti/bin/user" ]
      then
         mkdir -p /opt/openziti/bin/user
      fi
      cp zfw /opt/openziti/bin
      cp zfw_monitor /opt/openziti/bin
      cp zfw_tc_ingress.o /opt/openziti/bin
      cp zfw_tc_outbound_track.o /opt/openziti/bin
      cp zfw_xdp_tun_ingress.o /opt/openziti/bin
      cp zfw_tunnwrapper /opt/openziti/bin
      cp ../files/scripts/start_ebpf_tunnel.py /opt/openziti/bin
      cp ../files/scripts/zfw_refresh /etc/cron.d
      cp ../files/scripts/set_xdp_redirect.py /opt/openziti/bin
      cp ../files/scripts/zfwlogs /etc/logrotate.d
      cp ../files/scripts/user_rules.sh.sample /opt/openziti/bin/user
      cp ../files/json/ebpf_config.json.sample /opt/openziti/etc
      cp ../files/services/ziti-wrapper.service /etc/systemd/system
      cp ../files/services/ziti-fw-init.service /etc/systemd/system
      cp ../files/services/zfw-logging.service /etc/systemd/system
      chmod 744 /opt/openziti/bin/start_ebpf_tunnel.py
      chmod 744 /opt/openziti/bin/set_xdp_redirect.py
      chmod 744 /opt/openziti/bin/user/user_rules.sh.sample
      chmod 744 /opt/openziti/bin/zfw_tunnwrapper
      chmod 744 /opt/openziti/bin/zfw
      chmod 644 /etc/cron.d/zfw_refresh
      if [ ! -L "/usr/sbin/zfw" ]
      then
          ln -s /opt/openziti/bin/zfw /usr/sbin/zfw
      fi
      chmod 744 /opt/openziti/bin/zfw_monitor
      if [ ! -L "/usr/sbin/zfw_monitor" ]
         then
            ln -s /opt/openziti/bin/zfw_monitor /usr/sbin/zfw_monitor
      fi
   else
      echo "ziti-edge-tunnel not installed!"
      exit 1
   fi
elif [ $1 == "controller" ]
then
   if [ ! -d "/opt/openziti/bin/user" ]
   then
      mkdir -p /opt/openziti/bin/user
   fi
   if [ ! -d "/opt/openziti/etc" ]
   then
       mkdir -p /opt/openziti/etc
   fi
   cp  zfw /opt/openziti/bin
   cp  zfw_monitor /opt/openziti/bin
   cp  zfw_tc_ingress.o /opt/openziti/bin
   cp  zfw_tc_outbound_track.o /opt/openziti/bin
   cp  ../files/scripts/start_ebpf_controller.py /opt/openziti/bin
   cp ../files/scripts/zfw_refresh /etc/cron.d
   cp  ../files/scripts/revert_ebpf_controller.py /opt/openziti/bin
   cp  ../files/scripts/zfwlogs /etc/logrotate.d
   cp  ../files/scripts/user_rules.sh.sample /opt/openziti/bin/user
   cp  ../files/json/ebpf_config.json.sample /opt/openziti/etc
   cp  ../files/services/zfw-logging.service /etc/systemd/system
   chmod 744 /opt/openziti/bin/start_ebpf_controller.py
   chmod 744 /opt/openziti/bin/user/user_rules.sh.sample
   chmod 744 /opt/openziti/bin/zfw
   chmod 644 /etc/cron.d/zfw_refresh
   if [ ! -L "/usr/sbin/zfw" ]
   then
         ln -s /opt/openziti/bin/zfw /usr/sbin/zfw
   fi
   chmod 744 /opt/openziti/bin/zfw_monitor
   if [ ! -L "/usr/sbin/zfw_monitor" ]
      then
         ln -s /opt/openziti/bin/zfw_monitor /usr/sbin/zfw_monitor
   fi
fi
exit 0
