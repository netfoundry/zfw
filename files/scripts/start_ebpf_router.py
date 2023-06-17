#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import time

def tc_status(interface, direction):
    process = subprocess.Popen(['tc', 'filter', 'show', 'dev', interface, direction], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    if(len(data)):
        return True
    else:
        return False

def get_resolver():
    process = subprocess.Popen(['grep', 'resolver:', '/opt/openziti/ziti-router/config.yml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode()
    if(len(err)):
        return ''
    data = out.decode()
    raw = data.split(':')
    if(len(raw)):
       port= raw[-1].strip()
       try:
           int(port)
           return port
       except:
           return ''
    else:
        return ''

def get_edge_listener():
    in_edge = False
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml', 'r') as cfile:
           for line in cfile:
               if(line.find("binding: proxy") >= 0):
                   in_edge = False
               if(line.find("binding: edge") >= 0):
                   in_edge = True
               if(in_edge):
                  if(line.find("address:") >= 0):
                      address = line.split(':')
                      if(len(address)):
                          port = address[-1].strip()
                          try:
                              int(port)
                              return port
                          except:
                              return ''
    return ''

def get_health_check_listener():
    in_hc = False
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml', 'r') as cfile:
           for line in cfile:
               if(line.find("apis:") >= 0):
                   in_hc = False
               if(line.find("name: health-check") >= 0):
                   in_hc = True
               if(in_hc):
                  if(line.find("address:") >= 0):
                      address = line.split(':')
                      if(len(address)):
                          port = address[-1].strip()
                          try:
                              int(port)
                              return port
                          except:
                              return ''
    return ''

def get_link_listener():
    in_link = False
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml', 'r') as cfile:
           for line in cfile:
               if(line.find("healthChecks:") >= 0):
                   in_link = False
               if(line.find("link:") >= 0):
                   in_link = True
               if(in_link):
                  if(line.find("bind:") >= 0):
                      address = line.split(':')
                      if(len(address)):
                          port = address[-1].strip()
                          try:
                              int(port)
                              return port
                          except:
                              return ''
    return ''

def get_lanIf():
    process = subprocess.Popen(['grep', 'lanIf:', '/opt/openziti/ziti-router/config.yml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode()
    if(len(err)):
        return ''
    data = out.decode()
    raw = data.split(':')
    if(len(raw)):
       result = raw[1].strip()
       return result
    else:
        return ''

def get_if_ip(intf):
    process = subprocess.Popen(['ip', 'add'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    for line in data:
        if((line.find(intf) >= 0) & (line.find('inet') >= 0)):
            search_list = line.strip().split(" ")
            if(search_list[-1].strip() == intf):
               return search_list[1]
            else:
               return ""

def set_local_rules(resolver):
        default_cidr = '0.0.0.0/0'
        default_ip = '0.0.0.0'
        default_mask = '0'
        edge_port = get_edge_listener()
        health_port = get_health_check_listener()
        link_port = get_link_listener()
        resolver_port = get_resolver()
        if(len(resolver.split('/'))):
            lan_ip = resolver.split('/')[0]
            lan_mask = '32'
        else:
            lan_ip = default_cidr
            lan_mask = default_mask
        if(len(edge_port)):
            os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + edge_port + ' -h ' + edge_port + ' -t 0  -p tcp')
        if(len(link_port)):
            os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + link_port + ' -h ' + link_port + ' -t 0  -p tcp')
        if(len(health_port)):
            os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + health_port + ' -h ' + health_port + ' -t 0  -p tcp')
        if(len(resolver_port)):
            print("resolver_port=", resolver_port)
            os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + resolver_port + ' -h ' + resolver_port + ' -t 0  -p tcp')
            os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + resolver_port + ' -h ' + resolver_port + ' -t 0  -p udp')
        
netfoundry = False
if(os.path.exists('/opt/netfoundry/ziti/ziti-router/config.yml')):
    netfoundry = True
    print("Detected Netfoundry install/registration!")
    if(not os.path.exists('/opt/openziti/ziti-router/config.yml')):
        print("Installing symlink from /opt/openziti/ziti-router to /opt/netfoundry/ziti/ziti-router!")
        os.symlink('/opt/netfoundry/ziti/ziti-router', '/opt/openziti/ziti-router')
    else:
        print("Symlink found nothing to do!")

lanIf = get_lanIf()
if(not len(lanIf)):
    print("Unable to retrieve LanIf!")
else:
    if(not os.path.exists('/opt/openziti/etc/ebpf_config.json')):
        if(os.path.exists('/opt/openziti/etc/ebpf_config.json.sample')):
            with open('/opt/openziti/etc/ebpf_config.json.sample','r') as jfile:
                try:
                    config = json.loads(jfile.read())
                    if(config):
                        if("InternalInterfaces" in config.keys()):
                            interfaces = config["InternalInterfaces"]
                            if len(interfaces):
                                interface = interfaces[0]
                                if("Name" in interface.keys()):
                                    interface['Name'] = lanIf
                                else:
                                    print('Missing mandatory key: Name')
                                    sys.exit(1)
                            else:
                                print('Invalid config no interfaces found!')
                                sys.exit(1)
                        with open('/opt/openziti/etc/ebpf_config.json', 'w') as ofile:
                            json.dump(config, ofile)
                except Exception as e:
                    print('Malformed or missing json object in /opt/openziti/etc/ebpf_config.json.sample')
                    sys.exit(1)
        else:
            print('File does not exist: /opt/openziti/etc/ebpf_config.json.sample')
    else:
         print('File already exist: /opt/openziti/etc/ebpf_config.json')

router_config = False
if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
    unconfigured = os.system("grep -r '\ \ \ \ \ \ mode: tproxy:/opt/openziti/bin/zfw' /opt/openziti/ziti-router/config.yml")
    if(unconfigured):
        no_binding = os.system("grep -r '\ \ - binding: tunnel' /opt/openziti/ziti-router/config.yml")
        if(no_binding):
            print('ziti-router config.yml missing \"binding: tunnel\" aborting router config conversion!')
        else:
            test1 = os.system("sed -i 's/mode: tproxy/#mode: tproxy/g' /opt/openziti/ziti-router/config.yml")
            test2 = os.system("sed -i '/#mode: tproxy/a \ \ \ \ \ \ mode: tproxy:/opt/openziti/bin/zfw' /opt/openziti/ziti-router/config.yml")
            if(test1 | test2):
                print("Unable to convert ziti-router config to use ebpf diverter!")
            else:
                router_config = True
                print("config.yml successfully converted!")
    else:
        print("ziti-router config already converted to use ebpf diverter!")
else:
    print('ziti-router not installed, skipping ebpf router configuration!')

internal_list = []
external_list = []
per_interface_rules = dict()
outbound_passthrough_track = dict()
if(os.path.exists('/opt/openziti/etc/ebpf_config.json')):
    with open('/opt/openziti/etc/ebpf_config.json','r') as jfile:
        try:
            config = json.loads(jfile.read())
            if(config):
                if("InternalInterfaces" in config.keys()):
                    i_interfaces = config["InternalInterfaces"]
                    if len(i_interfaces):
                        for interface in i_interfaces:
                            if("Name" in interface.keys()):
                                print("Attempting to add ebpf ingress to: ",interface["Name"])
                                internal_list.append(interface["Name"])
                                if("OutboundPassThroughTrack") in interface.keys():
                                    if(interface["OutboundPassThroughTrack"]):
                                        outbound_passthrough_track[interface["Name"]] = True;
                                    else:
                                        outbound_passthrough_track[interface["Name"]] = False;
                                else:
                                    outbound_passthrough_track[interface["Name"]] = False;
                                if("PerInterfaceRules") in interface.keys():
                                    if(interface["PerInterfaceRules"]):
                                        per_interface_rules[interface["Name"]] = True;
                                    else:
                                        per_interface_rules[interface["Name"]] = False;
                                else:
                                    per_interface_rules[interface["Name"]] = False;
                            else:
                                print('Mandatory key \"Name\" missing skipping internal interface entry!')

                else:
                    print("No internal interfaces listed in /opt/openziti/etc/ebpf_config.json add at least one interface")
                    sys.exit(1)
                if("ExternalInterfaces" in config.keys()):
                    e_interfaces = config["ExternalInterfaces"]
                    if len(e_interfaces):
                        for interface in e_interfaces:
                            if("Name" in interface.keys()):
                                print("Attempting to add ebpf egress to: ",interface["Name"])
                                external_list.append(interface["Name"])
                                if("OutboundPassThroughTrack") in interface.keys():
                                    if(interface["OutboundPassThroughTrack"]):
                                        outbound_passthrough_track[interface["Name"]] = True;
                                    else:
                                        outbound_passthrough_track[interface["Name"]] = False;
                                else:
                                    outbound_passthrough_track[interface["Name"]] = True;
                                if("PerInterfaceRules") in interface.keys():
                                    if(interface["PerInterfaceRules"]):
                                        per_interface_rules[interface["Name"]] = True;
                                    else:
                                        per_interface_rules[interface["Name"]] = False;
                                else:
                                    per_interface_rules[interface["Name"]] = True;
                            else:
                                print('Mandatory key \"Name\" missing skipping external interface entry!')
                else:
                    print("No External interfaces listed in /opt/openziti/etc/ebpf_config.json")
        except Exception as e:
            print("Malformed or missing json object in /opt/openziti/etc/ebpf_config.json")
            sys.exit(1)
else:
    print("Missing /opt/openziti/etc/ebpf_config.json can't set ebpf interface config")
    sys.exit(1)

ingress_object_file = '/opt/openziti/bin/zfw_tc_ingress.o'
egress_object_file = '/opt/openziti/bin/zfw_tc_outbound_track.o'
if os.system("/opt/openziti/bin/zfw -L -E"):
    test1 = os.system("/opt/openziti/bin/zfw -Q")
    if test1:
        print("failed to clear ebpf maps")
    for i in internal_list:
        if(not tc_status(i, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + ingress_object_file + " -z ingress")
            time.sleep(1)
            if(test1):
                print("Cant attach " + i + " to tc ingress with " + ingress_object_file)
                continue
            else:
                print("Attached " + ingress_object_file + " to " + i)
                os.system("sudo ufw allow in on " + i + " to any")
            if(per_interface_rules[i]):
                os.system("/opt/openziti/bin/zfw -P " + i)
        if(not tc_status(i, "egress")):
            if(outbound_passthrough_track[i]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + i + " to tc egress with " + egress_object_file)
                    continue
                else:
                    print("Attached " + egress_object_file + " to " + i)
    for e in external_list:
        if(not tc_status(e, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + ingress_object_file + " -z ingress")
            if(test1):
                os.system("/opt/openziti/bin/zfw -Q")
                print("Cant attach " + e + " to tc ingress with " + ingress_object_file)
                continue
            else:
                print("Attached " + ingress_object_file + " to " + e)
                os.system("sudo ufw allow in on " +e + " to any")
            time.sleep(1)
            if(per_interface_rules[e]):
                os.system("/opt/openziti/bin/zfw -P " + e)
        if(not tc_status(e, "egress")):
            if(outbound_passthrough_track[e]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + e + " to tc egress with " + egress_object_file)
                    os.system("/opt/openziti/bin/zfw -Q")
                    continue
                else:
                    print("Attached " + egress_object_file + " to " + e)
    if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
        print("Adding user defined rules")
        os.system("/opt/openziti/bin/user/user_rules.sh")
else:
    print("ebpf already running!");
    os.system("/usr/sbin/zfw -F")
    print("Flushed Table")
    for i in internal_list:
        if(not tc_status(i, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + ingress_object_file + " -z ingress")
            time.sleep(1)
            if(test1):
                print("Cant attach " + i + " to tc ingress with " + ingress_object_file)
            else:
                print("Attached " + ingress_object_file + " to " + i)
                os.system("sudo ufw allow in on " + i + " to any")
            if(per_interface_rules[i]):
                os.system("/opt/openziti/bin/zfw -P " + i)
        if(not tc_status(i, "egress")):
            if(outbound_passthrough_track[i]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + i + " to tc egress with " + egress_object_file)
                else:
                    print("Attached " + egress_object_file + " to " + i)
    for e in external_list:
        if(not tc_status(e, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + ingress_object_file + " -z ingress")
            if(test1):
                print("Cant attach " + e + " to tc ingress with " + ingress_object_file)
            else:
                print("Attached " + ingress_object_file + " to " + e)
                os.system("sudo ufw allow in on " +e + " to any")
            time.sleep(1)
            if(per_interface_rules[e]):
                os.system("/opt/openziti/bin/zfw -P " + e)
        if(not tc_status(e, "egress")):
            if(outbound_passthrough_track[e]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + e + " to tc egress with " + egress_object_file)
                else:
                    print("Attached " + egress_object_file + " to " + e)
    if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
        print("Adding user defined rules!")
        os.system("/opt/openziti/bin/user/user_rules.sh")

resolver = get_if_ip(lanIf)
if(len(resolver)):
    set_local_rules(resolver)
if(os.path.exists('/etc/systemd/system/ziti-router.service') & router_config):
    unconfigured = os.system("grep -r 'ExecStartPre\=\-\/opt/openziti\/bin\/start_ebpf_router.py' /etc/systemd/system/ziti-router.service")
    if(unconfigured):
        os.system("sed -i 's/ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/objects\/etables \-F \-r/#ExecStartPre\=-\/opt\/netfoundry\/ebpf\/objects\/etables \-F \-r/g' /etc/systemd/system/ziti-router.service")
        os.system("sed -i 's/ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/#ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/g' /etc/systemd/system/ziti-router.service")
        test1 = 1
        if(netfoundry):
            test1 = os.system("sed -i '/ExecStart=\/opt\/netfoundry\/ziti\/ziti-router\/ziti router run \/opt\/netfoundry\/ziti\/ziti-router\/config.yml/i ExecStartPre\=\-\/opt\/openziti\/bin\/start_ebpf_router.py' /etc/systemd/system/ziti-router.service")
        else:
            test1 = os.system("sed -i '/ExecStart=\/opt\/openziti\/ziti-router\/ziti router run \/opt\/openziti\/ziti-router\/config.yml/i ExecStartPre\=\-\/opt\/openziti\/bin\/start_ebpf_router.py' /etc/systemd/system/ziti-router.service")
        if(not test1):
            test1 = os.system("systemctl daemon-reload")
            if(not test1):
                print("Successfully converted ziti-router.service. Restarting!")
                os.system('systemctl restart ziti-router.service')
                if(not os.system('systemctl is-active --quiet ziti-router.service')):
                    print("ziti-router.service successfully restarted!")
                else:
                    print('ziti-router.service unable to start check router logs!')
        else:
            print("Failed to convert ziti-router.service!")
    else:
        print("ziti-router.service already converted. Nothing to do!")
else:
    print("Skipping ziti-router.service conversion. File does not exist or config.yml not set!")
sys.exit(0)
