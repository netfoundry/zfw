#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import time
import yaml

def tc_status(interface, direction):
    process = subprocess.Popen(['tc', 'filter', 'show', 'dev', interface, direction], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    if(len(data)):
        return True
    else:
        return False

def add_health_check_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml') as config_file:
             config = yaml.load(config_file, Loader=yaml.FullLoader)
             if(config):
                 if('web' in config.keys()):
                     for key in config['web']:
                         if(('name' in key.keys()) and (key['name'] == 'health-check')):
                             if('bindPoints' in key.keys()):
                                 for point in key['bindPoints']:
                                     address = point['address']
                                     addr_array = address.split(':')
                                     if(len(addr_array)):
                                         try:
                                             port = addr_array[-1].strip()
                                             if(int(port) > 0):
                                                 os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp')
                                         except Exception as e:
                                             print(e)
                                             pass

def add_link_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml') as config_file:
             config = yaml.load(config_file, Loader=yaml.FullLoader)
             if(config):
                 if('link' in config.keys()):
                     if('listeners' in config['link'].keys()):
                         for key in config['link']['listeners']:
                             if(('binding' in key.keys()) and (key['binding'] == 'transport')):
                                 if('bind' in key.keys()):
                                     address = key['bind']
                                     addr_array = address.split(':')
                                     if(len(addr_array) == 3):
                                         try:
                                             port = addr_array[-1].strip()
                                             if((int(port) > 0) and (addr_array[0] == 'tls')):
                                                 os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp') 
                                         except Exception as e:
                                             print(e) 
                                             pass


def add_edge_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml') as config_file:
             config = yaml.load(config_file, Loader=yaml.FullLoader)
             if(config):
                 if('listeners' in config.keys()):
                   for key in config['listeners']:
                             if(('binding' in key.keys()) and (key['binding'] == 'edge')):
                                 if('address' in key.keys()):
                                     address = key['address']
                                     addr_array = address.split(':')
                                     if(len(addr_array) == 3):
                                         port = addr_array[-1].strip()
                                         try:
                                             port = addr_array[-1].strip()
                                             if((int(port) > 0) and (addr_array[0] == 'tls')):
                                                 os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp')
                                         except Exception as e:
                                             print(e)
                                             pass


def add_resolver_rules():
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml') as config_file:
             config = yaml.load(config_file, Loader=yaml.FullLoader)
             if(config):
                 if('listeners' in config.keys()):
                   for key in config['listeners']:
                       if(('binding' in key.keys()) and (key['binding'] == 'tunnel')):
                           if('options' in key.keys()):
                               if('resolver' in key['options']):
                                   address = key['options']['resolver']
                                   addr_array = address.split(':')
                                   if(len(addr_array) == 3):
                                       port = addr_array[-1].strip()
                                       lan_ip = addr_array[1].split('//')
                                       lan_mask = '32'
                                       try:
                                           port = addr_array[-1].strip()
                                           lan_ip = addr_array[1].split('//')[1]
                                           if((int(port) > 0)):
                                               os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp')
                                               os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p udp')
                                       except Exception as e:
                                           print(e)
                                           pass

def set_zfw_mode():
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml') as config_file:
             config = yaml.load(config_file, Loader=yaml.FullLoader)
             if(config):
                 if('listeners' in config.keys()):
                     for key in config['listeners']:
                         if(('binding' in key.keys()) and (key['binding'] == 'tunnel')):
                             if('options' in key.keys()):
                                 if('mode' in key['options']):
                                     if(key['options']['mode'] == 'tproxy:/opt/openziti/bin/zfw'):
                                         print("ziti-router config already converted to use ebpf diverter!")
                                     else:
                                         key['options']['mode'] = 'tproxy:/opt/openziti/bin/zfw'
                                         write_config(config)
                                         return True
                                 else:
                                     key['options']['mode'] = 'tproxy:/opt/openziti/bin/zfw'
                                     write_config(config)
                                     return True
                             else:
                                 print('Mandatory key \'options\' missing from binding: tunnel')
                 else:
                     print('Mandatory key \'listeners\' missing in config.yml')
    else:
        print('ziti-router not installed, skipping ebpf router configuration!')
    return False

def write_config(config):
    with open('/opt/openziti/ziti-router/config.yml', 'w') as config_file:
        yaml.dump(config, config_file, sort_keys=False)

def get_lanIf():
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        with open('/opt/openziti/ziti-router/config.yml') as config_file:
             config = yaml.load(config_file, Loader=yaml.FullLoader)
             if(config):
                 if('listeners' in config.keys()):
                     for key in config['listeners']:
                         if(('binding' in key.keys()) and (key['binding'] == 'tunnel')):
                             if('options' in key.keys()):
                                 if('lanIf' in key['options']):
                                    return key['options']['lanIf']
                             else:
                                 print('Mandatory key \'options\' missing from binding: tunnel')
                 else:
                     print('Mandatory key \'listeners\' missing in config.yml')
    else:
        print('ziti-router not installed, skipping ebpf router configuration!')
    return ''

def get_if_ip(intf):
    process = subprocess.Popen(['ip', 'add'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    for line in data:
        if((line.find(intf) >= 0) and (line.find('inet') >= 0)):
            search_list = line.strip().split(" ")
            if(search_list[-1].strip() == intf):
               return search_list[1]
            else:
               return ""

def set_local_rules(resolver):
        default_cidr = '0.0.0.0/0'
        default_ip = '0.0.0.0'
        default_mask = '0'
        if(len(resolver.split('/'))):
            lan_ip = resolver.split('/')[0]
            lan_mask = '32'
        else:
            lan_ip = default_cidr
            lan_mask = default_mask
        add_edge_listener_rules(lan_ip, lan_mask)
        add_link_listener_rules(lan_ip, lan_mask)
        add_health_check_rules(lan_ip, lan_mask)
        add_resolver_rules()

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

router_config = set_zfw_mode()
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
status = subprocess.run(['/opt/openziti/bin/zfw', '-L', '-E'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if(status.returncode):
    test1 = subprocess.run(['/opt/openziti/bin/zfw', '-Q'],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if(test1.returncode):
        print("Ebpf not running no  maps to clear")
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
if(os.path.exists('/etc/systemd/system/ziti-router.service') and router_config):
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
    print("Skipping ziti-router.service conversion. File does not exist or is already converted to run ebpf!")
sys.exit(0)
