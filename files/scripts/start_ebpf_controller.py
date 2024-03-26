#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import time
import yaml
import argparse

controller = False
router = False

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
        try:
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
        except Exception as e:
            print(e)


def add_link_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        try:
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
        except Exception as e:
            print(e)

def add_controller_edge_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        try:
            with open('/opt/openziti/ziti-controller/controller01.config.yml') as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
                if(config):
                    if('edge' in config.keys()):
                        if 'api' in config['edge'].keys():
                            if("address" in config['edge']['api'].keys()):
                                address = config['edge']['api']['address']
                                addr_array = address.split(':')
                                if(len(addr_array) == 2):
                                    port = addr_array[-1].strip()
                                    try:
                                        port = addr_array[-1].strip()
                                        if((int(port) > 0)):
                                            os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp')
                                    except Exception as e:
                                        print(e)
                                        pass
        except Exception as e:
            print(e)

def add_controller_ctrl_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        try:
            with open('/opt/openziti/ziti-controller/controller01.config.yml') as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
                if(config):
                    if('ctrl' in config.keys()):
                        if 'listener' in config['ctrl'].keys():
                            address = config['ctrl']['listener']
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
        except Exception as e:
            print(e)

def add_controller_web_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        try:
            with open('/opt/openziti/ziti-controller/controller01.config.yml') as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
                if(config):
                    if('web' in config.keys()):
                        for key in config['web']:
                            if('bindPoints' in key.keys()):
                                for bind in key['bindPoints']:
                                    address = bind['interface']
                                    addr_array = address.split(':')
                                    if(len(addr_array) == 2):
                                        port = addr_array[-1].strip()
                                        try:
                                            port = addr_array[-1].strip()
                                            if((int(port) > 0)):
                                                os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp')
                                        except Exception as e:
                                            print(e)
                                            pass
        except Exception as e:
            print(e)


def add_controller_port_forwarding_rule(lan_ip, lan_mask):
    test = os.system("grep -rnw \'A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 443\' /etc/ufw/before.rules")
    if(not test):
        port = "80"
        os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p tcp')
    else:
        print("Port forwarding rul not found")

def add_edge_listener_rules(lan_ip, lan_mask):
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        try:
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
        except Exception as e:
            print(e)

def add_resolver_rules():
    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
        try:
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
                                                    if(lan_ip == '100.127.255.254'):
                                                        #special case for NF AWS Gateway loadbalance via DNS over GENEVE using 100.127.255.254 on loopback so add route on loopback
                                                        os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p udp -r')
                                                    else:
                                                        os.system('/opt/openziti/bin/zfw -I -c ' + lan_ip + ' -m ' + lan_mask + ' -l ' + port + ' -h ' + port + ' -t 0  -p udp')
                                            except Exception as e:
                                                print(e)
                                                pass
        except Exception as e:
            print(e)

def write_config(config):
    try:
        with open('/opt/openziti/ziti-router/config.yml', 'w') as config_file:
            yaml.dump(config, config_file, sort_keys=False)
    except Exception as e:
        print(e)

def get_if_ip(intf):
    process = subprocess.Popen(['ip', 'add'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    for line in data:
        if((line.find(intf) >= 0) and (line.find('inet') >= 0)):
            search_list = line.strip().split(" ")
            if search_list[-1].strip() == intf:
                return search_list[1]    
    return ""

def set_local_rules(ip):
    default_ip = '0.0.0.0'
    default_mask = '0'
    if len(ip.split('/')) == 2:
        lan_ip = ip.split('/')[0]
        lan_mask = '32'
    else:
        lan_ip = default_ip
        lan_mask = default_mask
    if controller:
        add_controller_edge_listener_rules(lan_ip, lan_mask)
        add_controller_web_listener_rules(lan_ip, lan_mask)
        add_controller_port_forwarding_rule(lan_ip, lan_mask)
    if router:
        add_link_listener_rules(lan_ip, lan_mask)
    

parser = argparse.ArgumentParser(description="Network build script")
parser.add_argument("--lanIf", required=True, help='')
args = parser.parse_args()
lanIf = args.lanIf
if(os.path.exists('/opt/netfoundry/ziti/ziti-controller/conf/controller01.config.yml')):
    controller = True
    print("Detected Netfoundry install")
    if(not os.path.exists('/opt/openziti/ziti-controller/controller01.config.yml')):
        print("Installing symlink from /opt/openziti/ziti-controller to /opt/netfoundry/ziti/ziti-controller/conf")
        os.symlink('/opt/netfoundry/ziti/ziti-controller/conf', '/opt/openziti/ziti-controller')
    else:
        print("Symlink found nothing to do!")
    if(os.path.exists('/opt/netfoundry/ziti/ziti-router/config.yml')):
        router = True
        print("Detected Netfoundry install/registration!")
        if(not os.path.exists('/opt/openziti/ziti-router/config.yml')):
            print("Installing symlink from /opt/openziti/ziti-router to /opt/netfoundry/ziti/ziti-router!")
            os.symlink('/opt/netfoundry/ziti/ziti-router', '/opt/openziti/ziti-router')
        else:
            print("Symlink found nothing to do!")

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

internal_list = []
external_list = []
per_interface_rules = dict()
outbound_passthrough_track = dict()
if(os.path.exists('/opt/openziti/etc/ebpf_config.json')):
    with open('/opt/openziti/etc/ebpf_config.json','r') as jfile:
        try:
            config = json.loads(jfile.read())
            if(config):
                if "InternalInterfaces" in config.keys():
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
    os.system("/usr/sbin/zfw -F -r")
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

lanIp = get_if_ip(lanIf)
if(len(lanIp)):
    set_local_rules(lanIp)
if(os.path.exists('/etc/systemd/system/ziti-controller.service') and controller):
    unconfigured = os.system("grep -r 'ExecStartPre\=\-\/opt/openziti\/bin\/start_ebpf_controller.py' /etc/systemd/system/ziti-controller.service")
    if(unconfigured):
        test0 = 1
        test0 = os.system("sed -i 's/User\=ziti/User\=root/g' /etc/systemd/system/ziti-controller.service")
        test1 = 1
        test1 = os.system("sed -i '/ExecStart=/i ExecStartPre\=\-\/opt\/openziti\/bin\/start_ebpf_controller.py --lanIf " + lanIf + "' /etc/systemd/system/ziti-controller.service")
        if((not test0) and (not test1)):
            test1 = os.system("systemctl daemon-reload")
            if(not test1):
                print("Successfully converted ziti-controller.service. Restarting!")
                os.system('systemctl restart ziti-controller.service')
                if(not os.system('systemctl is-active --quiet ziti-controller.service')):
                    print("ziti-controller.service successfully restarted!")
                else:
                    print('ziti-controller.service unable to start check router logs!')
        else:
            print("Failed to convert ziti-controller.service!")
    else:
        print("ziti-controller.service already converted. Nothing to do!")
else:
    print("Skipping ziti-controller.service conversion. File does not exist or is already converted to run ebpf!")
sys.exit(0)
