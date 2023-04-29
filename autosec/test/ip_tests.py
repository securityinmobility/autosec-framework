
import sys 
sys.path.append("../autosec-framework")

from autosec.core.ressources.ip import InternetDevice, InternetInterface
import autosec.modules.port_scan as port_scan
import autosec.modules.arp_scan as arp_scan
from scapy.all import *


conf.use_pcap=True

network_address = '10.9.0.0/24'
interface_name= "ether"
ip = "10.9.0.5"

interface = InternetInterface(interface=interface_name, ipv4_address=network_address, subnet_length=24)
device = InternetDevice(interface, ip)

#conf.iface = interface.get_interface_name()
#ip = get_if_addr(conf.iface)


#------------------ARP SCAN TEST----------------------------------------
print("Starting ARP-Scan test: ")
module_arp = arp_scan.load_module()[0]
assert module_arp.can_run([interface, network_address]), "Not enough ressources. (InternetInterface, InternetDevice)"
device_lst = module_arp.run([interface])
print("Found %s devices: "%(len(device_lst)))
if len(device_lst) > 0:
    for devices in device_lst:
        print(devices.get_address())
else:
    print("Nothing found.")

#------------------PORT SCAN TEST----------------------------------------
print("\nStarting Port-Scan test: ")
module_port = port_scan.load_module()[0]
assert module_port.can_run([interface, device]), "Not enough ressources. (InternetInterfaces, InternetDevices)"
service_lst = module_port.run([interface, device])
if len(service_lst) > 0:
    print("Found %s ports for %s: "%(len(service_lst), device.get_address()))
    for service in service_lst:
        print("Port: %s \tService: %s" %(service.get_port(), service.get_service_name()))
else:
    print("Nothing found.")  
        

