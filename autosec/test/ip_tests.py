
import sys, os 
sys.path.append("../autosec-framework-master")
import unittest

from autosec.core.ressources.ip import InternetDevice, InternetInterface
import autosec.modules.arp_scan as arp_scan
from scapy.all import *
from python_on_whales import DockerClient
from multiprocessing import Process

def docker_setup():
    client = DockerClient(compose_files="./docker-compose.network.yaml")
    client.compose.build()
    client.compose.up()

"""
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
"""


class IP_tests(unittest.TestCase):
    
    def setUp(self):
        conf.use_pcap=True

        self.network_address = '10.9.0.0/24' 
        self.interface_name= "ether"
        self.ip = "10.9.0.5"   

        self.interface = InternetInterface(self.interface_name, self.network_address)
        self.device = InternetDevice(self.interface, self.ip)
        self.module_arp = arp_scan.load_module()[0]
        #self.module_port = port_scan.load_module()[0]

    def testArpScan(self):
        self.assertTrue(self.module_arp.can_run([self.interface, self.network_address])), "Not enough ressources. (InternetInterface, InternetDevice)"

        # start docker network
        p = Process(target=docker_setup)
        p.start()
        time.sleep(10)

        device_lst = self.module_arp.run([self.interface])
        result_lst = ['10.9.0.7', '10.9.0.5', '10.9.0.6']
        test_lst = [devices.get_address() for devices in device_lst]

        # remove docker
        os.system("docker compose -f ./docker-compose.network.yaml down")
        
        self.assertTrue(all([True if d in result_lst else False for d in test_lst])), "ARP-Scan test failed"
        self.assertEqual(len(test_lst), len(result_lst)),  "ARP-Scan test failed"

    """def testPortScan(self):
        self.assertTrue(self.module_port.can_run([self.interface, self.device])), "Not enough ressources. (InternetInterfaces, InternetDevices)"
        service_lst = self.module_port.run([self.interface, self.device])
        result_lst = []
        test_lst = [service.get_port() for service in service_lst]     
        self.assertTrue(all([True if d in result_lst else False for d in test_lst])), "Port-Scan test failed"
        assertEqual(), "Port-Scan test failed" 
    """

if __name__ == "__main__":
    unittest.main()
