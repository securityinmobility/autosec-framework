
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
