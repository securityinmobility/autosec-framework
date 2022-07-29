
import sys, os 
sys.path.append("../autosec-framework-master")
import unittest

from autosec.core.ressources.ip import InternetDevice, InternetInterface
from autosec.core.ressources.can import CanInterface
import autosec.modules.automatic_execution as automatic_execution
from scapy.all import *
import subprocess

class AutomaticExecutionTest(unittest.TestCase):

    def setUp(self):
        conf.use_pcap=True

        self.network_address = '10.9.0.0/24' 
        self.interface_name= "ether"
        self.ip = "10.9.0.5"   

        self.interface = InternetInterface(self.interface_name, self.network_address)
        self.device = InternetDevice(self.interface, self.ip)
        self.can_interface = CanInterface(interface_name="vcan0")


    def testAutomaticExecution(self):
        module = automatic_execution.load_module()[0]

        # start subprocess to run script to replay can data
        p2 = subprocess.Popen([sys.executable, './autosec/test/endpoints_sim.py'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # start subprocess to run script to replay can data
        p3 = subprocess.Popen([sys.executable, './autosec/test/replay_trc_test.py'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        
        results = module.run([self.interface, self.device, self.can_interface])
        
        # arp scan
        result_internet_devices = [devices.get_address() for devices in results.get('internet devices')]
        ground_truth_internet_devices = ['10.9.0.7', '10.9.0.5', '10.9.0.6']
        self.assertTrue(all([True if d in ground_truth_internet_devices else False for d in result_internet_devices])), "ARP-Scan test failed"
        self.assertEqual(len(result_internet_devices), len(ground_truth_internet_devices)),  "ARP-Scan test failed"
        

        # isotp scan
        ground_truth_isotp_services = [("vcan0", 1793, 1792), ("vcan0", 1795, 1962), ("vcan0", 1799, 1801), ("vcan0", 1861, 1945), ("vcan0", 1928, 1820), ("vcan0", 1979, 1996)]
        result_isopt_services = [(s.get_interface().get_interface_name(), s.get_tx_id(), s.get_rx_id()) for s in results.get('isotp services')]
        self.assertTrue(all([True if i in ground_truth_isotp_services else False for i in result_isopt_services])) , "ISOTP-Scan test failed"
        self.assertEqual(len(ground_truth_isotp_services), len(result_isopt_services)), "ISOTP-Scan test failed"

        # can sniff test
        result_can_devices_lst = [(d.get_interface().get_interface_name(), d.get_address()) for d in results.get('can devices')]
        result_can_services_lst = [(i.get_service(), i.get_data()) for i in results.get('can services')]
        ground_truth_can_devices_lst = [('vcan0', 612), ('vcan0', 64), ('vcan0', 253), ('vcan0', 406), ('vcan0', 408), ('vcan0', 407), ('vcan0', 409), ('vcan0', 410), ('vcan0', 412), ('vcan0', 402), ('vcan0', 836), ('vcan0', 837), ('vcan0', 405), ('vcan0', 400), ('vcan0', 352), ('vcan0', 353), ('vcan0', 362), ('vcan0', 363), ('vcan0', 354), ('vcan0', 355), ('vcan0', 356), ('vcan0', 357), ('vcan0', 358), ('vcan0', 359), ('vcan0', 360), ('vcan0', 361), ('vcan0', 404), ('vcan0', 441799967), ('vcan0', 316494952), ('vcan0', 441799968), ('vcan0', 364), ('vcan0', 365), ('vcan0', 366), ('vcan0', 367), ('vcan0', 372), ('vcan0', 373)]
        ground_truth_can_services_lst = [(612, b"\x00\xe0\x7f\x10'\xe3\xe5\x7f"), (64, b'\x11\x80\x00\x80\x81\x80\x15\x7f'), (253, b'\x0c\xd8\x1f\x81\x00\x00\x00\x00'), (406, b'\x1a\x08\xc4\x04'), (408, b'\x1a\x08\xc4\x04'), (407, b'\xfe\x0f\xf0\x07\x00\x00'), (409, b'\xfe\x0f\xf0\x07\x00\x00'), (410, b'\xfe\x07}\x04\xfe\xfe'), (412, b'\xfe\x07}\x04\xfe\xfe'), (402, b'\xfe\x07\x00\xfe\x07\x00\xe0\xbb'), (836, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (837, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (405, b'\xaa\x00\xa0\x00\x08\x00\x00\x00'), (400, b'\x1a\x08\x00\x1a\x08\xfe\xe0\xff'), (352, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (353, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (362, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (363, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (354, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (355, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (356, b'\x00\x00\x00\x80\x02\x00\x00\x00'), (357, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (358, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (359, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (360, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (361, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (404, b'\xa0\n\n\x00\x00\x00\x00\x00'), (441799967, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (316494952, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (441799968, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (364, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (365, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (366, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (367, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (372, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (373, b'\x00\x00\x00\x00\x00\x00\x00\x00')]
        self.assertTrue(all([True if i in ground_truth_can_devices_lst else False for i in result_can_devices_lst]))
        self.assertTrue(all([True if i in ground_truth_can_services_lst else False for i in result_can_services_lst]))
        self.assertTrue(len(result_can_devices_lst)>0)
        self.assertTrue(len(result_can_services_lst)>0)


        p2.kill()
        p3.kill()

       

if __name__ == "__main__": 
    unittest.main()