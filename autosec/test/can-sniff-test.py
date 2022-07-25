import sys 
sys.path.append("../autosec-framework-master")

from autosec.core.ressources.can import CanInterface
import autosec.modules.can_scan as can_scan
import unittest, subprocess

class Can_sniff_test(unittest.TestCase):

    def setUp(self):
        self.module = can_scan.load_module()[0]
        self.interface = CanInterface(interface_name="vcan0")

    def testCanSniff(self):
        self.assertTrue(self.module.can_run([self.interface])), "Not enough ressources. (CanInterface)"

        # start subprocess to run script to replay can data
        p = subprocess.Popen([sys.executable, './autosec/test/replay_trc_test.py'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        devices, data = self.module.run([self.interface])
        test_devices_lst = [(d.get_interface().get_interface_name(), d.get_address()) for d in devices]
        test_data_lst = [(i.get_service(), i.get_data()) for i in data]
        #kill subprocess
        p.kill()
        result_devices_lst = [('vcan0', 612), ('vcan0', 64), ('vcan0', 253), ('vcan0', 406), ('vcan0', 408), ('vcan0', 407), ('vcan0', 409), ('vcan0', 410), ('vcan0', 412), ('vcan0', 402), ('vcan0', 836), ('vcan0', 837), ('vcan0', 405), ('vcan0', 400), ('vcan0', 352), ('vcan0', 353), ('vcan0', 362), ('vcan0', 363), ('vcan0', 354), ('vcan0', 355), ('vcan0', 356), ('vcan0', 357), ('vcan0', 358), ('vcan0', 359), ('vcan0', 360), ('vcan0', 361), ('vcan0', 404), ('vcan0', 441799967), ('vcan0', 316494952), ('vcan0', 441799968), ('vcan0', 364), ('vcan0', 365), ('vcan0', 366), ('vcan0', 367), ('vcan0', 372), ('vcan0', 373)]
        result_data_lst = [(612, b"\x00\xe0\x7f\x10'\xe3\xe5\x7f"), (64, b'\x11\x80\x00\x80\x81\x80\x15\x7f'), (253, b'\x0c\xd8\x1f\x81\x00\x00\x00\x00'), (406, b'\x1a\x08\xc4\x04'), (408, b'\x1a\x08\xc4\x04'), (407, b'\xfe\x0f\xf0\x07\x00\x00'), (409, b'\xfe\x0f\xf0\x07\x00\x00'), (410, b'\xfe\x07}\x04\xfe\xfe'), (412, b'\xfe\x07}\x04\xfe\xfe'), (402, b'\xfe\x07\x00\xfe\x07\x00\xe0\xbb'), (836, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (837, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (405, b'\xaa\x00\xa0\x00\x08\x00\x00\x00'), (400, b'\x1a\x08\x00\x1a\x08\xfe\xe0\xff'), (352, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (353, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (362, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (363, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (354, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (355, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (356, b'\x00\x00\x00\x80\x02\x00\x00\x00'), (357, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (358, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (359, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (360, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (361, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (404, b'\xa0\n\n\x00\x00\x00\x00\x00'), (441799967, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (316494952, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (441799968, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (364, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (365, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (366, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (367, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (372, b'\x00\x00\x00\x00\x00\x00\x00\x00'), (373, b'\x00\x00\x00\x00\x00\x00\x00\x00')]
        self.assertTrue(all([True if i in result_devices_lst else False for i in test_devices_lst]))
        self.assertTrue(all([True if i in result_data_lst else False for i in test_data_lst]))
        self.assertTrue(len(test_data_lst) > 0)
        self.assertTrue(len(test_devices_lst) > 0)

if __name__ == "__main__": 
    unittest.main() 
