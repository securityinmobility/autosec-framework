import sys 
sys.path.append("../autosec-framework-master")

from autosec.core.ressources.can import CanInterface
import autosec.modules.isotp_scan as isotp_scan
import unittest, subprocess


class ISOTP_test(unittest.TestCase):

    def setUp(self):
        self.module = isotp_scan.load_module()[0]
        self.interface = CanInterface("vcan0")
    
    def test_istotp_scan(self):
        self.assertTrue(self.module.can_run([self.interface])), "Not enough ressources (CanInterface)"

        # subprocess to initialize isotp endpoints
        p = subprocess.Popen([sys.executable, './autosec/test/endpoints_sim.py'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        isotp_list = self.module.run([self.interface])
        result_lst = [("vcan0", 1793, 1792), ("vcan0", 1795, 1962), ("vcan0", 1799, 1801), ("vcan0", 1861, 1945), ("vcan0", 1928, 1820), ("vcan0", 1979, 1996)]
        test_lst = [(s.get_interface().get_interface_name(), s.get_tx_id(), s.get_rx_id()) for s in isotp_list]
        # terminate subprocess
        p.kill()
        self.assertTrue(all([True if i in result_lst else False for i in test_lst])) , "ISOTP-Scan test failed"
        self.assertEqual(len(result_lst), len(test_lst)), "ISOTP-Scan test failed"

if __name__ == "__main__": 
    unittest.main()    