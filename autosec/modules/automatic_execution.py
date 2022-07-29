from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.ip import InternetDevice, InternetInterface, InternetService
from autosec.core.ressources import AutosecRessource, CanInterface, CanOverride, CanService, CanDevice, IsoTPService
from autosec.modules import can_scan, isotp_scan, port_scan, arp_scan
from typing import List, Tuple
import subprocess


def load_module():
    """
    Method to provide the module to the framework
    """
    return [AutomaticExecution()]


class AutomaticExecution(AutosecModule):

    _internet_device_lst = None
    _internet_service_lst = None
    _can_device_lst = None
    _can_service_lst = None
    _isotpService_lst = None
    _can_interface = None
    _internet_interface = None


    def __init__(self):
        super().__init__()

    def get_info(self):
        return AutosecModuleInformation(
            name = "automaticExecution",
            description = "Module to automatically test all possible ressources",
            dependencies = [],
            tags = ["automatic"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [AutosecRessource]
    

    def get_required_ressources(self):
        return []


    def arp_test(self, inputs: List[AutosecRessource]) -> List[InternetDevice]: #InternetInterface
        module_arp = arp_scan.load_module()[0]
        possible = module_arp.can_run(inputs)
        if possible:
            self._internet_device_lst = module_arp.run(inputs)
        return None


    def port_test(self, inputs: List[AutosecRessource]) -> List[InternetService]: #InternetInterface, InternetDevice
        module_port = port_scan.load_module()[0]
        possible = module_port.can_run(inputs)
        if possible:
            self._internet_service_lst = module_port.run(inputs)
        return None


    def can_test(self, inputs: List[AutosecRessource]) -> Tuple[CanDevice, CanService]: #CanInterface
        module = can_scan.load_module()[0]
        possible = module.can_run(inputs)
        if possible:
            self._can_device_lst, self._can_service_lst = module.run(inputs)
        return None


    def isotp_test(self, inputs: List[AutosecRessource]) -> List[IsoTPService]: #CanInterface
        module = isotp_scan.load_module()[0]
        possible = module.can_run(inputs)
        if possible:
            self._isotpService_lst = module.run(inputs)
        return None


    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        
       # internet_interface_name = ""
       # network_address = ""

      #  self._can_interface = CanInterface(interface_name="vcan0")
      #  self._internet_interface = InternetInterface(internet_interface_name, network_address)

        #inputs = inputs.append(self._can_interface)
        self.can_test(inputs)
        self.isotp_test(inputs)
        #args = "/bin/python3 from automatic_execution.py import arp_test; arp_test(%s)" %(inputs)
        #returncode = subprocess.call(["/usr/bin/sudo", args])
        #print(returncode)
        self.arp_test(inputs)
        if self._internet_device_lst is not None:
            inputs.append(self._internet_device_lst)
        #self.port_test(inputs)

        result = {'internet devices':self._internet_device_lst, 'internet services':self._internet_service_lst, 'can devices':self._can_device_lst, 'can services':self._can_service_lst , 'isotp services':self._isotpService_lst, 'can interface':self._can_interface, 'internet interface':self._internet_interface}
        return result