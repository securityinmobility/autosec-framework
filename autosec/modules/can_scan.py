from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources.base import AutosecRessource
from typing import Tuple, List

from autosec.core.ressources.can import CanInterface, CanDevice, CanService


def load_module():
    """
    Method to provide the module to the framework
    """
    return [CanScan()]


class CanScan(AutosecModule):
    """
    Class that provides a CAN scan
    """

    def __init__(self):
        super().__init__()
    
    
    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name = "canService",
            description= "Module that scans the can device for services",
            dependencies=[],
            tags = ["CAN", "scan"]
        )
    
    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [CanDevice, CanService]
    
    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface]

    def run(self, inputs: List[AutosecRessource]) -> Tuple[CanDevice,CanService]:
        interface = self.get_ressource(inputs, CanInterface)
        socket = interface.get_socket()
        pkts = socket.sniff(timeout=10)
        result = set(p.getfieldval("identifier") for p in pkts)
        result_data = [(p.getfieldval("data"),p.getfieldval("identifier")) for p in pkts]
        return [CanDevice(interface, addr) for addr in result], [CanService(i,d) for d,i in result_data]
