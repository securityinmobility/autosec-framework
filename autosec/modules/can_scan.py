from this import d
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from typing import List

from autosec.core.ressources.can import CanInterface


def load_module():
    """
    Method to provide the module to the framework
    """
    return [CanService()]


class CanService(AutosecModule):
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
        return [CanService]
    
    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface]

    def run(self, inputs: List[AutosecRessource]) -> List[CanInterface]:
        interface = self.get_ressource(inputs, CanInterface)
        socket = interface.get_socket()
        pkts = socket.sniff(timeout=5)
        result = []
        for p in pkts:
            data = p.get_field("data")
            identifier = p.get_field("identifier")
            result.add(CanService(identifier, data))

        return result
