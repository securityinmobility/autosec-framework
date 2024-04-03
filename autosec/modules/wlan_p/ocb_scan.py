"""
Not yet implemented module for some OCB sniffing
"""
from typing import List
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource


def load_module() -> List[AutosecModule]:
    """
    Load module
    """
    return [OcbInterface()]

class OcbInterface(AutosecModule):
    """
    This module is supposed to scan though 
    OCB channels for data
    """
#    def __init__(self) -> None:
#       super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to collect packages in OCB mode",
            dependencies=["scapy", "pandas"],
            tags=["WIFI", "OCB", "802.11p"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError
