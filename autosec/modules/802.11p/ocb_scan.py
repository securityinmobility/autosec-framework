import time
from typing import List
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.base import NetworkInterface
from autosec.core.ressources.wifi import WifiInformation


def load_module() -> List[AutosecModule]:
    return [OcbModeScan()]

class OcbModeScan(AutosecModule):
    def __init__(self) -> None:
        super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to collect packages in OCB mode",
            dependencies=["scapy", "pandas"],
            tags=["WIFI", "OCB", "802.11p"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return 0
    
    def get_required_ressources(self) -> List[AutosecRessource]:
        return 0

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        
        return 0
