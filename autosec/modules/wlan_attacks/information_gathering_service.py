from typing import List
import time
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.base import NetworkInterface
from .information_gathering import InformationGathering


def load_module() -> List[AutosecModule]:
    return [InformationGatheringService()]


class InformationGatheringService(AutosecModule):

    def __init__(self) -> None:
        super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to collect information about existing wifi networks",
            dependencies=["scapy", "pandas"],
            tags=["WIFI", "information gathering"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return []

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [NetworkInterface(interface="wlo1")]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        network_interface: NetworkInterface = self.get_ressource(
            inputs=inputs,
            kind=NetworkInterface
        )
        info: InformationGathering = InformationGathering(
            iface=network_interface.get_interface_name(),
            hopping_channel=True
        )
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            pass
        info.stop()
        time.sleep(5)
        return []
