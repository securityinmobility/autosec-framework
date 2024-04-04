"""
This module starts the vanetza application and the dependencies 
Dependencies:
mqtt server (currently using mosquitto)
"""
from typing import List
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.modules.wlan_p.ocb_join import OcbModeJoin


def load_module() -> List[AutosecModule]:
    """
    Load module
    """
    return NotImplementedError

class Vanetza(AutosecModule):
    """
    This module starts the NAP vanetza application
    """
#    def __init__(self) -> None:
#       super().__init__()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to start the socktap application of vanetza",
            dependencies=["scapy", "pandas"],
            tags=["C2X", "vanetza", "socktap"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        Requirement is a configured WiFi interface
        """
        return [OcbModeJoin, MQTTserver]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError

class MQTTserver(AutosecModule):
    """
    This module handels the startup of the mosquitto MQTT server
    """
    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to start a mosquitto server",
            dependencies=["scapy", "pandas"],
            tags=["C2X", "MQTT", "mosquitto"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return [MQTTserver]

    def get_required_ressources(self) -> List[AutosecRessource]:
        """
        Requirement is a configured WiFi interface
        """
        return [OcbModeJoin]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        """
        Not Implemented
        """
        return NotImplementedError
