import re
import subprocess
import time
from typing import List
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
from autosec.core.ressources.base import NetworkInterface
from autosec.core.ressources.wifi import WifiInformation

#TODO: This module joins a network interface into an ocb network. 
# Requires the frequencies and channel width in europe, a wifi card with access to these channels and a modified regulatory database

def load_module() -> List[AutosecModule]:
    return [OcbModeJoin()]

class OcbModeJoin(AutosecModule):

    def __init__(self, iface: str) -> None:
        super().__init__()
        self._iface: str = iface

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to join a specific OCB channel",
            dependencies=["scapy", "pandas"],
            tags=["WIFI", "OCB", "802.11p", "JOIN"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [WifiInformation]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [NetworkInterface]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        
        return 0
    
    def _get_supported_channels(self) -> List[int]:
            command_result: List[str] = subprocess.run(
                ["iw", "phy"],
                capture_output=True,
                #text=True
            )\
                .stdout \
                .decode("UTF-8") \
                .splitlines()     
            supported_channels: List[int] = []
            for channel_result in command_result:
                if re.search('5..0 MHz', channel_result):
                    channel_result = channel_result.split()
                    supported_channels.append(channel_result[1])
            return supported_channels
    
    def join_channel(self) -> List[int]:
        
        return 0
