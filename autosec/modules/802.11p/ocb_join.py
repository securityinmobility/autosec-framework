import csv
from dataclasses import dataclass
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

@dataclass
class WifiChannel:
    centre_frequency: int = 0       # Carrier centre frequency
    channel_number: int = 0         # Channel number givien to it. Number usually changes all 5 MHz 
    channel_width: int = 0          # Channel bandwidth, in wifi usual width are 5,10,20,40,80,160 MHz
    tx_power: float =0              # Ususally measured in dbm
    enabled: bool = False           # State of the channel with respect to the regulatory domain
    #TODO: Implement NL_FLAGS like NO-IR
    
    def __init__(self) -> None:
        super().__init__()

    def setTx(self, input: str):
        if "disabled" in input:
            self.tx_power = 0
            self.enabled = False
        elif float(input) > 0:
            self.tx_power = float(input)
            self.enabled = True
        else:
            print("Error parsing input")

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
    
    def _get_supported_channels(self) -> List[WifiChannel]:
        """"
        Reads the device configuration with 'iw' to get the supported wifi channels of the cards
        TODO: Depends on iw tool, multiple cards will result in false data, output of 'iw' is parsed (maybe use pyroute2 instead? Netlink parameters are headaches tho)
        """
        command_result: List[str] = subprocess.run(
            ["iw", "phy"],
            capture_output=True,
            #text=True
        )\
            .stdout \
            .decode("UTF-8") \
            .splitlines()     
        supported_channels: List[WifiChannel] = []
        for channel_result in command_result:
            if re.search('5..0 MHz', channel_result):
                channel = WifiChannel()
                channel_result = channel_result.split()
                channel.centre_frequency=channel_result[1]
                channel.channel_number=channel_result[3].strip("[]")
                channel.setTx(input = channel_result[4].strip("()"))
                supported_channels.append(channel)
        return supported_channels
    
    def _get_europe_channels(self, parameter_file: str) -> List[WifiChannel]:
        """"
        Read in the parameterfile to get the channels and width for europe
        """
        europe_channels: List[WifiChannel] = []
        with open(parameter_file, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = WifiChannel()
                channel.centre_frequency = row['centre_frequency']
                channel.channel_number = row['channel_number']
                channel.channel_width = row['channdel_width']
                europe_channels.append(channel)
        return europe_channels
    
    def get_usable_channels(self) -> List[WifiChannel]:
        """
        Function to get the usable channels in the EU with the selected interface
        #TODO: Implement frequency lists for other countries
        """
        usable_channels: List[WifiChannel] = []
        supported_channels = self._get_supported_channels()
        europe_channels = self._get_europe_channels('./frequencys_europe.txt')

        for eu_channel in europe_channels:
            for supported_channel in supported_channels:
                if eu_channel.centre_frequency == supported_channel.centre_frequency:
                    eu_channel.enabled = supported_channel.enabled
                    eu_channel.tx_power = supported_channel.tx_power
                    usable_channels.append(eu_channel)
                    break
        if not usable_channels:
            # Could not find any channel supported by the wifi card(s)
            # TODO: How to handle no supported channels? Exception or is it done with giving an empty output? 
            raise Exception('No Channels')
        else:
            return usable_channels
    
    def join_channel(self, channel: WifiChannel) -> None:
        command_result: List[str] = subprocess.run(
            ["iw", "dev", self._iface, "ocb", "join", channel.centre_frequency, channel.channel_width],
            capture_output=True,
            #text=True
        )\
            .stdout \
            .decode("UTF-8") \
            .splitlines()
    
    def leave_channel(self) -> None:
        command_result: List[str] = subprocess.run(
            ["iw", "dev", self._iface, "ocb", "leave"],
            capture_output=True,
            #text=True
        )\
            .stdout \
            .decode("UTF-8") \
            .splitlines()
