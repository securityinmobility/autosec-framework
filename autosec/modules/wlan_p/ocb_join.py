"""
This module joins a network interface into the OCB mode.
It takes a NetworkInterface type as input.
The Interface is checked for ITS-G5 frequencies with iw.
The ITS-G5 frequencies are noted in the file "frequencys_europe.txt"
"""
import csv
from dataclasses import dataclass
import os
import re
import subprocess
#import time
from typing import List
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource
#from autosec.core.ressources.base import NetworkInterface
from autosec.core.ressources.ip import InternetInterface
from autosec.core.ressources.wlan_p import OcbInterface, WifiChannel
#from autosec.core.ressources.wifi import WifiInformation
#from autosec.modules.wlan_p.ocb_scan import OcbInterface

# TODO: This module joins a network interface into an ocb network.
# Requires the frequencies and channel width in europe, a wifi card with access to
# these channels and a modified regulatory database

def load_module(interface: InternetInterface) -> List[AutosecModule]:
    """
    Load the module
    """
    return [OcbModeJoin(interface)]

class OcbModeJoin(AutosecModule):
    """
    AutoSec Module that finds out for an interface the usable ITS-G5 channels
    with the transmit power. It can also join a specific ocb mode channel 
    with the help of iw and ip commandline tools
    """
    def __init__(self, interface: InternetInterface) -> None:
        super().__init__()
        self._iface: str = interface.get_interface_name()

    def get_info(self) -> AutosecModuleInformation:
        return AutosecModuleInformation(
            name=self.__class__.__name__,
            description="Module to join a specific OCB channel",
            dependencies=["scapy", "pandas"],
            tags=["WIFI", "OCB", "802.11p", "JOIN"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return [OcbInterface]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [InternetInterface]

    def run(self, inputs: AutosecRessource) -> List[AutosecRessource]:
        channels = self.get_usable_channels()

        if len(channels) > 0:
            # Join first available channel (Not very sophisticated.
            # Split in 2 modules or keep a list inside the class?)
            self.set_ocb_mode()
            self.leave_channel()
            self.join_channel(channels[0])
        else:
            return []
        return [OcbInterface(self._iface)]

    def _get_supported_channels(self) -> List[WifiChannel]:
        """"
        Reads the device configuration with 'iw' to get the supported wifi channels of the cards
        TODO: Depends on iw tool, multiple cards will result in false data, 
        output of 'iw' is parsed (maybe use pyroute2 instead? Netlink parameters are headaches tho)
        """
        command_result: List[str] = subprocess.run(
            ["iw", "phy"],
            capture_output=True,
            text=True,
            check=True
        )\
            .stdout \
            .splitlines()
        supported_channels: List[WifiChannel] = []
        for channel_result in command_result:
            if re.search('5..0 MHz', channel_result):
                channel = WifiChannel()
                channel_result_split = channel_result.split()
                channel.centre_frequency= int(channel_result_split[1])
                channel.channel_number= int(channel_result_split[3].strip("[]"))
                channel.set_tx(input_text = channel_result_split[4].strip("()"))
                supported_channels.append(channel)
        return supported_channels

    def _get_europe_channels(self, parameter_file: str) -> List[WifiChannel]:
        """"
        Read in the parameterfile to get the channels and width for europe
        """
        europe_channels: List[WifiChannel] = []
        with open(parameter_file, 'r', newline='', encoding="UTF-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                channel = WifiChannel()
                channel.centre_frequency = int(row['centre_frequency'])
                channel.channel_number = int(row['channel_number'])
                channel.channel_width = int(row['channdel_width'])
                europe_channels.append(channel)
        return europe_channels

    def get_usable_channels(self) -> List[WifiChannel]:
        """
        Function to get the usable channels in the EU with the selected interface
        """
        usable_channels: List[WifiChannel] = []
        supported_channels = self._get_supported_channels()
        europe_channels = self._get_europe_channels( \
                f"{os.getcwd()}/autosec/modules/wlan_p/frequencys_europe.txt")

        for eu_channel in europe_channels:
            for supported_channel in supported_channels:
                if eu_channel.centre_frequency == supported_channel.centre_frequency:
                    eu_channel.enabled = supported_channel.enabled
                    eu_channel.tx_power = supported_channel.tx_power
                    usable_channels.append(eu_channel)
                    break
        if len(usable_channels) > 0:
            return usable_channels

        # Could not find any channel supported by the wifi card(s)
        # TODO: How to handle no supported channels?
        # Exception or is it done with giving an empty output?
        return []

    def set_ocb_mode(self) -> None:
        """"
        Set the interface into ocb mode (needs to be done once in the beginning)
        """
        subprocess.run(
            ["iw", "dev", self._iface, "set", "type", "ocb"],
            capture_output=False,
            check=True
        )

    def join_channel(self, channel: WifiChannel) -> None:
        """"
        Joins the interface to a specific wifi channel with the defined width, 
        receiving data is possible after this (if successfull)
        """
        subprocess.run(
            ["iw", \
                "dev", 
                self._iface, \
                "ocb", \
                "join", \
                str(channel.centre_frequency), \
                str(channel.channel_width)],
            capture_output=False,
            check=True
        )

    def leave_channel(self) -> None:
        """"
        Leaves the ocb channel, new channel can only be joined after leaving the old one
        """
        subprocess.run(
            ["iw", "dev", self._iface, "ocb", "leave"],
            capture_output=False,
            check=True
        )
