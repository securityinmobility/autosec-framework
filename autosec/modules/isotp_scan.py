'''
Module for scanning CAN bus for ISO-TP endpoints
'''

from typing import List
from autosec.core.ressources import AutosecRessource, CanInterface, IsoTPService
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from scapy.all import ISOTPScan

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [IsoTpServices()]

class IsoTpServices(AutosecModule):
    '''
    Class that provides the isotp endpoint scan.
    '''

    def get_info(self):
        return AutosecModuleInformation(
            name = "IsoTPServiceScan",
            description = "Module that interprets services that run over ISO TP",
            dependencies = [],
            tags = ["CAN", "ISOTP", "scan"]
        )

    def get_produced_outputs(self) -> List[IsoTPService]:
        return [IsoTPService]

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface]

    def run(self, inputs: List[AutosecRessource]) -> List[IsoTPService]:
        can = self.get_ressource(inputs, CanInterface)
        #  scan_range=range(0x7ff + 1)
        socks = ISOTPScan(can.get_socket(), can_interface=can.get_interface_name(), sniff_time=0.1)
        # TODO extended addressing. In separate module(?)

        return [IsoTPService(can, x.src, x.dst) for x in socks]
