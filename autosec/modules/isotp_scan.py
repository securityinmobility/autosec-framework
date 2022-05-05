'''
Module for scanning CAN bus for ISO-TP endpoints
'''

from typing import List
from scapy.all import conf, load_contrib

from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource, CanInterface, IsoTPService

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
        conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
        conf.contribs['CANSocket'] = {'use-python-can': False}
        load_contrib('cansocket')
        load_contrib('isotp')

        can = self.get_ressource(inputs, CanInterface)
        socks = ISOTPScan(can.get_socket(), extended_addressing=False)
        # TODO extended addressing. In separate module(?)

        return [IsoTPService(can, x.tx_id, x.rx_id) for x in socks]
