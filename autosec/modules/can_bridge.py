'''
Module to provide sniffing and manipulation of CAN networks.
This attack works as a MITM with two CAN interfaces.
Usually, all messages are transferred between the interfaces, but some
messages (e.g. with certain IDs) can be manipulated.
'''



from scapy.all import load_layer, load_contrib, conf, CAN, CANSocket, bridge_and_sniff
from autosec.core.autosec_module import AutosecModule, AutosecModuleInformation
from autosec.core.ressources import AutosecRessource, CanInterface, CanOverride1
from typing import List

def load_module():
    '''
    Method to provide the module to the framework
    '''
    return [CanBridge()]


class CanBridge(AutosecModule):
    '''
    Class that implements the MITM attack
    '''
    def __init__(self):
        super().__init__()


    def get_info(self):
        return AutosecModuleInformation(
            name = "canBridge",
            description = "Module to perform MITM CAN attacks with two CAN interfaces",
            dependencies = [],
            tags = ["CAN", "MITM", "attack"]
        )

    def get_produced_outputs(self) -> List[AutosecRessource]:
        return []

    def get_required_ressources(self) -> List[AutosecRessource]:
        return [CanInterface, CanInterface]

    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:
        conf.contribs['CANSocket'] = {'use-python-can': False}
        load_contrib('cansocket')

        interfaces = self.get_ressources(inputs, CanInterface)
        socket1 = interfaces[0].get_socket()
        socket2 = interfaces[1].get_socket()
        bridge_and_sniff(if1=socket1, if2=socket2, xfrm12=self.forwarding12, xfrm21=self.forwarding21, timeout=1)

        #socket1.close()
        #socket2.close()
        return []

    def forwarding12(self, pkt):
        data = pkt.data
        msg_id = pkt.identifier
        interface = 2
        self.logger.debug("Received message on %s with id %03x and data %s", interface, msg_id, data)
        # filters could be implemented to change the data
        new_pkt = CAN(identifier=msg_id, length=len(data), data=data)
        return new_pkt
    
    def forwarding21(self, pkt):
        data = pkt.data
        msg_id = pkt.identifier
        interface = 1
        self.logger.debug("Received message on %s with id %03x and data %s", interface, msg_id, data)
        # filters could be implemented to change the data
        new_pkt = CAN(identifier=msg_id, length=len(data), data=data)
        return new_pkt

