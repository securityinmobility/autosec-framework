'''
Module to provide sniffing and manipulation of CAN networks.
This attack works as a MITM with two CAN interfaces.
Usually, all messages are transferred between the interfaces, but some
messages (e.g. with certain IDs) can be manipulated.
'''
import threading
import logging
from numpy import identity
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

        """
        #self.logger = logging.getLogger("autosec.modules.can_bridge")
        #self.logger.setLevel(logging.DEBUG)
        
        self._add_option("primaryInterface",
            description="First Interface of the CAN Bridge",
            required=True,
            value="can0"
        )

        self._add_option("secondaryInterface",
            description="Second Interface of the CAN Bridge",
            required=True,
            value="can1"
        )

        self._add_option("filters",
            description="Filters that can intercept the communication",
            required=True,
            default=([],[])
        )

        self.logger = logging.getLogger("autosec.modules.can_bridge")
        self.logger.setLevel(logging.DEBUG)

        load_layer("can")
        load_contrib("cansocket")

        self.primary_interface = None
        self.secondary_interface = None
        self.filters = ([], [])
        self.thread = None
        """

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



"""
    def run(self, inputs: List[AutosecRessource]) -> List[AutosecRessource]:

        self.primary_interface = CANSocket(channel = "vcan0")
        self.secondary_interface = CANSocket(channel = "vcan1")
        self.logger.debug("Starting the bridge..")
        self.thread = threading.Thread(target=self._sniff)
        self.thread.start()



    def _sniff(self):
        # sniff packets and return list of packets, prn function to apply to each packet
        self.primary_interface.sniff(prn=self._primary_message)  
        self.secondary_interface.sniff(prn=self._secondary_message)

    def _primary_message(self, pkt):
        self._on_message(0, pkt.identifier, pkt.data)

    def _secondary_message(self, pkt):
        self._on_message(1, pkt.identifier, pkt.data)

    def _on_message(self, interface, msg_id, data):
        '''
        # list to carry the messages to be intercepted
        # ID IF1, Answer IF1, ID IF2, Answer IF2eceived message.
        self.intercept = [
            (
                0x7af,
                lambda data: b'\x03\x04\x05',
                None,
                lambda data: b'\x06\x07\x08'
            )
        ]
        interface: interface that received message (0 = primary, 1 = secondary)
        id: ID of the received message
        data: data of the received message
        '''
        self.logger.debug("Received message on %s with id %03x and data %s", interface, msg_id, data)
        result = (False, None, None)
        for _filter in self.filters[interface]:
            filter_result = _filter(msg_id, data)
            if filter_result[0]:
                result = filter_result

        if result[0]:
            if result[1] is not None:
                #self._send(self.primary_interface, result[1])
                
                self.primary_interface.send_message(msg_id=result[1][0], data=result[1][1])
                #self._send(self.secondary_interface, result[2])
                self.secondary_interface.send_message(msg_id=result[2][0], data=result[2][1])
        else:
            if interface == 0:
                if data is not None:
                    #self._send(self.secondary_interface, (msg_id, data))
                    self.secondary_interface.send_message(msg_id=msg_id, data=data)

            else:
                if data is not None:
                    #self._send(self.primary_interface, (msg_id, data))
                    self.primary_interface.send_message(msg_id=msg_id, data=data)

   
    @staticmethod
    def _send(interface, packet):   # CanInterface send_message(msg_id: int, data_bytes)
        '''
        Method to send a packet on a specified interface
        '''
        if packet is not None:
            identifier = packet[0]
            data = packet[1]
            interface.send(CAN(identifier=identifier, length=len(data), data=data))
    """